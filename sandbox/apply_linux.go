//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// bwrapRoBindCandidates is the narrowed set of host paths the sandboxed
// process needs read-only access to in order to run common script
// interpreters and resolve TLS / DNS. We deliberately do NOT bind /home,
// /root, /var, /srv, /opt, or arbitrary dotfiles — those can contain
// secrets (AWS creds, SSH keys, shell history) the agent must not see.
// Paths that don't exist on a given host are silently skipped so the
// bwrap invocation doesn't error on e.g. /lib64 on pure-multiarch
// systems.
//
// Audit-trace (extracted from nanite, finding 06 gap #1, 2026-04-10
// audit): closes the host-secrets read path that a blanket
// `--ro-bind / /` would expose.
var bwrapRoBindCandidates = []string{
	"/usr",
	"/lib",
	"/lib32",
	"/lib64",
	"/bin",
	"/sbin",
	"/etc/alternatives",
	"/etc/ssl",
	"/etc/ca-certificates",
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/nsswitch.conf",
}

// BuildBwrapArgs translates a Profile + workspace into the bwrap argument
// list that follows the leading "bwrap" name and precedes the trailing
// "--" + payload separator.
//
// Hardening posture (verbatim from nanite's 2026-04-10 audit, gaps #1–#5):
//
//   - Read-only mounts narrowed to interpreter / TLS paths in
//     bwrapRoBindCandidates rather than blanket `--ro-bind / /`. This
//     closes the host-secrets read path (gap #1): user dotfiles, SSH
//     keys, and cloud creds are no longer visible from inside the
//     sandbox.
//   - PID, IPC, UTS, cgroup, and user namespaces always unshared so the
//     sandboxed process cannot observe or interfere with host processes
//     (gap #2). `--unshare-user-try` degrades gracefully on kernels that
//     disable unprivileged user namespaces.
//   - /tmp is replaced with a per-invocation tmpfs (gap #4) so there is
//     no cross-session state leakage through shared /tmp files.
//   - The network namespace is unshared when p.Net == false. When
//     p.Net == true the netns is left intact — see the network-isolation
//     note below for the host-proxy story (gap #3 partial; intentionally
//     out of scope for the lib v1 default-allow posture).
//   - --die-with-parent and --new-session prevent orphan escape and TTY
//     hijacking (gap #5 partial).
//
// network-isolation note: when a future caller needs allowlisted egress
// (proxy mode), they will need a proxy that lives inside the sandbox
// netns — e.g. via socket passing or a co-located helper. Until then,
// p.Net == true keeps the sandbox in the host netns. See README "Out of
// scope: network proxy subsystem".
func BuildBwrapArgs(p Profile, workspace string) ([]string, error) {
	return buildBwrapArgs(p, workspace, "", "", nil)
}

// buildBwrapArgs builds the legacy bwrap arguments. env is the child's
// environment (nil: the parent's), which DenyUserServiceManager reads for
// the runtime directory and session bus to hide.
func buildBwrapArgs(p Profile, workspace, helperPath, bridgeDir string, env []string) ([]string, error) {
	absWS, err := filepath.Abs(workspace)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace dir: %w", err)
	}
	if p.HostFilesystem {
		return buildHostFilesystemBwrapArgs(p, absWS, env)
	}

	args := make([]string, 0, 32)

	// Narrowed read-only mounts (gap #1). Missing paths are skipped so
	// different distros (musl/glibc, multiarch/single-arch) all work. Linux
	// compatibility symlink paths are preserved so ELF interpreters that refer
	// to /lib or payloads that refer to /bin continue to resolve.
	for _, path := range bwrapRoBindCandidates {
		if _, statErr := os.Lstat(path); statErr == nil {
			args = append(args, "--ro-bind", filepath.Clean(path), filepath.Clean(path))
		}
	}

	home, _ := os.UserHomeDir()
	args = append(args, "--tmpfs", "/tmp")
	for _, dir := range legacyBwrapMountParentDirs(absWS, p, helperPath, bridgeDir, home) {
		args = append(args, "--dir", dir)
	}

	if helperPath != "" && !pathVisibleInSandbox(helperPath, absWS, p) {
		args = append(args, "--ro-bind", helperPath, helperPath)
	}
	if bridgeDir != "" && !pathVisibleInSandbox(bridgeDir, absWS, p) {
		args = append(args, "--ro-bind", bridgeDir, bridgeDir)
	}

	// Workspace is the writable root; per-invocation /tmp avoids host leakage.
	args = append(args,
		"--bind", absWS, absWS,
		"--dev", "/dev",
		"--proc", "/proc",
	)

	// Additional Write paths.
	seen := map[string]bool{absWS: true}
	for _, raw := range p.FS.Write {
		path := expandPathLinux(raw, absWS, home)
		if seen[path] {
			continue
		}
		seen[path] = true
		args = append(args, "--bind", path, path)
	}

	// Write protection (Profile.FS.Protect): plan it against every mount the
	// child sees, in the child's path space. Pins go here, after the writable
	// mounts and before the read mounts, so a pin never covers a read-only
	// grant beneath it; the read-only binds go after everything.
	roots := []protectRoot{newProtectRoot(absWS, true)}
	for _, raw := range p.FS.Write {
		roots = append(roots, newProtectRoot(expandPathLinux(raw, absWS, home), true))
	}
	for _, raw := range p.FS.Read {
		roots = append(roots, newProtectRoot(expandPathLinux(raw, absWS, home), false))
	}
	for _, path := range existingLinuxPaths(bwrapRoBindCandidates) {
		roots = append(roots, newProtectRoot(path, false))
	}
	protected, err := legacyProtectPaths(p.FS.Protect, absWS, home)
	if err != nil {
		return nil, err
	}
	plan, err := planProtect(protected, roots)
	if err != nil {
		return nil, err
	}
	args = append(args, plan.pinArgs("--bind")...)

	// Additional Read paths (try-bind so missing paths are skipped, not errors).
	for _, raw := range p.FS.Read {
		path := expandPathLinux(raw, absWS, home)
		if seen[path] {
			continue
		}
		seen[path] = true
		args = append(args, "--ro-bind-try", path, path)
	}
	args = append(args, plan.bindArgs()...)
	// Last of the mounts, over every grant that shows the runtime directory.
	if p.DenyUserServiceManager {
		masks, err := userManagerMasks(roots, nil, env, p.Net)
		if err != nil {
			return nil, err
		}
		args = append(args, masks...)
	}

	// Namespace isolation (gap #2). --unshare-user-try degrades on kernels
	// that disable unprivileged user namespaces (common in hardened distros);
	// the rest are always available.
	args = append(args,
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-cgroup-try",
		"--unshare-user-try",
		"--new-session",
		"--die-with-parent",
	)

	// Network namespace unshared when p.Net is false (full offline isolation).
	// When true, the sandbox stays in the host netns — see the
	// network-isolation note above and README "Out of scope".
	if !p.Net {
		args = append(args, "--unshare-net")
	}

	return args, nil
}

// buildHostFilesystemBwrapArgs is Profile.HostFilesystem: the host
// filesystem as the parent sees it, writable and with devices, minus the
// write-protected paths. It shares the ipc and uts namespaces and the
// session, so apart from protection the child sees only its own processes in
// /proc and, when Net is false, no network.
func buildHostFilesystemBwrapArgs(p Profile, workspace string, env []string) ([]string, error) {
	if len(p.FS.Deny) > 0 {
		return nil, fmt.Errorf("%w: profile %q: FS.Deny is not enforced by a host-filesystem profile on linux", ErrUnsupportedPolicy, p.ID)
	}
	home, _ := os.UserHomeDir()
	protected, err := legacyProtectPaths(p.FS.Protect, workspace, home)
	if err != nil {
		return nil, err
	}
	plan, err := planProtect(protected, []protectRoot{{Dest: "/", Canon: "/", Writable: true}})
	if err != nil {
		return nil, err
	}
	// A private pid namespace and /proc: the host's /proc would offer
	// /proc/<pid>/root of every same-uid host process, a path into the host
	// mount namespace that no bind here covers.
	args := []string{"--dev-bind", "/", "/", "--unshare-pid", "--proc", "/proc"}
	args = append(args, plan.pinArgs("--dev-bind")...)
	args = append(args, plan.bindArgs()...)
	if p.DenyUserServiceManager {
		masks, err := userManagerMasks([]protectRoot{{Dest: "/", Canon: "/", Writable: true}}, nil, env, p.Net)
		if err != nil {
			return nil, err
		}
		args = append(args, masks...)
	}
	// With paths to protect, the user namespace is required, not tried: it is
	// what makes the kernel refuse /proc/<pid>/root and ptrace of host
	// processes from inside, so a bwrap that cannot create one must fail.
	if len(protected) > 0 {
		args = append(args, "--unshare-user")
	} else {
		args = append(args, "--unshare-user-try")
	}
	// No --new-session: a PTY session needs its controlling terminal, and
	// setsid would take it away. TIOCSTI injection into a parent's terminal
	// is off by default since Linux 6.2 (dev.tty.legacy_tiocsti=0).
	args = append(args, "--die-with-parent")
	if !p.Net {
		args = append(args, "--unshare-net")
	}
	return args, nil
}

// legacyProtectPaths expands Profile.FS.Protect (~, ${HOME}, the workspace
// token), requires each to be absolute, refuses ones the child could re-point
// or that are not directories, and returns their canonical host paths.
func legacyProtectPaths(raws []string, workspace, home string) ([]string, error) {
	out := make([]string, 0, len(raws))
	for _, raw := range raws {
		path := expandPathLinux(raw, workspace, home)
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("%w: protected path %q must be absolute (or ~/..., or workspace)", ErrUnsupportedPolicy, raw)
		}
		if err := validateProtectPath(path); err != nil {
			return nil, err
		}
		canonical, err := canonicalPath(path)
		if err != nil {
			return nil, fmt.Errorf("sandbox: resolve protected path %q: %w", raw, err)
		}
		if !slices.Contains(out, canonical) {
			out = append(out, canonical)
		}
	}
	if err := validateProtectSet(out); err != nil {
		return nil, err
	}
	return out, nil
}

// protectRoot is a mount the sandbox shows: Dest is where the child sees it,
// Canon the host directory it resolves to, Writable whether the child writes
// through it.
type protectRoot struct {
	Dest, Canon string
	Writable    bool
}

func newProtectRoot(dest string, writable bool) protectRoot {
	dest = filepath.Clean(dest)
	canon := dest
	if resolved, err := filepath.EvalSymlinks(dest); err == nil {
		canon = resolved
	}
	return protectRoot{Dest: dest, Canon: canon, Writable: writable}
}

// protectPlan is the binds that write-protect paths, in the child's path
// space: pins (renameable ancestors bound onto themselves) and read-only
// binds over the protected directories.
type protectPlan struct {
	pins, binds []string
}

func (p protectPlan) pinArgs(flag string) []string {
	args := make([]string, 0, 3*len(p.pins))
	for _, pin := range p.pins {
		args = append(args, flag, pin, pin)
	}
	return args
}

func (p protectPlan) bindArgs() []string {
	args := make([]string, 0, 3*len(p.binds))
	for _, bind := range p.binds {
		args = append(args, "--ro-bind", bind, bind)
	}
	return args
}

// planProtect maps canonical protected paths (validated: absolute, not
// re-pointable, directories) into the child's path space through roots, the
// mounts the child sees. A root whose Dest is a symlink on the host still
// shows the protected directory at Dest plus the relative path, which is
// where the bind must go.
//
//   - A protected directory under a writable root gets a read-only bind at
//     each place the child sees it. Read-only roots need nothing, and one no
//     root shows stays hidden: protection grants nothing.
//   - Every ancestor between the writable root's Dest and the bind is pinned:
//     bound onto itself, rw as before. A mount point cannot be renamed or
//     removed (EBUSY), so the child cannot `mv /W /W2`, carrying the
//     read-only mount away, and recreate /W/state with its own content for
//     the host to read.
//   - A protected path that does not exist cannot be bound without creating
//     it on the host, so it is refused where the child could create it (its
//     nearest existing ancestor is under a writable root and not itself
//     protected), and skipped otherwise.
//
// It fails closed: an existing protected directory under a writable root
// that ends up with no bind is an error.
func planProtect(paths []string, roots []protectRoot) (protectPlan, error) {
	var dirs, missing []string
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				missing = append(missing, path)
				continue
			}
			return protectPlan{}, fmt.Errorf("sandbox: inspect protected path %q: %w", path, err)
		}
		dirs = append(dirs, path)
	}
	// A writable mount at or inside a protected directory would stay
	// writable through the read-only bind over its parent, so the tree would
	// not be protected at all: refuse it (validateWritesOutsideProtect makes
	// the same call for resolved policies).
	for _, root := range roots {
		if !root.Writable {
			continue
		}
		for _, dir := range dirs {
			if pathUnderAny(root.Canon, []string{dir}) {
				return protectPlan{}, fmt.Errorf("%w: writable path %q is inside protected path %q; a protected tree cannot also be granted writes", ErrUnsupportedPolicy, root.Dest, dir)
			}
		}
	}
	for _, path := range missing {
		ancestor := nearestExistingAncestor(path)
		if pathUnderAny(ancestor, dirs) {
			continue
		}
		for _, root := range roots {
			if root.Writable && pathUnderAny(ancestor, []string{root.Canon}) {
				return protectPlan{}, fmt.Errorf("%w: protected path %q does not exist and the sandboxed process could create it; create it before launch or protect its existing parent", ErrUnsupportedPolicy, path)
			}
		}
	}
	var plan protectPlan
	for _, dir := range dirs {
		// Every protected directory under a writable root is bound, nested or
		// not: an outer protected directory need not have a bind of its own
		// (it may sit outside every writable root), so its bind cannot be
		// assumed to cover this one.
		bound, needed := false, false
		for _, root := range roots {
			if !root.Writable || !pathUnderAny(dir, []string{root.Canon}) {
				continue
			}
			needed = true
			rel, err := filepath.Rel(root.Canon, dir)
			if err != nil {
				return protectPlan{}, fmt.Errorf("sandbox: place protected path %q under %q: %w", dir, root.Dest, err)
			}
			dest := filepath.Join(root.Dest, rel)
			for ancestor := filepath.Dir(dest); ancestor != root.Dest && pathUnderAny(ancestor, []string{root.Dest}); ancestor = filepath.Dir(ancestor) {
				// Never pin inside a protected directory: a pin is a
				// writable bind.
				if pathUnderAny(filepath.Join(root.Canon, mustRel(root.Dest, ancestor)), dirs) {
					continue
				}
				if !slices.Contains(plan.pins, ancestor) {
					plan.pins = append(plan.pins, ancestor)
				}
			}
			if !slices.Contains(plan.binds, dest) {
				plan.binds = append(plan.binds, dest)
			}
			bound = true
		}
		if needed && !bound {
			return protectPlan{}, fmt.Errorf("%w: protected path %q is writable in the sandbox but could not be bound read-only", ErrUnsupportedPolicy, dir)
		}
	}
	byDepth := func(a, b string) int {
		if da, db := pathDepthLinux(a), pathDepthLinux(b); da != db {
			return da - db
		}
		return strings.Compare(a, b)
	}
	slices.SortFunc(plan.pins, byDepth)
	slices.SortFunc(plan.binds, byDepth)
	return plan, nil
}

// mustRel is filepath.Rel for a target known to be under base.
func mustRel(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return "."
	}
	return rel
}

func nearestExistingAncestor(path string) string {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil {
			if resolved, err := filepath.EvalSymlinks(dir); err == nil {
				return resolved
			}
			return dir
		}
		if dir == filepath.Dir(dir) {
			return dir
		}
	}
}

func pathUnderAny(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, strings.TrimSuffix(root, "/")+"/") {
			return true
		}
	}
	return false
}

func legacyBwrapMountParentDirs(workspace string, p Profile, helperPath, bridgeDir, home string) []string {
	seen := map[string]bool{"/": true}
	var dirs []string
	addForPath := func(path string) {
		for _, dir := range parentDirsForBwrap(path) {
			if seen[dir] {
				continue
			}
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	addForPath(workspace)
	if helperPath != "" {
		addForPath(helperPath)
	}
	if bridgeDir != "" {
		addForPath(bridgeDir)
	}
	for _, raw := range p.FS.Write {
		addForPath(expandPathLinux(raw, workspace, home))
	}
	for _, raw := range p.FS.Read {
		addForPath(expandPathLinux(raw, workspace, home))
	}
	slices.Sort(dirs)
	return dirs
}

func pathVisibleInSandbox(target, workspace string, p Profile) bool {
	// A host-filesystem profile binds / itself: everything the parent sees,
	// the child sees at the same path.
	if p.HostFilesystem {
		return true
	}
	if pathWithinBind(target, workspace) {
		return true
	}

	home, _ := os.UserHomeDir()
	for _, candidate := range bwrapRoBindCandidates {
		if _, err := os.Lstat(candidate); err != nil {
			continue
		}
		if pathWithinBind(target, candidate) {
			return true
		}
	}
	for _, raw := range p.FS.Write {
		if pathWithinBind(target, expandPathLinux(raw, workspace, home)) {
			return true
		}
	}
	for _, raw := range p.FS.Read {
		if pathWithinBind(target, expandPathLinux(raw, workspace, home)) {
			return true
		}
	}
	return false
}

func pathWithinBind(target, bindPath string) bool {
	if target == bindPath {
		return true
	}
	info, err := os.Lstat(bindPath)
	if err != nil || !info.IsDir() {
		return false
	}
	return strings.HasPrefix(target, bindPath+"/")
}

func expandPathLinux(raw, workspace, home string) string {
	if raw == "workspace" {
		return workspace
	}
	raw = strings.ReplaceAll(raw, "${HOME}", home)
	if raw == "~" {
		return home
	}
	if strings.HasPrefix(raw, "~/") {
		raw = home + raw[1:]
	}
	return raw
}

// Apply wraps cmd to run under Linux bubblewrap (bwrap). Returns a no-op
// cleanup; bwrap needs no temp files. Returns an error if bwrap is not
// found — per the lib's hard-error posture, no silent downgrade.
//
// Subprocess gating note: Linux bwrap does not directly enforce
// p.Subprocess. Namespace isolation prevents the sandboxed process from
// affecting the host, but it can still fork children inside the sandbox.
// macOS enforces Subprocess via SBPL process-fork / process-exec* denies.
// A future iteration may add a seccomp filter for parity.
func Apply(cmd *exec.Cmd, p Profile, workspace string) (cleanup func(), err error) {
	bwrapBin, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("bwrap not found: cannot enforce profile %q on this system (install bubblewrap)", p.ID)
	}

	origPath := cmd.Path
	origArgs := cmd.Args[1:]
	payloadPath := origPath
	payloadArgs := origArgs
	useLoopbackHelper := !p.Net && (p.AllowLoopback || len(p.LoopbackForwardPorts) > 0)
	var bridge *loopbackForwarders

	helperPath := ""
	if useLoopbackHelper {
		resolvedOrigPath := origPath
		if !filepath.IsAbs(resolvedOrigPath) {
			resolvedOrigPath, err = exec.LookPath(origPath)
			if err != nil {
				return nil, fmt.Errorf("resolve sandbox target %q: %w", origPath, err)
			}
		}
		if len(p.LoopbackForwardPorts) > 0 {
			bridge, err = startLoopbackForwarders(p.LoopbackForwardPorts)
			if err != nil {
				return nil, err
			}
		}
		helperPath, err = os.Executable()
		if err != nil {
			if bridge != nil {
				bridge.Close()
			}
			return nil, fmt.Errorf("resolve loopback helper executable: %w", err)
		}
		if resolved, resolveErr := filepath.EvalSymlinks(helperPath); resolveErr == nil {
			helperPath = resolved
		}
		payloadPath = helperPath
		payloadArgs = append([]string{loopbackHelperArg, resolvedOrigPath}, origArgs...)
		cmd.Env = append(inheritedEnv(cmd.Env), loopbackHelperEnv+"=1")
		if bridge != nil {
			cmd.Env = append(cmd.Env,
				loopbackHelperForwardDirEnv+"="+bridge.dir,
				loopbackHelperForwardPortsEnv+"="+encodeLoopbackPorts(bridge.ports),
			)
		}
	}

	payloadBindPath := helperPath
	if payloadBindPath == "" {
		resolvedPayloadPath := payloadPath
		if !filepath.IsAbs(resolvedPayloadPath) {
			if lookedUp, lookErr := exec.LookPath(resolvedPayloadPath); lookErr == nil {
				resolvedPayloadPath = lookedUp
			}
		}
		if filepath.IsAbs(resolvedPayloadPath) {
			if resolved, resolveErr := filepath.EvalSymlinks(resolvedPayloadPath); resolveErr == nil {
				resolvedPayloadPath = resolved
			}
			if !pathVisibleInSandbox(resolvedPayloadPath, workspace, p) {
				payloadBindPath = resolvedPayloadPath
				payloadPath = resolvedPayloadPath
			}
		}
	}

	bridgeDir := ""
	if bridge != nil {
		bridgeDir = bridge.dir
	}
	bwrapArgs, err := buildBwrapArgs(p, workspace, payloadBindPath, bridgeDir, cmd.Env)
	if err != nil {
		if bridge != nil {
			bridge.Close()
		}
		return nil, err
	}

	full := make([]string, 0, 1+len(bwrapArgs)+2+len(origArgs))
	full = append(full, "bwrap")
	full = append(full, bwrapArgs...)
	full = append(full, "--", payloadPath)
	full = append(full, payloadArgs...)

	cmd.Path = bwrapBin
	cmd.Args = full

	return func() {
		if bridge != nil {
			bridge.Close()
		}
	}, nil
}

func inheritedEnv(env []string) []string {
	if env == nil {
		return append([]string(nil), os.Environ()...)
	}
	return append([]string(nil), env...)
}

type loopbackForwarders struct {
	dir       string
	ports     []int
	listeners []net.Listener
	once      sync.Once
}

func startLoopbackForwarders(ports []int) (*loopbackForwarders, error) {
	validated, err := validateLoopbackPorts(ports)
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp("", "go-sandbox-loopback-*")
	if err != nil {
		return nil, fmt.Errorf("create loopback forwarder dir: %w", err)
	}

	bridge := &loopbackForwarders{
		dir:   dir,
		ports: validated,
	}

	for _, port := range validated {
		socketPath := filepath.Join(dir, loopbackSocketName(port))
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			bridge.Close()
			return nil, fmt.Errorf("listen on loopback bridge socket for port %d: %w", port, err)
		}
		bridge.listeners = append(bridge.listeners, listener)
		go bridge.serve(listener, port)
	}

	return bridge, nil
}

func (f *loopbackForwarders) Close() {
	f.once.Do(func() {
		for _, listener := range f.listeners {
			_ = listener.Close()
		}
		_ = os.RemoveAll(f.dir)
	})
}

func (f *loopbackForwarders) serve(listener net.Listener, port int) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if isClosedNetworkError(err) {
				return
			}
			continue
		}
		go handleLoopbackForwardConn(conn, port)
	}
}

func handleLoopbackForwardConn(conn net.Conn, port int) {
	defer conn.Close()

	target, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return
	}
	defer target.Close()

	proxyConns(conn, target)
}

func proxyConns(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if tcp, ok := a.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		} else {
			_ = a.Close()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if tcp, ok := b.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		} else {
			_ = b.Close()
		}
	}()

	wg.Wait()
}

func validateLoopbackPorts(ports []int) ([]int, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	validated := slices.Clone(ports)
	slices.Sort(validated)
	for i, port := range validated {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid loopback forward port %d", port)
		}
		if i > 0 && validated[i-1] == port {
			return nil, fmt.Errorf("duplicate loopback forward port %d", port)
		}
	}
	return validated, nil
}

func encodeLoopbackPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ",")
}

func loopbackSocketName(port int) string {
	return fmt.Sprintf("%d.sock", port)
}

func isClosedNetworkError(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection")
}

type bwrapDenyShadow struct {
	Source string
	Dest   string
}

// BuildResolvedBwrap translates a resolved access policy into the bwrap
// argument list that follows the leading "bwrap" name and precedes the
// trailing "--" + payload separator. It is default-deny: only runtime/system
// reads, explicit read grants, write grants, provider state and scratch are
// mounted into the child namespace. SourceRead entries are intentionally not
// mounted because they are preparation inputs, not execution grants.
func BuildResolvedBwrap(p ResolvedAccessPolicy) ([]string, error) {
	return buildResolvedBwrapArgs(p, "", "", nil, nil)
}

// BuildResolvedBwrapArgs is kept as a compatibility alias for callers that
// adopted the M10 name while the API was settling.
func BuildResolvedBwrapArgs(p ResolvedAccessPolicy) ([]string, error) {
	return BuildResolvedBwrap(p)
}

// buildResolvedBwrapArgs builds the resolved-policy bwrap arguments. env is
// the child's environment (nil: the parent's); see buildBwrapArgs.
func buildResolvedBwrapArgs(p ResolvedAccessPolicy, helperPath, bridgeDir string, denyShadows []bwrapDenyShadow, env []string) ([]string, error) {
	if p.Mode == ConfinementDisabled {
		return nil, fmt.Errorf("%w: disabled policy %q has no bwrap arguments", ErrUnsupportedPolicy, p.ID)
	}
	if p.Subprocess == SubprocessDeny {
		return nil, fmt.Errorf("%w: subprocess deny is unsupported by linux bwrap resolved enforcement", ErrUnsupportedPolicy)
	}

	args := make([]string, 0, 48)
	seenMounts := map[string]bool{}
	mounted := make([]string, 0, 16)
	writableMounted := make([]string, 0, 8)
	addMount := func(flag, source, dest string) {
		key := dest
		if seenMounts[key] {
			return
		}
		seenMounts[key] = true
		mounted = append(mounted, dest)
		if flag == "--bind" {
			writableMounted = append(writableMounted, dest)
		}
		args = append(args, flag, source, dest)
	}
	alreadyMounted := func(path string) bool {
		for _, root := range mounted {
			if pathWithinBind(path, root) {
				return true
			}
		}
		return false
	}
	alreadyWritable := func(path string) bool {
		for _, root := range writableMounted {
			if pathWithinBind(path, root) {
				return true
			}
		}
		return false
	}

	for _, path := range bwrapResolvedSystemReadPaths() {
		addMount("--ro-bind", path, path)
	}

	// Hide host /tmp, then recreate parent directories needed by explicit
	// absolute mounts under the private tmpfs before binding the requested roots.
	args = append(args, "--tmpfs", "/tmp")
	for _, dir := range bwrapMountParentDirs(p, helperPath, bridgeDir, denyShadows) {
		args = append(args, "--dir", dir)
	}

	for _, item := range p.allWrites() {
		if err := ensureExistingBwrapSource(item.Path, true); err != nil {
			return nil, err
		}
		if !alreadyWritable(item.Path) {
			addMount("--bind", item.Path, item.Path)
		}
	}

	// Write protection right after the write mounts and before every read
	// mount, as for legacy profiles: a pin is a writable bind, and placed
	// first it can never re-expose a path a later read mount makes
	// read-only. Resolved paths and roots are canonical, so each mount's
	// Dest is its Canon.
	var protectRoots []protectRoot
	for _, item := range p.allWrites() {
		protectRoots = append(protectRoots, protectRoot{Dest: item.Path, Canon: item.Path, Writable: true})
	}
	for _, item := range p.allReads() {
		protectRoots = append(protectRoots, protectRoot{Dest: item.Path, Canon: item.Path})
	}
	plan, err := planProtect(resolvedPathStrings(p.FS.Protect), protectRoots)
	if err != nil {
		return nil, err
	}
	args = append(args, plan.pinArgs("--bind")...)
	args = append(args, plan.bindArgs()...)
	for _, item := range p.allReads() {
		if alreadyMounted(item.Path) {
			continue
		}
		if err := ensureExistingBwrapSource(item.Path, false); err != nil {
			return nil, err
		}
		addMount("--ro-bind", item.Path, item.Path)
	}

	if helperPath != "" && !resolvedPathVisibleInSandbox(helperPath, p) {
		addMount("--ro-bind", helperPath, helperPath)
	}
	if bridgeDir != "" && !resolvedPathVisibleInSandbox(bridgeDir, p) {
		addMount("--ro-bind", bridgeDir, bridgeDir)
	}

	// Deny precedence is implemented after broader read/write parents are mounted.
	// ApplyResolved passes unreadable shadow sources, which supports both file and
	// directory denies. The pure BuildResolvedBwrap path has no temp shadow source,
	// so it emits directory overlays directly and rejects file-level deny rules.
	if len(denyShadows) > 0 {
		for _, shadow := range denyShadows {
			args = append(args, "--ro-bind", shadow.Source, shadow.Dest)
		}
	} else {
		deniedDirs, err := pureResolvedBwrapDenyDirs(p)
		if err != nil {
			return nil, err
		}
		for _, denied := range deniedDirs {
			args = append(args, "--perms", "000", "--dir", denied)
		}
	}

	// Over every grant that shows the runtime directory, read-only ones
	// included: a read-only mount does not stop connect(2) on a socket.
	if p.DenyUserServiceManager {
		maskRoots := slices.Clone(protectRoots)
		for _, path := range bwrapResolvedSystemReadPaths() {
			maskRoots = append(maskRoots, newProtectRoot(path, false))
		}
		masks, err := userManagerMasks(maskRoots, resolvedPathStrings(p.allDenies()), env, p.Network.Mode == NetworkFull)
		if err != nil {
			return nil, err
		}
		args = append(args, masks...)
	}

	args = append(args,
		"--dev", "/dev",
		"--proc", "/proc",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-cgroup-try",
		"--unshare-user-try",
		"--new-session",
		"--die-with-parent",
	)

	switch p.Network.Mode {
	case NetworkFull:
		// Keep host network namespace by explicit policy request.
	case NetworkDeny, NetworkLoopback:
		args = append(args, "--unshare-net")
	default:
		return nil, fmt.Errorf("%w: unsupported network mode %q", ErrUnsupportedPolicy, p.Network.Mode)
	}

	if p.Roots.CWD != "" {
		if !alreadyMounted(p.Roots.CWD) {
			args = append(args, "--dir", p.Roots.CWD)
		}
		args = append(args, "--chdir", p.Roots.CWD)
	}

	return args, nil
}

func pureResolvedBwrapDenyDirs(p ResolvedAccessPolicy) ([]string, error) {
	denies := p.allDenies()
	if len(denies) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(denies))
	seen := map[string]bool{}
	for _, item := range denies {
		if seen[item.Path] {
			continue
		}
		info, err := os.Lstat(item.Path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("inspect denied bwrap path %q: %w", item.Path, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%w: linux bwrap pure argument generation supports directory deny overlays only, got %q", ErrUnsupportedPolicy, item.Path)
		}
		seen[item.Path] = true
		out = append(out, item.Path)
	}
	slices.SortFunc(out, func(a, b string) int {
		if depthA, depthB := pathDepthLinux(a), pathDepthLinux(b); depthA != depthB {
			return depthA - depthB
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	})
	return out, nil
}

func pathDepthLinux(path string) int {
	path = filepath.Clean(path)
	if path == string(filepath.Separator) {
		return 0
	}
	return strings.Count(path, string(filepath.Separator))
}

func bwrapResolvedSystemReadPaths() []string {
	return existingLinuxPaths(bwrapRoBindCandidates)
}

func existingLinuxPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, err := os.Lstat(path); err == nil {
			// Preserve Linux compatibility symlink mountpoints such as /bin and /lib.
			// Executables and ELF interpreters may still refer to those paths even
			// when the directories resolve under /usr on merged-/usr distros.
			out = append(out, filepath.Clean(path))
		}
	}
	return out
}

func ensureExistingBwrapSource(path string, writable bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			if writable {
				return fmt.Errorf("sandbox: writable bwrap source %q does not exist", path)
			}
			return fmt.Errorf("sandbox: readable bwrap source %q does not exist", path)
		}
		return fmt.Errorf("sandbox: inspect bwrap source %q: %w", path, err)
	}
	if writable && !info.IsDir() {
		return fmt.Errorf("sandbox: writable bwrap source %q is not a directory", path)
	}
	return nil
}

func bwrapMountParentDirs(p ResolvedAccessPolicy, helperPath, bridgeDir string, denyShadows []bwrapDenyShadow) []string {
	seen := map[string]bool{"/": true}
	var dirs []string
	addForPath := func(path string) {
		for _, dir := range parentDirsForBwrap(path) {
			if seen[dir] {
				continue
			}
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	for _, item := range p.allReads() {
		addForPath(item.Path)
	}
	for _, item := range p.allWrites() {
		addForPath(item.Path)
	}
	for _, item := range p.allDenies() {
		addForPath(item.Path)
	}
	if helperPath != "" {
		addForPath(helperPath)
	}
	if bridgeDir != "" {
		addForPath(bridgeDir)
	}
	for _, shadow := range denyShadows {
		addForPath(shadow.Dest)
	}
	slices.Sort(dirs)
	return dirs
}

func parentDirsForBwrap(path string) []string {
	path = filepath.Clean(path)
	parent := filepath.Dir(path)
	if parent == "." || parent == "/" {
		return nil
	}
	var rev []string
	for parent != "/" && parent != "." {
		rev = append(rev, parent)
		parent = filepath.Dir(parent)
	}
	out := make([]string, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		out = append(out, rev[i])
	}
	return out
}

func resolvedPathVisibleInSandbox(target string, p ResolvedAccessPolicy) bool {
	for _, item := range append(p.allReads(), p.allWrites()...) {
		if pathWithinBind(target, item.Path) {
			return true
		}
	}
	for _, candidate := range bwrapResolvedSystemReadPaths() {
		if pathWithinBind(target, candidate) {
			return true
		}
	}
	return false
}

func prepareBwrapDenyShadows(p ResolvedAccessPolicy) ([]bwrapDenyShadow, func(), error) {
	denies := p.allDenies()
	if len(denies) == 0 {
		return nil, func() {}, nil
	}
	dir, err := os.MkdirTemp("", "go-sandbox-deny-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create deny shadow dir: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	shadows := make([]bwrapDenyShadow, 0, len(denies))
	for i, item := range denies {
		info, err := os.Lstat(item.Path)
		if err != nil {
			cleanup()
			if os.IsNotExist(err) {
				return nil, nil, fmt.Errorf("sandbox: denied bwrap path %q does not exist; refusing to create host path for shadow deny", item.Path)
			}
			return nil, nil, fmt.Errorf("sandbox: inspect denied bwrap path %q: %w", item.Path, err)
		}
		shadow := filepath.Join(dir, fmt.Sprintf("deny-%d", i))
		if info.IsDir() {
			if err := os.Mkdir(shadow, 0o000); err != nil {
				cleanup()
				return nil, nil, fmt.Errorf("create deny shadow dir: %w", err)
			}
		} else {
			f, err := os.OpenFile(shadow, os.O_CREATE|os.O_EXCL, 0o000)
			if err != nil {
				cleanup()
				return nil, nil, fmt.Errorf("create deny shadow file: %w", err)
			}
			if err := f.Close(); err != nil {
				cleanup()
				return nil, nil, fmt.Errorf("close deny shadow file: %w", err)
			}
		}
		shadows = append(shadows, bwrapDenyShadow{Source: shadow, Dest: item.Path})
	}
	return shadows, cleanup, nil
}

func probeResolvedBwrapBackend(bwrapBin string, networkMode NetworkMode) error {
	truePath, err := exec.LookPath("true")
	if err != nil {
		return fmt.Errorf("%w: resolve true for bwrap capability probe: %v", ErrBackendUnavailable, err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(truePath); resolveErr == nil {
		truePath = resolved
	}

	args := make([]string, 0, 32)
	for _, path := range bwrapResolvedSystemReadPaths() {
		args = append(args, "--ro-bind", path, path)
	}
	if !pathVisibleInResolvedBwrapProbe(truePath) {
		args = append(args, "--ro-bind", truePath, truePath)
	}
	args = append(args,
		"--dev", "/dev",
		"--proc", "/proc",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-cgroup-try",
		"--unshare-user-try",
		"--new-session",
		"--die-with-parent",
	)
	if networkMode == NetworkDeny || networkMode == NetworkLoopback {
		args = append(args, "--unshare-net")
	}
	args = append(args, "--", truePath)

	cmd := exec.Command(bwrapBin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		return fmt.Errorf("%w: bwrap namespace probe failed: %s", ErrBackendUnavailable, detail)
	}
	return nil
}

func pathVisibleInResolvedBwrapProbe(target string) bool {
	for _, candidate := range bwrapResolvedSystemReadPaths() {
		if pathWithinBind(target, candidate) {
			return true
		}
	}
	return false
}

func applyResolved(cmd *exec.Cmd, p ResolvedAccessPolicy) (func(), error) {
	bwrapBin, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("%w: bwrap not found: cannot enforce policy %q on this system (install bubblewrap)", ErrBackendUnavailable, p.ID)
	}
	if err := probeResolvedBwrapBackend(bwrapBin, p.Network.Mode); err != nil {
		return nil, err
	}

	origPath := cmd.Path
	origArgs := cmd.Args[1:]
	payloadPath := origPath
	payloadArgs := origArgs
	useLoopbackHelper := p.Network.Mode == NetworkLoopback
	var bridge *loopbackForwarders

	helperPath := ""
	if useLoopbackHelper {
		resolvedOrigPath := origPath
		if !filepath.IsAbs(resolvedOrigPath) {
			resolvedOrigPath, err = exec.LookPath(origPath)
			if err != nil {
				return nil, fmt.Errorf("resolve sandbox target %q: %w", origPath, err)
			}
		}
		if len(p.Network.LoopbackPorts) > 0 {
			bridge, err = startLoopbackForwarders(p.Network.LoopbackPorts)
			if err != nil {
				return nil, err
			}
		}
		helperPath, err = os.Executable()
		if err != nil {
			if bridge != nil {
				bridge.Close()
			}
			return nil, fmt.Errorf("resolve loopback helper executable: %w", err)
		}
		if resolved, resolveErr := filepath.EvalSymlinks(helperPath); resolveErr == nil {
			helperPath = resolved
		}
		payloadPath = helperPath
		payloadArgs = append([]string{loopbackHelperArg, resolvedOrigPath}, origArgs...)
		cmd.Env = append(inheritedEnv(cmd.Env), loopbackHelperEnv+"=1")
		if bridge != nil {
			cmd.Env = append(cmd.Env,
				loopbackHelperForwardDirEnv+"="+bridge.dir,
				loopbackHelperForwardPortsEnv+"="+encodeLoopbackPorts(bridge.ports),
			)
		}
	}

	shadows, cleanupShadows, err := prepareBwrapDenyShadows(p)
	if err != nil {
		if bridge != nil {
			bridge.Close()
		}
		return nil, err
	}

	bridgeDir := ""
	if bridge != nil {
		bridgeDir = bridge.dir
	}
	bwrapArgs, err := buildResolvedBwrapArgs(p, helperPath, bridgeDir, shadows, cmd.Env)
	if err != nil {
		cleanupShadows()
		if bridge != nil {
			bridge.Close()
		}
		return nil, err
	}

	full := make([]string, 0, 1+len(bwrapArgs)+2+len(payloadArgs))
	full = append(full, "bwrap")
	full = append(full, bwrapArgs...)
	full = append(full, "--", payloadPath)
	full = append(full, payloadArgs...)

	cmd.Path = bwrapBin
	cmd.Args = full
	cmd.Dir = ""

	return func() {
		cleanupShadows()
		if bridge != nil {
			bridge.Close()
		}
	}, nil
}
