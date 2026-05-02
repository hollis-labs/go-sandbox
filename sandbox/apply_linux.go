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
	return buildBwrapArgs(p, workspace, "", "")
}

func buildBwrapArgs(p Profile, workspace, helperPath, bridgeDir string) ([]string, error) {
	absWS, err := filepath.Abs(workspace)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace dir: %w", err)
	}

	args := make([]string, 0, 32)

	// Narrowed read-only mounts (gap #1). Missing paths are skipped so
	// different distros (musl/glibc, multiarch/single-arch) all work.
	for _, path := range bwrapRoBindCandidates {
		if _, statErr := os.Lstat(path); statErr == nil {
			args = append(args, "--ro-bind", path, path)
		}
	}

	if helperPath != "" && !pathVisibleInSandbox(helperPath, absWS, p) {
		args = append(args, "--ro-bind", helperPath, helperPath)
	}
	if bridgeDir != "" && !pathVisibleInSandbox(bridgeDir, absWS, p) {
		args = append(args, "--bind", bridgeDir, bridgeDir)
	}

	// Workspace is the writable root; per-invocation /tmp avoids host leakage.
	args = append(args,
		"--bind", absWS, absWS,
		"--tmpfs", "/tmp",
		"--dev", "/dev",
		"--proc", "/proc",
	)

	// Additional Write paths.
	home, _ := os.UserHomeDir()
	seen := map[string]bool{absWS: true}
	for _, raw := range p.FS.Write {
		path := expandPathLinux(raw, absWS, home)
		if seen[path] {
			continue
		}
		seen[path] = true
		args = append(args, "--bind", path, path)
	}

	// Additional Read paths (try-bind so missing paths are skipped, not errors).
	for _, raw := range p.FS.Read {
		path := expandPathLinux(raw, absWS, home)
		if seen[path] {
			continue
		}
		seen[path] = true
		args = append(args, "--ro-bind-try", path, path)
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

func pathVisibleInSandbox(target, workspace string, p Profile) bool {
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

	bridgeDir := ""
	if bridge != nil {
		bridgeDir = bridge.dir
	}
	bwrapArgs, err := buildBwrapArgs(p, workspace, helperPath, bridgeDir)
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
