//go:build linux

package sandbox

import (
	"bufio"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// DenyUserServiceManager on Linux (CW-20261001-0128).
//
// The systemd user service manager runs whatever it is asked to, outside any
// sandbox and as the same uid: `systemd-run --user touch /protected/x` writes a
// protected path on the child's behalf. Measured against systemd 259, the
// manager answers on two kinds of socket, and both must be hidden:
//
//   - $XDG_RUNTIME_DIR/systemd/: its private D-Bus socket ("private") and its
//     Varlink sockets (io.systemd.Manager, ...).
//   - The session bus ($XDG_RUNTIME_DIR/bus, or DBUS_SESSION_BUS_ADDRESS),
//     where it is org.freedesktop.systemd1. `systemd-run --user --wait`, or any
//     D-Bus client calling StartTransientUnit, gets through there with
//     systemd/ hidden.
//
// A read-only mount does not stop connect(2) on a socket, so a read grant that
// covers the runtime directory exposes both. The masks are mounts, so the child
// cannot remove them: it has no capabilities, and a nested user namespace
// inherits them locked (mount_namespaces(7)). They cover the sockets present at
// launch: a host that unlinks and recreates one (a dbus restart) detaches the
// mask from the old file, and the new socket is visible.

// userManagerTargets are the canonical host paths to hide.
type userManagerTargets struct {
	dirs    []string // systemd/ directories: an empty read-only tmpfs over each
	sockets []string // session-bus sockets and hard links to them: /dev/null over each
}

// maxRuntimeDirEntries bounds the hard-link search of a runtime directory.
const maxRuntimeDirEntries = 20000

// userManagerMasks returns the bwrap mounts that hide the user service manager
// wherever roots show it to the child. env is the child's environment (nil
// means the parent's); the parent's is consulted as well, since the child can
// set its own. denied are canonical paths already hidden by a deny overlay.
// With the network namespace shared, a session bus that mounts cannot hide
// (an abstract-socket or TCP address) is refused.
func userManagerMasks(roots []protectRoot, denied []string, env []string, netShared bool) ([]string, error) {
	envs := [][]string{os.Environ()}
	if env != nil {
		envs = append(envs, env)
	}
	return userManagerMasksFor(roots, denied, envs, os.Getuid(), netShared)
}

func userManagerMasksFor(roots []protectRoot, denied []string, envs [][]string, uid int, netShared bool) ([]string, error) {
	targets, err := findUserManagerTargets(envs, uid, netShared)
	if err != nil {
		return nil, err
	}
	var args []string
	seen := map[string]bool{}
	emit := func(canon string, dir bool) {
		if slices.ContainsFunc(denied, func(d string) bool { return underPath(canon, d) }) {
			return
		}
		for _, root := range roots {
			if !underPath(canon, root.Canon) {
				continue
			}
			dest := filepath.Join(root.Dest, mustRel(root.Canon, canon))
			if seen[dest] {
				continue
			}
			seen[dest] = true
			if dir {
				args = append(args, "--tmpfs", dest, "--remount-ro", dest)
			} else {
				args = append(args, "--ro-bind", "/dev/null", dest)
			}
		}
	}
	for _, socket := range targets.sockets {
		emit(socket, false)
	}
	for _, dir := range targets.dirs {
		emit(dir, true)
	}
	return args, nil
}

// underPath reports whether path is root or inside it. Both are clean
// absolute paths; root may be "/".
func underPath(path, root string) bool {
	return root == "/" || path == root || strings.HasPrefix(path, root+"/")
}

func findUserManagerTargets(envs [][]string, uid int, netShared bool) (userManagerTargets, error) {
	var t userManagerTargets
	var runtimeDirs, busAddrs []string
	addRuntimeDir := func(raw string) {
		if !filepath.IsAbs(raw) {
			return
		}
		canon, err := filepath.EvalSymlinks(raw)
		if err != nil {
			return
		}
		if info, err := os.Stat(canon); err == nil && info.IsDir() && !slices.Contains(runtimeDirs, canon) {
			runtimeDirs = append(runtimeDirs, canon)
		}
	}
	for _, env := range envs {
		if v := envValue(env, "XDG_RUNTIME_DIR"); v != "" {
			addRuntimeDir(v)
		}
		if v := envValue(env, "DBUS_SESSION_BUS_ADDRESS"); v != "" && !slices.Contains(busAddrs, v) {
			busAddrs = append(busAddrs, v)
		}
	}
	// logind's runtime directory, whatever the environment says: the child
	// can point XDG_RUNTIME_DIR there itself.
	addRuntimeDir(fmt.Sprintf("/run/user/%d", uid))

	addTarget := func(raw string) error {
		if _, err := os.Lstat(raw); err != nil {
			return nil
		}
		canon, err := filepath.EvalSymlinks(raw)
		if err != nil {
			return nil
		}
		info, err := os.Stat(canon)
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if !slices.Contains(t.dirs, canon) {
				t.dirs = append(t.dirs, canon)
			}
		} else if !slices.Contains(t.sockets, canon) {
			t.sockets = append(t.sockets, canon)
		}
		return nil
	}
	for _, dir := range runtimeDirs {
		_ = addTarget(filepath.Join(dir, "bus"))
		if info, err := os.Lstat(filepath.Join(dir, "systemd")); err == nil && (info.IsDir() || info.Mode()&fs.ModeSymlink != 0) {
			_ = addTarget(filepath.Join(dir, "systemd"))
		}
	}
	for _, addr := range busAddrs {
		paths, err := sessionBusPaths(addr, netShared)
		if err != nil {
			return userManagerTargets{}, err
		}
		for _, path := range paths {
			_ = addTarget(path)
		}
	}
	aliases, err := findSocketAliases(runtimeDirs, t)
	if err != nil {
		return userManagerTargets{}, err
	}
	for _, alias := range aliases {
		if !slices.Contains(t.sockets, alias) {
			t.sockets = append(t.sockets, alias)
		}
	}
	// A socket inside a masked directory is already hidden, and binding over
	// it would need the read-only tmpfs to be writable.
	t.sockets = slices.DeleteFunc(t.sockets, func(s string) bool {
		return slices.ContainsFunc(t.dirs, func(d string) bool { return underPath(s, d) })
	})
	slices.Sort(t.sockets)
	slices.Sort(t.dirs)
	return t, nil
}

func envValue(env []string, key string) string {
	value := ""
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			value = v // last one wins, as for exec
		}
	}
	return value
}

// sessionBusPaths returns the socket paths in a D-Bus address
// ("transport:key=value,...;..."). A path-based unix socket can be masked; an
// abstract socket or a TCP address lives in the network namespace, so it is
// unreachable only when that is unshared, and refused otherwise. Any other
// transport is refused: the mounts cannot account for it.
func sessionBusPaths(addr string, netShared bool) ([]string, error) {
	var paths []string
	for _, entry := range strings.Split(addr, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		transport, params, _ := strings.Cut(entry, ":")
		kv := map[string]string{}
		for _, pair := range strings.Split(params, ",") {
			k, v, ok := strings.Cut(pair, "=")
			if !ok {
				continue
			}
			if unescaped, err := url.PathUnescape(v); err == nil {
				v = unescaped
			}
			kv[k] = v
		}
		unreachable := func(what string) error {
			if netShared {
				return fmt.Errorf("%w: DenyUserServiceManager cannot hide a session bus at %s (%q) while the sandbox shares the host network namespace", ErrUnsupportedPolicy, what, entry)
			}
			return nil
		}
		switch transport {
		case "unix":
			switch {
			case kv["path"] != "":
				paths = append(paths, kv["path"])
			case kv["runtime"] == "yes":
				// $XDG_RUNTIME_DIR/bus, masked with the runtime directory.
			case kv["abstract"] != "":
				if err := unreachable("an abstract socket"); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("%w: DenyUserServiceManager cannot account for session bus address %q", ErrUnsupportedPolicy, entry)
			}
		case "tcp", "nonce-tcp":
			if err := unreachable("a TCP address"); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: DenyUserServiceManager cannot account for session bus transport %q", ErrUnsupportedPolicy, entry)
		}
	}
	return paths, nil
}

// findSocketAliases searches each runtime directory for hard links to a target
// socket or to anything inside a target directory: a link planted earlier
// (say, by an agent run without this option) would otherwise stay reachable
// under another name. Hard links cannot leave a filesystem, so it skips other
// mounts beneath the directory without touching them (a FUSE mount such as
// gvfs can hang a stat). A runtime directory that is not its own filesystem
// is searched only within itself.
func findSocketAliases(runtimeDirs []string, t userManagerTargets) ([]string, error) {
	type inode struct{ dev, ino uint64 }
	wanted := map[inode]bool{}
	record := func(path string) {
		var st syscall.Stat_t
		if err := syscall.Lstat(path, &st); err == nil && st.Mode&syscall.S_IFMT != syscall.S_IFDIR && st.Mode&syscall.S_IFMT != syscall.S_IFLNK {
			wanted[inode{uint64(st.Dev), st.Ino}] = true //nolint:unconvert // Dev's width varies by arch
		}
	}
	for _, socket := range t.sockets {
		record(socket)
	}
	for _, dir := range t.dirs {
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				record(path)
			}
			return nil
		})
	}
	if len(wanted) == 0 {
		return nil, nil
	}
	mounts, err := mountPoints()
	if err != nil {
		return nil, err
	}
	var aliases []string
	for _, root := range runtimeDirs {
		entries := 0
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return fmt.Errorf("%w: DenyUserServiceManager cannot search %q for links to the session bus: %v", ErrUnsupportedPolicy, path, walkErr)
			}
			if entries++; entries > maxRuntimeDirEntries {
				return fmt.Errorf("%w: DenyUserServiceManager: %q has more than %d entries to search for links to the session bus", ErrUnsupportedPolicy, root, maxRuntimeDirEntries)
			}
			if d.IsDir() {
				if path != root && (mounts[path] || slices.Contains(t.dirs, path)) {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 || slices.Contains(t.sockets, path) {
				return nil
			}
			var st syscall.Stat_t
			if err := syscall.Lstat(path, &st); err == nil && wanted[inode{uint64(st.Dev), st.Ino}] { //nolint:unconvert // Dev's width varies by arch
				aliases = append(aliases, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return aliases, nil
}

// mountPoints returns this mount namespace's mount points from
// /proc/self/mountinfo.
func mountPoints() (map[string]bool, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("sandbox: read mount table: %w", err)
	}
	defer func() { _ = f.Close() }()
	mounts := map[string]bool{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		mounts[unescapeMountinfo(fields[4])] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("sandbox: read mount table: %w", err)
	}
	return mounts, nil
}

// unescapeMountinfo decodes the octal escapes (\040 for a space) the kernel
// writes in mountinfo paths.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
