//go:build linux

package sandbox

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// CW-20261001-0128: DenyUserServiceManager hides the systemd user manager,
// which would otherwise run a command for the child outside the sandbox and
// write a protected path for it.

// fakeUID has no /run/user directory, so tests see only their own runtime dir.
const fakeUID = 1 << 30

// listenUnix creates a listening unix socket at path, closed at cleanup.
func listenUnix(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
}

// fakeRuntimeDir builds a runtime directory shaped like logind's: a session
// bus, the manager's systemd/ sockets, an unrelated agent socket, and hard
// links to the bus and the private socket planted elsewhere in it.
func fakeRuntimeDir(t *testing.T) string {
	t.Helper()
	// Short: a socket path must fit sun_path (108 bytes), and t.TempDir's
	// names do not.
	tmp, err := os.MkdirTemp("", "usm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	dir, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	listenUnix(t, filepath.Join(dir, "bus"))
	listenUnix(t, filepath.Join(dir, "systemd", "private"))
	listenUnix(t, filepath.Join(dir, "systemd", "io.systemd.Manager"))
	listenUnix(t, filepath.Join(dir, "agent.sock"))
	if err := os.MkdirAll(filepath.Join(dir, "planted"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(dir, "bus"), filepath.Join(dir, "planted", "bus-alias")); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := os.Link(filepath.Join(dir, "systemd", "private"), filepath.Join(dir, "private-alias")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSessionBusPaths(t *testing.T) {
	cases := []struct {
		addr      string
		netShared bool
		want      []string
		refused   bool
	}{
		{addr: "unix:path=/run/user/1000/bus", want: []string{"/run/user/1000/bus"}},
		{addr: "unix:path=/tmp/a%2cb,guid=00", want: []string{"/tmp/a,b"}},
		{addr: "unix:runtime=yes"},
		{addr: "unix:path=/a;unix:path=/b", want: []string{"/a", "/b"}},
		{addr: "unix:abstract=/tmp/dbus-x,guid=00", netShared: true, refused: true},
		{addr: "unix:abstract=/tmp/dbus-x,guid=00"},
		{addr: "tcp:host=localhost,port=1234", netShared: true, refused: true},
		{addr: "tcp:host=localhost,port=1234"},
		{addr: "unix:tmpdir=/tmp", refused: true},
		{addr: "autolaunch:", refused: true},
		{addr: "unixexec:path=/bin/sh", refused: true},
	}
	for _, tc := range cases {
		got, err := sessionBusPaths(tc.addr, tc.netShared)
		if tc.refused {
			if !errors.Is(err, ErrUnsupportedPolicy) {
				t.Errorf("sessionBusPaths(%q, net shared %v) = %v, %v; want ErrUnsupportedPolicy", tc.addr, tc.netShared, got, err)
			}
			continue
		}
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("sessionBusPaths(%q, net shared %v) = %v, %v; want %v", tc.addr, tc.netShared, got, err, tc.want)
		}
	}
}

func TestFindUserManagerTargetsIncludesHardLinkAliases(t *testing.T) {
	dir := fakeRuntimeDir(t)
	got, err := findUserManagerTargets([][]string{{"XDG_RUNTIME_DIR=" + dir}}, fakeUID, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(dir, "systemd")}; !slices.Equal(got.dirs, want) {
		t.Errorf("dirs = %v, want %v", got.dirs, want)
	}
	want := []string{filepath.Join(dir, "bus"), filepath.Join(dir, "planted", "bus-alias"), filepath.Join(dir, "private-alias")}
	if !slices.Equal(got.sockets, want) {
		t.Errorf("sockets = %v, want %v (agent.sock untouched)", got.sockets, want)
	}
}

func TestFindUserManagerTargetsFollowsTheBusAddressAndRefusesAbstract(t *testing.T) {
	dir := fakeRuntimeDir(t)
	elsewhere := filepath.Join(fakeRuntimeDir(t), "session-bus")
	listenUnix(t, elsewhere)
	env := []string{"DBUS_SESSION_BUS_ADDRESS=unix:path=" + elsewhere + ",guid=0", "XDG_RUNTIME_DIR=" + dir}
	got, err := findUserManagerTargets([][]string{env}, fakeUID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got.sockets, elsewhere) {
		t.Errorf("sockets = %v, want the bus address %s", got.sockets, elsewhere)
	}
	abstract := []string{"DBUS_SESSION_BUS_ADDRESS=unix:abstract=/tmp/dbus-x", "XDG_RUNTIME_DIR=" + dir}
	if _, err := findUserManagerTargets([][]string{abstract}, fakeUID, true); !errors.Is(err, ErrUnsupportedPolicy) {
		t.Errorf("abstract bus with a shared network: err = %v, want ErrUnsupportedPolicy", err)
	}
	if _, err := findUserManagerTargets([][]string{abstract}, fakeUID, false); err != nil {
		t.Errorf("abstract bus with the network unshared: err = %v, want nil", err)
	}
}

func TestUserManagerMasksMapThroughRoots(t *testing.T) {
	dir := fakeRuntimeDir(t)
	envs := [][]string{{"XDG_RUNTIME_DIR=" + dir}}
	masks := func(roots []protectRoot, denied []string) []string {
		t.Helper()
		args, err := userManagerMasksFor(roots, denied, envs, fakeUID, true)
		if err != nil {
			t.Fatal(err)
		}
		return args
	}
	host := masks([]protectRoot{{Dest: "/", Canon: "/", Writable: true}}, nil)
	for _, want := range [][]string{
		{"--ro-bind", "/dev/null", filepath.Join(dir, "bus")},
		{"--ro-bind", "/dev/null", filepath.Join(dir, "planted", "bus-alias")},
		{"--ro-bind", "/dev/null", filepath.Join(dir, "private-alias")},
		{"--tmpfs", filepath.Join(dir, "systemd"), "--remount-ro", filepath.Join(dir, "systemd")},
	} {
		if !containsSeq(host, want) {
			t.Errorf("host-filesystem masks %q lack %q", host, want)
		}
	}
	if strings.Contains(strings.Join(host, " "), "agent.sock") {
		t.Errorf("masks %q touch an unrelated socket", host)
	}
	// A grant that shows the directory elsewhere gets the masks there.
	moved := masks([]protectRoot{{Dest: "/sandbox/rt", Canon: dir}}, nil)
	if !containsSeq(moved, []string{"--ro-bind", "/dev/null", "/sandbox/rt/bus"}) {
		t.Errorf("masks through a moved root = %q, want them at /sandbox/rt", moved)
	}
	if got := masks([]protectRoot{{Dest: "/elsewhere", Canon: "/elsewhere"}}, nil); len(got) != 0 {
		t.Errorf("masks with no root showing the runtime dir = %q, want none", got)
	}
	if got := masks([]protectRoot{{Dest: "/", Canon: "/"}}, []string{dir}); len(got) != 0 {
		t.Errorf("masks under a denied runtime dir = %q, want none", got)
	}
}

func containsSeq(args, seq []string) bool {
	for i := 0; i+len(seq) <= len(args); i++ {
		if slices.Equal(args[i:i+len(seq)], seq) {
			return true
		}
	}
	return false
}

// The masks come last, after the protect binds, so nothing re-exposes the
// sockets; and only when asked for.
func TestBwrapDenyUserServiceManagerPlacement(t *testing.T) {
	dir := fakeRuntimeDir(t)
	env := []string{"XDG_RUNTIME_DIR=" + dir}
	bus := []string{"--ro-bind", "/dev/null", filepath.Join(dir, "bus")}
	state := realDir(t)

	hostArgs, err := buildHostFilesystemBwrapArgs(Profile{ID: "h", HostFilesystem: true, Net: true, DenyUserServiceManager: true, FS: FSSpec{Protect: []string{state}}}, realDir(t), env)
	if err != nil {
		t.Fatal(err)
	}
	if !containsSeq(hostArgs, bus) || argIndex(hostArgs, "--ro-bind", state) > slices.Index(hostArgs, filepath.Join(dir, "bus")) {
		t.Errorf("host-filesystem args %q: want the bus masked after the protect bind", hostArgs)
	}
	plain, err := buildHostFilesystemBwrapArgs(Profile{ID: "h", HostFilesystem: true, Net: true}, realDir(t), env)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(plain, " "), "/dev/null") {
		t.Errorf("args without the option mask something: %q", plain)
	}

	ws := realDir(t)
	legacy, err := buildBwrapArgs(Profile{ID: "l", DenyUserServiceManager: true, FS: FSSpec{Read: []string{dir}}}, ws, "", "", env)
	if err != nil {
		t.Fatal(err)
	}
	if !containsSeq(legacy, bus) || argIndex(legacy, "--ro-bind-try", dir) > slices.Index(legacy, filepath.Join(dir, "bus")) {
		t.Errorf("legacy args %q: want the bus masked after the read grant that shows it", legacy)
	}

	resolved, err := ResolveAccessPolicy(AccessPolicy{
		ID: "r", Roots: Roots{Project: ws},
		FS:                     FilesystemAccess{Read: []PathRef{{Path: dir}}, Write: []PathRef{{Root: ProjectRoot}}},
		DenyUserServiceManager: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	rargs, err := buildResolvedBwrapArgs(resolved, "", "", nil, env)
	if err != nil {
		t.Fatal(err)
	}
	if !containsSeq(rargs, bus) || argIndex(rargs, "--ro-bind", dir) > slices.Index(rargs, filepath.Join(dir, "bus")) {
		t.Errorf("resolved args %q: want the bus masked after the read grant that shows it", rargs)
	}
}

func TestBwrapDenyUserServiceManagerRefusesAnAbstractBusOnTheHostNetwork(t *testing.T) {
	env := []string{"DBUS_SESSION_BUS_ADDRESS=unix:abstract=/tmp/dbus-x,guid=0"}
	_, err := buildHostFilesystemBwrapArgs(Profile{ID: "h", HostFilesystem: true, Net: true, DenyUserServiceManager: true}, realDir(t), env)
	if !errors.Is(err, ErrUnsupportedPolicy) {
		t.Fatalf("err = %v, want ErrUnsupportedPolicy", err)
	}
	if _, err := buildHostFilesystemBwrapArgs(Profile{ID: "h", HostFilesystem: true, Net: false, DenyUserServiceManager: true}, realDir(t), env); err != nil {
		t.Fatalf("with the network unshared: err = %v, want nil", err)
	}
}

// requireUserManager skips unless this host has a systemd user manager that
// systemd-run --user can reach.
func requireUserManager(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("systemd-run not found")
	}
	if out, err := exec.Command("systemd-run", "--user", "--wait", "--quiet", "true").CombinedOutput(); err != nil {
		t.Skipf("no reachable systemd user manager: %v: %s", err, out)
	}
}

// The reported gap, end to end with real bwrap: under a HostFilesystem
// profile protecting a directory, systemd-run --user writes into it from
// outside the sandbox; with DenyUserServiceManager it cannot, by either the
// session bus (--wait) or the manager's private socket (no --wait).
func TestApplyDenyUserServiceManagerStopsSystemdRun(t *testing.T) {
	requireBwrapLinux(t)
	requireUserManager(t)
	run := func(deny bool) string {
		t.Helper()
		ws := realDir(t)
		state := realDir(t)
		script := `
systemd-run --user --wait --quiet touch "$STATE/via-bus" 2>&1
systemd-run --user --quiet touch "$STATE/via-private" 2>&1
busctl --user call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.DBus.Peer Ping 2>&1 && echo bus-reachable
exit 0
`
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Dir = ws
		cmd.Env = append(os.Environ(), "STATE="+state)
		cleanup, err := Apply(cmd, Profile{ID: "control-plane", HostFilesystem: true, Net: true, Subprocess: true,
			DenyUserServiceManager: deny, FS: FSSpec{Protect: []string{state}}}, ws)
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		defer cleanup()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("sandboxed script: %v\n%s", err, out)
		}
		time.Sleep(2 * time.Second) // the no-wait unit runs asynchronously
		var wrote []string
		for _, name := range []string{"via-bus", "via-private"} {
			if _, err := os.Stat(filepath.Join(state, name)); err == nil {
				wrote = append(wrote, name)
			}
		}
		return strings.Join(wrote, ",") + "|" + string(out)
	}

	// Control: the delegated write gets past Protect without the option.
	if got := run(false); !strings.HasPrefix(got, "via-bus") || !strings.Contains(got, "bus-reachable") {
		t.Fatalf("without DenyUserServiceManager: wrote|output = %q, want the bus write to land", got)
	}
	if got := run(true); !strings.HasPrefix(got, "|") || strings.Contains(got, "bus-reachable") {
		t.Fatalf("with DenyUserServiceManager: wrote|output = %q, want no write and no bus", got)
	}
}

// The masks leave the rest of the runtime directory alone, and catch a hard
// link planted to the bus.
func TestApplyDenyUserServiceManagerMasksOnlyTheManager(t *testing.T) {
	requireBwrapLinux(t)
	dir := fakeRuntimeDir(t)
	script := `
[ -c "$R/bus" ] || exit 10
[ -c "$R/planted/bus-alias" ] || exit 11
[ -c "$R/private-alias" ] || exit 12
[ -z "$(ls -A "$R/systemd")" ] || exit 13
mkdir "$R/systemd/x" 2>/dev/null && exit 14
[ -S "$R/agent.sock" ] || exit 15
rm "$R/bus" 2>/dev/null && exit 16
exit 0
`
	ws := realDir(t)
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Dir = ws
	cmd.Env = append(os.Environ(), "R="+dir, "XDG_RUNTIME_DIR="+dir)
	cleanup, err := Apply(cmd, Profile{ID: "masks", HostFilesystem: true, Net: true, Subprocess: true, DenyUserServiceManager: true}, ws)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandboxed script: %v\n%s", err, out)
	}
}

// A resolved policy whose read grant shows the runtime directory: a
// read-only mount does not stop connect(2), so the bus answers unless the
// option masks it.
func TestApplyResolvedDenyUserServiceManagerUnderAReadGrant(t *testing.T) {
	requireBwrapLinux(t)
	requireUserManager(t)
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		t.Skip("XDG_RUNTIME_DIR unset")
	}
	busctl, err := exec.LookPath("busctl")
	if err != nil {
		t.Skip("busctl not found")
	}
	run := func(deny bool) (string, error) {
		ws := realDir(t)
		policy, err := ResolveAccessPolicy(AccessPolicy{
			ID: "resolved", Roots: Roots{Project: ws},
			FS:                     FilesystemAccess{Read: []PathRef{{Path: runtimeDir}}, Write: []PathRef{{Root: ProjectRoot}}},
			Network:                NetworkAccess{Mode: NetworkDeny},
			DenyUserServiceManager: deny,
		})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(busctl, "--user", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.DBus.Peer", "Ping")
		cmd.Dir = ws
		outcome, cleanup, err := ApplyResolved(cmd, policy)
		if err != nil {
			t.Fatalf("ApplyResolved: %v (%+v)", err, outcome)
		}
		defer cleanup()
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(false); err != nil {
		t.Skipf("busctl cannot reach the bus under this resolved policy even without the option: %v: %s", err, out)
	}
	if out, err := run(true); err == nil {
		t.Fatalf("with DenyUserServiceManager, busctl --user still reached the manager: %s", out)
	}
}
