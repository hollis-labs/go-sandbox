//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// CW-20260930-0237: write-protected control-plane paths under Linux bwrap.

func argIndex(args []string, flag, path string) int {
	for i := 0; i+2 < len(args); i++ {
		if args[i] == flag && args[i+1] == path && args[i+2] == path {
			return i
		}
	}
	return -1
}

func realDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBwrapProtectLegacyBindsReadOnlyOverWorkspace(t *testing.T) {
	ws := realDir(t)
	state := filepath.Join(ws, ".state")
	if err := os.Mkdir(state, 0o755); err != nil {
		t.Fatal(err)
	}
	hidden := realDir(t) // outside every grant
	args, err := BuildBwrapArgs(Profile{ID: "p", FS: FSSpec{Protect: []string{state, hidden}}}, ws)
	if err != nil {
		t.Fatalf("BuildBwrapArgs: %v", err)
	}
	bind, ro := argIndex(args, "--bind", ws), argIndex(args, "--ro-bind", state)
	if bind < 0 || ro < 0 || ro < bind {
		t.Fatalf("want --ro-bind %s after --bind %s, got %v", state, ws, args)
	}
	if argIndex(args, "--ro-bind", hidden) >= 0 {
		t.Errorf("protected path outside every grant was mounted (protection must grant nothing): %v", args)
	}
}

func TestBwrapProtectRefusesMissingPathTheChildCouldCreate(t *testing.T) {
	ws := realDir(t)
	missing := filepath.Join(ws, "allow-list.json")
	_, err := BuildBwrapArgs(Profile{ID: "p", FS: FSSpec{Protect: []string{missing}}}, ws)
	if !errors.Is(err, ErrUnsupportedPolicy) || !strings.Contains(err.Error(), missing) {
		t.Fatalf("BuildBwrapArgs with a creatable missing protected path: err = %v, want ErrUnsupportedPolicy naming it", err)
	}

	// Missing but out of reach: inside an existing protected dir, or outside
	// every grant. Nothing to bind and nothing the child could create.
	state := filepath.Join(ws, "state")
	if err := os.Mkdir(state, 0o755); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(realDir(t), "not-yet")
	if _, err := BuildBwrapArgs(Profile{ID: "p", FS: FSSpec{Protect: []string{state, filepath.Join(state, "later.json"), elsewhere}}}, ws); err != nil {
		t.Fatalf("BuildBwrapArgs with unreachable missing paths: %v", err)
	}
}

func TestBwrapProtectHostFilesystem(t *testing.T) {
	ws := realDir(t)
	state := realDir(t)
	args, err := BuildBwrapArgs(Profile{ID: "host", HostFilesystem: true, Net: true, FS: FSSpec{Protect: []string{state}}}, ws)
	if err != nil {
		t.Fatalf("BuildBwrapArgs: %v", err)
	}
	if argIndex(args, "--dev-bind", "/") != 0 {
		t.Errorf("host filesystem profile does not start with --dev-bind / /: %v", args)
	}
	if argIndex(args, "--ro-bind", state) < 0 {
		t.Errorf("protected path not bound read-only: %v", args)
	}
	for _, flag := range []string{"--unshare-ipc", "--unshare-uts", "--new-session", "--unshare-net", "--tmpfs"} {
		if slices.Contains(args, flag) {
			t.Errorf("host filesystem profile with Net carries %s: %v", flag, args)
		}
	}
	// A private /proc: the host's would offer /proc/<pid>/root of same-uid
	// host processes, a way around every bind here.
	if !slices.Contains(args, "--unshare-pid") || argIndex(args, "--proc", "/proc") < 0 && !strings.Contains(strings.Join(args, " "), "--proc /proc") {
		t.Errorf("host filesystem profile lacks a private pid namespace and /proc: %v", args)
	}
	// The renameable ancestors of the protected path are pinned, shallow first,
	// before the read-only bind.
	parent := filepath.Dir(state)
	pin, ro := argIndex(args, "--dev-bind", parent), argIndex(args, "--ro-bind", state)
	if pin < 0 || ro < pin {
		t.Errorf("want --dev-bind %s (ancestor pin) before --ro-bind %s: %v", parent, state, args)
	}
	offline, err := BuildBwrapArgs(Profile{ID: "host", HostFilesystem: true}, ws)
	if err != nil || !slices.Contains(offline, "--unshare-net") {
		t.Errorf("host filesystem profile without Net: %v, %v; want --unshare-net", offline, err)
	}
	if _, err := BuildBwrapArgs(Profile{ID: "host", HostFilesystem: true, FS: FSSpec{Deny: []string{state}}}, ws); !errors.Is(err, ErrUnsupportedPolicy) {
		t.Errorf("host filesystem profile with FS.Deny: err = %v, want ErrUnsupportedPolicy", err)
	}
}

func TestBwrapProtectResolvedBindsBetweenWritesAndDenies(t *testing.T) {
	project := realDir(t)
	state := filepath.Join(project, "state")
	denied := filepath.Join(project, "denied")
	for _, dir := range []string{state, denied} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p, err := ResolveAccessPolicy(AccessPolicy{
		ID:      "resolved-protect",
		Roots:   Roots{Project: project},
		FS:      FilesystemAccess{Write: []PathRef{{Root: ProjectRoot}}, Deny: []PathRef{{Path: denied}}, Protect: []PathRef{{Path: state}}},
		Network: NetworkAccess{Mode: NetworkFull},
	})
	if err != nil {
		t.Fatal(err)
	}
	args, err := BuildResolvedBwrap(p)
	if err != nil {
		t.Fatalf("BuildResolvedBwrap: %v", err)
	}
	write, ro := argIndex(args, "--bind", project), argIndex(args, "--ro-bind", state)
	deny := slices.Index(args, denied)
	if write < 0 || ro < write || deny < ro {
		t.Fatalf("want --bind project, then --ro-bind state, then the deny overlay; got %v", args)
	}

	missing, err := p.WithProtected(filepath.Join(project, "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildResolvedBwrap(missing); !errors.Is(err, ErrUnsupportedPolicy) {
		t.Errorf("BuildResolvedBwrap with a creatable missing protected path: err = %v, want ErrUnsupportedPolicy", err)
	}
}

func requireBwrapLinux(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not found")
	}
	if out, err := exec.Command("bwrap", "--dev-bind", "/", "/", "--", "/bin/true").CombinedOutput(); err != nil {
		t.Skipf("bwrap cannot create a mount namespace here: %v: %s", err, out)
	}
}

// The behaviour the task asks for: a child under a sandbox with a protected
// path cannot write, create, rename or remove anything in it, and can still
// write next to it.
func TestApplyProtectHostFilesystemBlocksWrites(t *testing.T) {
	requireBwrapLinux(t)
	ws := realDir(t)
	state := realDir(t)
	if err := os.WriteFile(filepath.Join(state, "allow.json"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `
set -u
echo agent > "$WS/ok" || exit 10
echo pwned > "$STATE/allow.json" 2>/dev/null && exit 11
echo new > "$STATE/new.json" 2>/dev/null && exit 12
mv "$STATE/allow.json" "$STATE/moved" 2>/dev/null && exit 13
rm -f "$STATE/allow.json" 2>/dev/null; [ -f "$STATE/allow.json" ] || exit 14
mkdir "$STATE/sub" 2>/dev/null && exit 15
cat "$STATE/allow.json" >/dev/null || exit 16
exit 0
`
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Dir = ws
	cmd.Env = append(os.Environ(), "WS="+ws, "STATE="+state)
	cleanup, err := Apply(cmd, Profile{ID: "control-plane", HostFilesystem: true, Net: true, Subprocess: true, FS: FSSpec{Protect: []string{state}}}, ws)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandboxed script: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(filepath.Join(state, "allow.json")); string(got) != "original" {
		t.Errorf("protected file = %q after the run, want unchanged", got)
	}
	if _, err := os.Stat(filepath.Join(ws, "ok")); err != nil {
		t.Errorf("write next to the protected path did not land: %v", err)
	}
}

func TestApplyResolvedProtectBlocksWritesUnderAWriteGrant(t *testing.T) {
	requireBwrapLinux(t)
	project := realDir(t)
	state := filepath.Join(project, ".control")
	if err := os.Mkdir(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "db"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := ResolveAccessPolicy(AccessPolicy{
		ID:      "resolved-protect-run",
		Roots:   Roots{Project: project},
		FS:      FilesystemAccess{Write: []PathRef{{Root: ProjectRoot}}, Protect: []PathRef{{Root: ProjectRoot, Relative: ".control"}}},
		Runtime: RuntimeAccess{Executable: PathRef{Path: "/bin/sh"}},
		Network: NetworkAccess{Mode: NetworkFull},
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", `echo ok > "$P/work" || exit 10; echo pwned > "$P/.control/db" 2>/dev/null && exit 11; echo x > "$P/.control/new" 2>/dev/null && exit 12; exit 0`)
	cmd.Env = []string{"P=" + project, "PATH=/usr/bin:/bin"}
	out, cleanup, err := ApplyResolved(cmd, p)
	if err != nil {
		t.Fatalf("ApplyResolved: %+v %v", out, err)
	}
	defer cleanup()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandboxed script: %v\n%s", err, output)
	}
	if got, _ := os.ReadFile(filepath.Join(state, "db")); string(got) != "original" {
		t.Errorf("protected file = %q after the run, want unchanged", got)
	}
}

// The attack the adversarial review named: with /W writable and /W/state
// protected, `mv /W /W2` carries the read-only mount away, and the child
// recreates /W/state for the host to read. Pinning every renameable ancestor
// makes each a mount point, which cannot be renamed or removed.
func TestApplyProtectBlocksAncestorRenameAndFileTampering(t *testing.T) {
	requireBwrapLinux(t)
	script := `
set -u
for a in "$W/sub" "$W" "$BASE"; do mv "$a" "$a.moved" 2>/dev/null && exit 20; done
rmdir "$W/sub" 2>/dev/null && exit 21
echo pwned > "$W/sub/state/allow.json" 2>/dev/null && exit 22
echo pwned > "$W/sub/state/allow.json-wal" 2>/dev/null && exit 23
mv "$W/sub/state/allow.json" "$W/moved.json" 2>/dev/null && exit 24
rm -f "$W/sub/state/allow.json" 2>/dev/null; [ -f "$W/sub/state/allow.json" ] || exit 25
ln "$W/sub/state/allow.json" "$W/hard.json" 2>/dev/null && exit 26
echo ok > "$W/sibling" || exit 27
mkdir "$W/newdir" || exit 28
exit 0
`
	for _, name := range []string{"host-filesystem", "narrowed"} {
		t.Run(name, func(t *testing.T) {
			base := realDir(t)
			w := filepath.Join(base, "W")
			state := filepath.Join(w, "sub", "state")
			if err := os.MkdirAll(state, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(state, "allow.json"), []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			profile := Profile{ID: name, HostFilesystem: name == "host-filesystem", Net: true, Subprocess: true, FS: FSSpec{Protect: []string{state}}}
			cmd := exec.Command("/bin/sh", "-c", script)
			cmd.Dir = base
			cmd.Env = append(os.Environ(), "BASE="+base, "W="+w)
			cleanup, err := Apply(cmd, profile, base)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			defer cleanup()
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("sandboxed script: %v\n%s", err, out)
			}
			if got, _ := os.ReadFile(filepath.Join(state, "allow.json")); string(got) != "original" {
				t.Errorf("allow.json = %q after the run, want unchanged", got)
			}
			if _, err := os.Stat(filepath.Join(state, "allow.json-wal")); err == nil {
				t.Error("a sidecar was planted in the protected dir")
			}
		})
	}
}

func TestApplyResolvedProtectBlocksAncestorRename(t *testing.T) {
	requireBwrapLinux(t)
	project := realDir(t)
	state := filepath.Join(project, "a", "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "db"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := ResolveAccessPolicy(AccessPolicy{
		ID:      "resolved-ancestor",
		Roots:   Roots{Project: project},
		FS:      FilesystemAccess{Write: []PathRef{{Root: ProjectRoot}}, Protect: []PathRef{{Root: ProjectRoot, Relative: "a/state"}}},
		Runtime: RuntimeAccess{Executable: PathRef{Path: "/bin/sh"}},
		Network: NetworkAccess{Mode: NetworkFull},
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", `mv "$P/a" "$P/a2" 2>/dev/null && { mkdir -p "$P/a/state"; echo pwned > "$P/a/state/db"; exit 20; }; echo ok > "$P/a/sibling" || exit 21; exit 0`)
	cmd.Env = []string{"P=" + project, "PATH=/usr/bin:/bin"}
	out, cleanup, err := ApplyResolved(cmd, p)
	if err != nil {
		t.Fatalf("ApplyResolved: %+v %v", out, err)
	}
	defer cleanup()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandboxed script: %v\n%s", err, output)
	}
	if got, _ := os.ReadFile(filepath.Join(state, "db")); string(got) != "original" {
		t.Errorf("protected file = %q after the run, want unchanged", got)
	}
}

func TestBwrapProtectRefusesFilesRelativeAndRepointablePaths(t *testing.T) {
	ws := realDir(t)
	file := filepath.Join(ws, "torque.db")
	if err := os.WriteFile(file, []byte("rows"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(ws, "real-state")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(ws, "state")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	for name, entry := range map[string]string{"file": file, "relative": "state", "symlink in a writable dir": link} {
		for _, host := range []bool{false, true} {
			if _, err := BuildBwrapArgs(Profile{ID: "p", HostFilesystem: host, FS: FSSpec{Protect: []string{entry}}}, ws); !errors.Is(err, ErrUnsupportedPolicy) {
				t.Errorf("%s (host filesystem %v): err = %v, want ErrUnsupportedPolicy", name, host, err)
			}
		}
	}
}

// With protected paths, host-filesystem mode requires the user namespace
// (the kernel's ptrace and /proc/<pid>/root checks across it), rather than
// trying it.
func TestBwrapProtectHostFilesystemRequiresUserNamespace(t *testing.T) {
	ws := realDir(t)
	state := realDir(t)
	args, err := BuildBwrapArgs(Profile{ID: "host", HostFilesystem: true, Net: true, FS: FSSpec{Protect: []string{state}}}, ws)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(args, "--unshare-user") || slices.Contains(args, "--unshare-user-try") {
		t.Errorf("want --unshare-user (required), got %v", args)
	}
	unprotected, err := BuildBwrapArgs(Profile{ID: "host", HostFilesystem: true, Net: true}, ws)
	if err != nil || !slices.Contains(unprotected, "--unshare-user-try") {
		t.Errorf("without protected paths: %v, %v; want --unshare-user-try", unprotected, err)
	}
}

// A workspace reached through a symlink: the child sees it at the symlinked
// path, so the read-only bind must go there too. Before, the protected path
// (canonical) was compared with the unresolved workspace, nothing was bound,
// and the write landed.
func TestApplyProtectUnderSymlinkedWorkspace(t *testing.T) {
	requireBwrapLinux(t)
	base := realDir(t)
	realWS := filepath.Join(base, "real")
	state := filepath.Join(realWS, "proj", "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "allow.json"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realWS, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(base, "link", "proj")
	cmd := exec.Command("/bin/sh", "-c", `echo pwned > "$WS/state/allow.json" 2>/dev/null && exit 20; echo ok > "$WS/beside" || exit 21; exit 0`)
	cmd.Dir = ws
	cmd.Env = append(os.Environ(), "WS="+ws)
	cleanup, err := Apply(cmd, Profile{ID: "symlinked-ws", Net: true, Subprocess: true, FS: FSSpec{Protect: []string{state}}}, ws)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandboxed script: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(filepath.Join(state, "allow.json")); string(got) != "original" {
		t.Errorf("allow.json = %q after the run, want unchanged", got)
	}
}

// Pins are emitted before the read mounts: a pin on an ancestor of a
// protected dir must not cover a read-only grant beneath that ancestor and
// make it writable again.
func TestApplyProtectPinsDoNotUnshadowReadOnlyGrants(t *testing.T) {
	requireBwrapLinux(t)
	ws := realDir(t)
	readOnly := filepath.Join(ws, "a", "ro")
	state := filepath.Join(ws, "a", "b", "state")
	for _, dir := range []string{readOnly, state} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("/bin/sh", "-c", `echo x > "$WS/a/ro/x" 2>/dev/null && exit 20; echo x > "$WS/a/b/state/x" 2>/dev/null && exit 21; echo ok > "$WS/a/beside" || exit 22; exit 0`)
	cmd.Dir = ws
	cmd.Env = append(os.Environ(), "WS="+ws)
	cleanup, err := Apply(cmd, Profile{ID: "ro-under-pin", Net: true, Subprocess: true, FS: FSSpec{Read: []string{readOnly}, Protect: []string{state}}}, ws)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sandboxed script: %v\n%s", err, out)
	}
}
