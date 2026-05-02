//go:build linux

package sandbox

import (
	"os/exec"
	"strings"
	"testing"
)

// TestBwrapArgs_NarrowedMounts verifies the argument list puts the expected
// bwrap flags in place: narrowed read-only mounts (no blanket
// `--ro-bind / /`), per-invocation tmpfs for /tmp, and the full set of
// namespace unshare flags. Regression test for nanite's audit finding 06.
func TestBwrapArgs_NarrowedMounts(t *testing.T) {
	args, err := BuildBwrapArgs(Profile{ID: "t", Net: false}, t.TempDir())
	if err != nil {
		t.Fatalf("BuildBwrapArgs: %v", err)
	}
	joined := strings.Join(args, " ")

	// Must NOT contain the old blanket-mount flag.
	if strings.Contains(joined, "--ro-bind / /") {
		t.Errorf("bwrap still uses blanket `--ro-bind / /`; finding 06 gap #1 regressed\nargs: %s", joined)
	}
	// Must use a per-invocation tmpfs for /tmp, not a host bind.
	if !strings.Contains(joined, "--tmpfs /tmp") {
		t.Errorf("bwrap missing `--tmpfs /tmp`; finding 06 gap #4 regressed\nargs: %s", joined)
	}
	if strings.Contains(joined, "--bind /tmp /tmp") {
		t.Errorf("bwrap still binds host /tmp; finding 06 gap #4 regressed\nargs: %s", joined)
	}
	for _, want := range []string{
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-net",
		"--unshare-user-try",
		"--die-with-parent",
		"--new-session",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("bwrap args missing %q\nargs: %s", want, joined)
		}
	}
}

// TestBwrapArgs_UnshareNetConditional verifies --unshare-net is gated on
// p.Net == false. With p.Net == true the netns is left intact so a future
// in-namespace proxy can mediate egress; with p.Net == false the sandbox
// is fully offline.
func TestBwrapArgs_UnshareNetConditional(t *testing.T) {
	denied, err := BuildBwrapArgs(Profile{ID: "t", Net: false}, t.TempDir())
	if err != nil {
		t.Fatalf("BuildBwrapArgs (net=false): %v", err)
	}
	deniedJoin := strings.Join(denied, " ")
	if !strings.Contains(deniedJoin, "--unshare-net") {
		t.Errorf("net=false: --unshare-net missing; expected offline sandbox\nargs: %s", deniedJoin)
	}

	allowed, err := BuildBwrapArgs(Profile{ID: "t", Net: true}, t.TempDir())
	if err != nil {
		t.Fatalf("BuildBwrapArgs (net=true): %v", err)
	}
	allowedJoin := strings.Join(allowed, " ")
	if strings.Contains(allowedJoin, "--unshare-net") {
		t.Errorf("net=true: --unshare-net present; would block host-side egress\nargs: %s", allowedJoin)
	}
}

// TestBwrapArgs_FSWriteAndRead verifies additional FS.Write paths are added
// as `--bind` and FS.Read paths as `--ro-bind-try`.
func TestBwrapArgs_FSWriteAndRead(t *testing.T) {
	p := Profile{
		ID: "t",
		FS: FSSpec{
			Write: []string{"/var/extra-writable"},
			Read:  []string{"/opt/extra-readable"},
		},
		Net: true,
	}
	args, err := BuildBwrapArgs(p, t.TempDir())
	if err != nil {
		t.Fatalf("BuildBwrapArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--bind /var/extra-writable /var/extra-writable") {
		t.Errorf("expected --bind for extra Write path\nargs: %s", joined)
	}
	if !strings.Contains(joined, "--ro-bind-try /opt/extra-readable /opt/extra-readable") {
		t.Errorf("expected --ro-bind-try for extra Read path\nargs: %s", joined)
	}
}

// TestExpandPathLinux_TildeExpansion ensures that only a leading "~" or "~/"
// is treated as the home directory — a tilde mid-path (e.g. "/cache/foo~2")
// must not be corrupted. Regression test for the strings.ReplaceAll bug.
func TestExpandPathLinux_TildeExpansion(t *testing.T) {
	home := "/home/testuser"
	cases := []struct {
		raw  string
		want string
	}{
		{"~", home},
		{"~/foo", home + "/foo"},
		{"~/foo/bar", home + "/foo/bar"},
		{"/cache/foo~2", "/cache/foo~2"},       // mid-path ~ must not expand
		{"/var/tmp~backup", "/var/tmp~backup"}, // same
		{"${HOME}/baz", home + "/baz"},
		{"/explicit/path", "/explicit/path"},
		{"workspace", "/ws"},
	}
	for _, tc := range cases {
		got := expandPathLinux(tc.raw, "/ws", home)
		if got != tc.want {
			t.Errorf("expandPathLinux(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestApply_ReturnsCleanup is a smoke test that Apply returns a non-nil
// cleanup function on supported platforms (or an error if bwrap is absent).
func TestApply_ReturnsCleanup(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not installed")
	}
	cmd := exec.Command("/bin/true")
	cleanup, err := Apply(cmd, Profile{ID: "t", Net: false}, t.TempDir())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if cleanup == nil {
		t.Fatal("Apply returned nil cleanup")
	}
	cleanup()
}

func TestBwrapArgs_AllowLoopbackHelperBind(t *testing.T) {
	helperPath := "/tmp/go-sandbox-helper"
	args, err := buildBwrapArgs(Profile{ID: "t", Net: false, AllowLoopback: true}, t.TempDir(), helperPath)
	if err != nil {
		t.Fatalf("buildBwrapArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--ro-bind "+helperPath+" "+helperPath) {
		t.Fatalf("expected helper bind for loopback trampoline\nargs: %s", joined)
	}
	if !strings.Contains(joined, "--unshare-net") {
		t.Fatalf("expected loopback-only mode to keep --unshare-net\nargs: %s", joined)
	}
}

func TestBwrapArgs_AllowLoopbackNoOpWhenNetTrue(t *testing.T) {
	args, err := BuildBwrapArgs(Profile{ID: "t", Net: true, AllowLoopback: true}, t.TempDir())
	if err != nil {
		t.Fatalf("BuildBwrapArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--unshare-net") {
		t.Fatalf("net=true should remain host-net even when AllowLoopback is set\nargs: %s", joined)
	}
}
