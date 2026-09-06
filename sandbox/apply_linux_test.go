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

func TestApply_AllowLoopbackResolvesBareCommandName(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not installed")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not installed")
	}

	cmd := exec.Command("sh", "-c", "exit 0")
	_, err := Apply(cmd, Profile{ID: "t", Net: false, AllowLoopback: true}, t.TempDir())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	found := false
	for _, arg := range cmd.Args {
		if strings.HasSuffix(arg, "/sh") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected trampoline payload to contain resolved target path, got args: %v", cmd.Args)
	}
}

func TestBwrapArgs_AllowLoopbackHelperBind(t *testing.T) {
	helperPath := "/tmp/go-sandbox-helper"
	args, err := buildBwrapArgs(Profile{ID: "t", Net: false, AllowLoopback: true}, t.TempDir(), helperPath, "")
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

func TestBwrapArgs_LoopbackForwardDirBind(t *testing.T) {
	bridgeDir := t.TempDir()
	args, err := buildBwrapArgs(Profile{ID: "t", Net: false, LoopbackForwardPorts: []int{4317}}, t.TempDir(), "", bridgeDir)
	if err != nil {
		t.Fatalf("buildBwrapArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--ro-bind "+bridgeDir+" "+bridgeDir) {
		t.Fatalf("expected read-only bridge dir bind for loopback forwards\nargs: %s", joined)
	}
}

func TestBwrapArgs_AllowLoopbackNoOpWhenNetTrue(t *testing.T) {
	args, err := BuildBwrapArgs(Profile{ID: "t", Net: true, AllowLoopback: true, LoopbackForwardPorts: []int{4317}}, t.TempDir())
	if err != nil {
		t.Fatalf("BuildBwrapArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--unshare-net") {
		t.Fatalf("net=true should remain host-net even when AllowLoopback is set\nargs: %s", joined)
	}
}

func TestValidateLoopbackPorts(t *testing.T) {
	got, err := validateLoopbackPorts([]int{8123, 4317})
	if err != nil {
		t.Fatalf("validateLoopbackPorts: %v", err)
	}
	if !slices.Equal(got, []int{4317, 8123}) {
		t.Fatalf("validateLoopbackPorts sorted = %v, want [4317 8123]", got)
	}

	if _, err := validateLoopbackPorts([]int{0}); err == nil {
		t.Fatal("expected invalid port error")
	}
	if _, err := validateLoopbackPorts([]int{4317, 4317}); err == nil {
		t.Fatal("expected duplicate port error")
	}
}

func TestBuildResolvedBwrap_DefaultDenyBindingsAndDenyOverlay(t *testing.T) {
	base := t.TempDir()
	project := filepath.Join(base, "project root")
	boot := filepath.Join(base, "boot root")
	state := filepath.Join(base, "provider state")
	scratch := filepath.Join(base, "scratch root")
	cwd := filepath.Join(project, "subdir")
	source := filepath.Join(base, "source only")
	for _, path := range []string{
		filepath.Join(project, "secrets"),
		boot,
		state,
		scratch,
		cwd,
		source,
	} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}

	resolved, err := ResolveAccessPolicy(AccessPolicy{
		ID:    "resolved-linux",
		Mode:  ConfinementRequired,
		Roots: Roots{Project: project, Boot: boot, State: state, Scratch: scratch, CWD: cwd},
		FS: FilesystemAccess{
			Read:       []PathRef{{Root: BootRoot}},
			Write:      []PathRef{{Root: ProjectRoot}},
			Deny:       []PathRef{{Root: ProjectRoot, Relative: "secrets"}},
			SourceRead: []PathRef{{Path: source}},
		},
		Runtime:       RuntimeAccess{Executable: PathRef{Path: "/bin/sh"}},
		ProviderState: ProviderStateAccess{Write: []PathRef{{Root: StateRoot}}},
		Scratch:       ScratchAccess{Writable: true},
		Network:       NetworkAccess{Mode: NetworkDeny},
		Subprocess:    SubprocessAllow,
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}

	args, err := BuildResolvedBwrap(resolved)
	if err != nil {
		t.Fatalf("BuildResolvedBwrap: %v", err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--ro-bind / /") {
		t.Fatalf("resolved bwrap emitted blanket root bind:\n%s", joined)
	}
	for _, seq := range [][]string{
		{"--tmpfs", "/tmp"},
		{"--bind", resolved.Roots.Project, resolved.Roots.Project},
		{"--ro-bind", resolved.Roots.Boot, resolved.Roots.Boot},
		{"--bind", resolved.Roots.State, resolved.Roots.State},
		{"--bind", resolved.Roots.Scratch, resolved.Roots.Scratch},
		{"--perms", "000", "--dir", filepath.Join(resolved.Roots.Project, "secrets")},
		{"--unshare-net"},
		{"--chdir", resolved.Roots.CWD},
	} {
		if !containsArgSequence(args, seq) {
			t.Fatalf("resolved bwrap args missing %v\nargs: %v", seq, args)
		}
	}
	if strings.Contains(joined, source) {
		t.Fatalf("source-read path leaked into child bwrap grants:\n%s", joined)
	}
}

func TestBuildResolvedBwrap_NetworkModes(t *testing.T) {
	project := t.TempDir()
	for _, tc := range []struct {
		name      string
		mode      NetworkMode
		wantNetNS bool
		loopback  []int
	}{
		{name: "deny", mode: NetworkDeny, wantNetNS: true},
		{name: "loopback", mode: NetworkLoopback, wantNetNS: true, loopback: []int{4317}},
		{name: "full", mode: NetworkFull, wantNetNS: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved, err := ResolveAccessPolicy(AccessPolicy{
				ID:      "net-" + tc.name,
				Mode:    ConfinementRequired,
				Roots:   Roots{Project: project},
				Network: NetworkAccess{Mode: tc.mode, LoopbackPorts: tc.loopback},
			})
			if err != nil {
				t.Fatalf("ResolveAccessPolicy: %v", err)
			}
			args, err := BuildResolvedBwrap(resolved)
			if err != nil {
				t.Fatalf("BuildResolvedBwrap: %v", err)
			}
			gotNetNS := containsArgSequence(args, []string{"--unshare-net"})
			if gotNetNS != tc.wantNetNS {
				t.Fatalf("--unshare-net presence = %v, want %v\nargs: %v", gotNetNS, tc.wantNetNS, args)
			}
		})
	}
}

func TestBuildResolvedBwrap_UnsupportedPolicyShapes(t *testing.T) {
	project := t.TempDir()
	fileDeny := filepath.Join(project, "token.txt")
	if err := os.WriteFile(fileDeny, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write denied file: %v", err)
	}

	for _, tc := range []struct {
		name  string
		build func() AccessPolicy
	}{
		{
			name: "subprocess deny",
			build: func() AccessPolicy {
				return AccessPolicy{ID: "subprocess", Mode: ConfinementRequired, Roots: Roots{Project: project}, Network: NetworkAccess{Mode: NetworkDeny}, Subprocess: SubprocessDeny}
			},
		},
		{
			name: "file deny",
			build: func() AccessPolicy {
				return AccessPolicy{
					ID:    "file-deny",
					Mode:  ConfinementRequired,
					Roots: Roots{Project: project},
					FS: FilesystemAccess{
						Write: []PathRef{{Root: ProjectRoot}},
						Deny:  []PathRef{{Path: fileDeny}},
					},
					Network:    NetworkAccess{Mode: NetworkDeny},
					Subprocess: SubprocessAllow,
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolved, err := ResolveAccessPolicy(tc.build())
			if err != nil {
				t.Fatalf("ResolveAccessPolicy: %v", err)
			}
			_, err = BuildResolvedBwrap(resolved)
			if !errors.Is(err, ErrUnsupportedPolicy) {
				t.Fatalf("BuildResolvedBwrap err = %v, want ErrUnsupportedPolicy", err)
			}
		})
	}
}

func TestApplyResolved_BwrapMissingReportsUnsupported(t *testing.T) {
	project := t.TempDir()
	resolved, err := ResolveAccessPolicy(AccessPolicy{
		ID:         "missing-bwrap",
		Mode:       ConfinementRequired,
		Roots:      Roots{Project: project},
		Network:    NetworkAccess{Mode: NetworkDeny},
		Subprocess: SubprocessAllow,
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}

	t.Setenv("PATH", t.TempDir())
	cmd := exec.Command("/bin/true")
	outcome, cleanup, err := ApplyResolved(cmd, resolved)
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("ApplyResolved err = %v, want ErrBackendUnavailable", err)
	}
	if cleanup != nil {
		t.Fatalf("ApplyResolved returned cleanup on unavailable backend")
	}
	if outcome.State != EnforcementUnsupported || outcome.Backend != BackendLinuxBwrap || outcome.Enforced {
		t.Fatalf("ApplyResolved outcome = %#v, want linux unsupported", outcome)
	}
}

func containsArgSequence(args, seq []string) bool {
	if len(seq) == 0 {
		return true
	}
	for i := 0; i+len(seq) <= len(args); i++ {
		if slices.Equal(args[i:i+len(seq)], seq) {
			return true
		}
	}
	return false
}
