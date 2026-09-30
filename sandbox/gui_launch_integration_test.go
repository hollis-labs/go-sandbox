//go:build darwin

package sandbox_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/hollis-labs/go-sandbox/sandbox"
)

// These tests launch real processes under sandbox-exec. They check behavior,
// not just that the profile text compiles: /usr/bin/open must fail to exec,
// an ordinary binary must still run, and a LaunchServices client must be cut
// off from the Mach services that launch GUI apps.

const execDenied = "Operation not permitted"

func runCombined(t *testing.T, cmd *exec.Cmd) (string, int) {
	t.Helper()
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run: %v", err)
		}
	}
	return out.String(), code
}

func guiPolicy(t *testing.T, deny bool) sandbox.ResolvedAccessPolicy {
	t.Helper()
	dir := t.TempDir()
	p, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:            "gui-launch",
		Mode:          sandbox.ConfinementRequired,
		Roots:         sandbox.Roots{Project: dir, CWD: dir},
		DenyGUILaunch: deny,
		Network:       sandbox.NetworkAccess{Mode: sandbox.NetworkFull},
		// The default-deny resolved emitter needs the executables readable.
		FS: sandbox.FilesystemAccess{Read: []sandbox.PathRef{{Path: "/usr/bin"}, {Path: "/bin"}, {Path: "/System"}}},
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}
	return p
}

func TestDenyGUILaunch_LegacyApply(t *testing.T) {
	requireSandboxTool(t)
	for _, tc := range []struct {
		name     string
		deny     bool
		wantExec bool
	}{{"denied", true, false}, {"control-allowed", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("/usr/bin/open", "-h")
			cleanup, err := sandbox.Apply(cmd, sandbox.Profile{ID: "gui", Net: true, Subprocess: true, DenyGUILaunch: tc.deny}, t.TempDir())
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			defer cleanup()
			out, code := runCombined(t, cmd)
			denied := strings.Contains(out, execDenied)
			if tc.wantExec == denied {
				t.Fatalf("exec denied=%v want exec=%v (exit %d): %s", denied, tc.wantExec, code, out)
			}
			if !tc.wantExec && code != 71 {
				t.Errorf("denied exec exit = %d, want 71 (sandbox-exec EX_OSERR)", code)
			}
		})
	}
}

func TestDenyGUILaunch_ResolvedOrdinaryBinaryStillRuns(t *testing.T) {
	requireSandboxTool(t)
	cmd := exec.Command("/usr/bin/true")
	outcome, cleanup, err := sandbox.ApplyResolved(cmd, guiPolicy(t, true))
	if err != nil {
		t.Fatalf("ApplyResolved: %+v %v", outcome, err)
	}
	defer cleanup()
	if !outcome.Enforced {
		t.Fatalf("not enforced: %+v", outcome)
	}
	if out, code := runCombined(t, cmd); code != 0 {
		t.Fatalf("/usr/bin/true under DenyGUILaunch exit %d: %s", code, out)
	}
}

func TestDenyGUILaunch_ResolvedBlocksOpen(t *testing.T) {
	requireSandboxTool(t)
	cmd := exec.Command("/usr/bin/open", "-h")
	outcome, cleanup, err := sandbox.ApplyResolved(cmd, guiPolicy(t, true))
	if err != nil {
		t.Fatalf("ApplyResolved: %+v %v", outcome, err)
	}
	defer cleanup()
	out, code := runCombined(t, cmd)
	if !strings.Contains(out, execDenied) || code != 71 {
		t.Fatalf("open was not blocked (exit %d): %s", code, out)
	}
}

func TestDenyGUILaunch_BlocksLaunchServicesClients(t *testing.T) {
	requireSandboxTool(t)
	lsappinfo, err := exec.LookPath("lsappinfo")
	if err != nil {
		t.Skip("lsappinfo not found")
	}
	// Control: without the knob, a LaunchServices client sees the session's
	// apps. A host with no GUI session returns nothing, so the test is moot.
	ctl := exec.Command(lsappinfo, "list")
	cleanup, err := sandbox.Apply(ctl, sandbox.Profile{ID: "ctl", Net: true, Subprocess: true}, t.TempDir())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()
	if out, _ := runCombined(t, ctl); strings.TrimSpace(out) == "" {
		t.Skip("lsappinfo returns nothing here (no GUI session); cannot distinguish a block")
	}

	blocked := exec.Command(lsappinfo, "list")
	cleanup2, err := sandbox.Apply(blocked, sandbox.Profile{ID: "gui", Net: true, Subprocess: true, DenyGUILaunch: true}, t.TempDir())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup2()
	if out, _ := runCombined(t, blocked); strings.TrimSpace(out) != "" {
		t.Fatalf("LaunchServices still reachable under DenyGUILaunch: %s", out)
	}
}

func TestDenyGUILaunch_CapabilityIsMacOnly(t *testing.T) {
	p := guiPolicy(t, true)
	darwin := sandbox.AssessEnforcement(p, sandbox.ResolveBackendCapabilities("darwin", ""))
	if len(darwin.Unsupported) != 0 {
		t.Errorf("darwin reports unsupported %v", darwin.Unsupported)
	}
	linux := sandbox.AssessEnforcement(p, sandbox.ResolveBackendCapabilities("linux", ""))
	found := false
	for _, c := range linux.Unsupported {
		found = found || c == sandbox.CapGUILaunchDeny
	}
	if !found || linux.State != sandbox.EnforcementUnsupported {
		t.Errorf("linux must refuse a required gui-launch-deny: %+v", linux)
	}
}
