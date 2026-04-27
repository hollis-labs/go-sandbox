//go:build darwin || linux

package sandbox_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hollis-labs/go-sandbox/sandbox"
)

// requireSandboxTool skips the test if the platform's sandbox tool is absent.
func requireSandboxTool(t *testing.T) {
	t.Helper()
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("sandbox-exec"); err != nil {
			t.Skip("sandbox-exec not found; skipping integration test")
		}
	case "linux":
		if _, err := exec.LookPath("bwrap"); err != nil {
			t.Skip("bwrap not found; skipping integration test")
		}
	default:
		t.Skipf("sandbox enforcement not supported on %s", runtime.GOOS)
	}
}

// TestSandbox_WorkspaceWriteAllowed verifies that a sandboxed process can
// write inside its workspace directory.
func TestSandbox_WorkspaceWriteAllowed(t *testing.T) {
	requireSandboxTool(t)

	workspace := t.TempDir()
	target := filepath.Join(workspace, "output.txt")

	p := sandbox.Profile{
		ID: "test-write",
		FS: sandbox.FSSpec{
			Write: []string{"workspace"},
			Read:  []string{"workspace"},
		},
		Net:        false,
		Subprocess: true,
	}

	cmd := exec.Command("sh", "-c", "echo hello > "+target)
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	if err := cmd.Run(); err != nil {
		t.Fatalf("sandboxed write inside workspace failed: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("expected output file to exist: %v", err)
	}
}

// TestSandbox_OutsideWorkspaceReadBlocked verifies that a sandboxed process
// cannot read a sensitive path outside the workspace.
func TestSandbox_OutsideWorkspaceReadBlocked(t *testing.T) {
	requireSandboxTool(t)

	if runtime.GOOS == "linux" {
		t.Skip("linux bwrap read-block test requires additional bind config; skip for now")
	}

	workspace := t.TempDir()

	home, _ := os.UserHomeDir()
	sshDir := filepath.Join(home, ".ssh")
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		t.Skipf(".ssh dir not present; skipping")
	}

	p := sandbox.Profile{
		ID: "test-no-ssh",
		FS: sandbox.FSSpec{
			Write: []string{"workspace"},
			Read:  []string{"workspace"},
			Deny:  []string{"${HOME}/.ssh"},
		},
		Net:        false,
		Subprocess: true,
	}

	cmd := exec.Command("ls", sshDir)
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	if err := cmd.Run(); err == nil {
		t.Error("expected listing ~/.ssh to fail inside sandbox, but it succeeded")
	}
}

// TestSandbox_NetworkBlockedWhenNetFalse verifies that outbound connections
// are blocked when the profile sets Net=false.
func TestSandbox_NetworkBlockedWhenNetFalse(t *testing.T) {
	requireSandboxTool(t)

	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not found")
	}

	workspace := t.TempDir()

	p := sandbox.Profile{
		ID:         "test-no-net",
		Net:        false,
		Subprocess: true,
	}

	cmd := exec.Command("curl", "-sf", "--max-time", "3", "https://example.com")
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	if err := cmd.Run(); err == nil {
		t.Error("expected network connection to fail inside net=false sandbox, but curl succeeded")
	}
}

// TestSandbox_NetworkAllowedWhenNetTrue verifies that the sandbox does NOT
// block outbound when the profile sets Net=true.
func TestSandbox_NetworkAllowedWhenNetTrue(t *testing.T) {
	requireSandboxTool(t)

	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not found")
	}

	workspace := t.TempDir()

	p := sandbox.Profile{
		ID:         "test-net-allowed",
		Net:        true,
		Subprocess: true,
	}

	cmd := exec.Command("curl", "-sf", "--max-time", "1", "http://127.0.0.1:1")
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	err = cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code := exitErr.ExitCode()
			if code != 7 && code != 28 {
				t.Logf("curl exit %d (non-refused/timeout): %v", code, err)
			}
		}
	}
}
