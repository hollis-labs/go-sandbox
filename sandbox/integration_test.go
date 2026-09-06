//go:build darwin || linux

package sandbox_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

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

func TestAllowLoopback_LoopbackReachable(t *testing.T) {
	requireSandboxTool(t)

	workspace := t.TempDir()

	p := sandbox.Profile{
		ID:            "allow-loopback-v4",
		Net:           false,
		AllowLoopback: true,
		Subprocess:    true,
	}

	cmdArgs := []string{"http-get", "http://127.0.0.1:0"}
	if runtime.GOOS == "linux" {
		cmdArgs = []string{"self-http-roundtrip", "tcp4", "127.0.0.1:0"}
	} else {
		listener := newHTTPListener(t, "tcp4", "127.0.0.1:0")
		cmdArgs = []string{"http-get", "http://" + listener.Addr().String()}
	}

	cmd := helperCommand(t, cmdArgs...)
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("loopback GET failed: %v\noutput:\n%s", err, out)
	}
}

func TestLoopbackForward_Linux_HostLoopbackReachable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only loopback forward test")
	}
	requireSandboxTool(t)

	listener := newHTTPListener(t, "tcp4", "127.0.0.1:0")
	port := listener.Addr().(*net.TCPAddr).Port
	workspace := t.TempDir()

	p := sandbox.Profile{
		ID:                   "host-loopback-forward",
		Net:                  false,
		LoopbackForwardPorts: []int{port},
		Subprocess:           true,
	}

	cmd := helperCommand(t, "http-get", "http://127.0.0.1:"+fmt.Sprint(port))
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("forwarded host loopback GET failed: %v\noutput:\n%s", err, out)
	}
}

func TestLoopbackForward_Linux_NonForwardedHostLoopbackBlocked(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only loopback forward test")
	}
	requireSandboxTool(t)

	listener := newHTTPListener(t, "tcp4", "127.0.0.1:0")
	port := listener.Addr().(*net.TCPAddr).Port
	workspace := t.TempDir()

	p := sandbox.Profile{
		ID:         "host-loopback-not-forwarded",
		Net:        false,
		Subprocess: true,
	}

	cmd := helperCommand(t, "http-get", "http://127.0.0.1:"+fmt.Sprint(port))
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("expected non-forwarded host loopback GET to fail, but it succeeded\noutput:\n%s", out)
	}
}

func TestAllowLoopback_NonLoopbackBlocked(t *testing.T) {
	requireSandboxTool(t)
	requireHostCanDial(t, "1.1.1.1:443")

	workspace := t.TempDir()
	p := sandbox.Profile{
		ID:            "allow-loopback-only",
		Net:           false,
		AllowLoopback: true,
		Subprocess:    true,
	}

	cmd := helperCommand(t, "tcp-dial", "1.1.1.1:443")
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("expected non-loopback dial to fail, but it succeeded\noutput:\n%s", out)
	}
}

func TestAllowLoopback_IPv6LoopbackReachable(t *testing.T) {
	requireSandboxTool(t)
	if runtime.GOOS == "linux" && !supportsIPv6Loopback() {
		t.Skip("::1 loopback is not available on this host")
	}

	workspace := t.TempDir()
	p := sandbox.Profile{
		ID:            "allow-loopback-v6",
		Net:           false,
		AllowLoopback: true,
		Subprocess:    true,
	}

	cmdArgs := []string{"http-get", "http://[::1]:0"}
	if runtime.GOOS == "linux" {
		cmdArgs = []string{"self-http-roundtrip", "tcp6", "[::1]:0"}
	} else {
		listener := newHTTPListener(t, "tcp6", "[::1]:0")
		cmdArgs = []string{"http-get", "http://" + listener.Addr().String()}
	}

	cmd := helperCommand(t, cmdArgs...)
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("IPv6 loopback GET failed: %v\noutput:\n%s", err, out)
	}
}

func TestAllowLoopback_NoOpWhenNetTrue(t *testing.T) {
	requireSandboxTool(t)

	workspace := t.TempDir()
	p := sandbox.Profile{
		ID:                   "allow-loopback-noop",
		Net:                  true,
		AllowLoopback:        true,
		LoopbackForwardPorts: []int{4317},
		Subprocess:           true,
	}

	cmd := helperCommand(t, "exit-0")
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("expected profile to apply cleanly when net=true and allow_loopback=true: %v\noutput:\n%s", err, out)
	}
}

func TestAllowLoopback_Linux_NamespaceStillIsolated(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only namespace test")
	}
	requireSandboxTool(t)

	workspace := t.TempDir()
	p := sandbox.Profile{
		ID:            "allow-loopback-linux-interfaces",
		Net:           false,
		AllowLoopback: true,
		Subprocess:    true,
	}

	cmd := helperCommand(t, "list-interfaces")
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list interfaces: %v\noutput:\n%s", err, out)
	}

	names := strings.Fields(string(out))
	if len(names) != 1 || names[0] != "lo" {
		t.Fatalf("expected isolated netns to expose only lo, got %q", strings.Join(names, " "))
	}
}

func TestApplyResolvedDarwin_FilesystemAllowlist(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only resolved seatbelt test")
	}
	requireSandboxTool(t)

	base, err := os.MkdirTemp("/tmp", "go-sandbox m09 ")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(base)

	projectReal := filepath.Join(base, "project real")
	projectLink := filepath.Join(base, "project link")
	boot := filepath.Join(base, "boot outside project")
	state := filepath.Join(base, "provider state")
	scratch := filepath.Join(base, "private scratch")
	sibling := filepath.Join(base, "unlisted sibling")
	cwd := filepath.Join(projectReal, "subdir")
	for _, path := range []string{
		filepath.Join(projectReal, "secrets"),
		boot,
		state,
		scratch,
		sibling,
		cwd,
	} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.Symlink(projectReal, projectLink); err != nil {
		t.Fatalf("symlink project root: %v", err)
	}
	writeFixture(t, filepath.Join(projectReal, "approved.txt"), "project ok")
	writeFixture(t, filepath.Join(projectReal, "secrets", "token.txt"), "secret")
	writeFixture(t, filepath.Join(boot, "boot.txt"), "boot ok")
	writeFixture(t, filepath.Join(sibling, "sibling.txt"), "sibling")

	script := filepath.Join(boot, "probe.sh")
	writeFixture(t, script, fsProbeScript([]string{
		"read-ok", filepath.Join(projectLink, "approved.txt"),
		"write-ok", filepath.Join(projectLink, "created via symlink.txt"),
		"read-ok", canonicalAliasPath(filepath.Join(boot, "boot.txt")),
		"write-fail", canonicalAliasPath(filepath.Join(boot, "blocked write.txt")),
		"write-ok", filepath.Join(state, "cache.txt"),
		"write-ok", filepath.Join(scratch, "scratch.txt"),
		"read-fail", filepath.Join(sibling, "sibling.txt"),
		"write-fail", filepath.Join(sibling, "blocked.txt"),
		"read-fail", filepath.Join(projectLink, "secrets", "token.txt"),
		"write-fail", filepath.Join(projectLink, "secrets", "blocked.txt"),
	}))
	policy, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:   "m09-darwin-fs",
		Mode: sandbox.ConfinementRequired,
		Roots: sandbox.Roots{
			Project: projectLink,
			Boot:    boot,
			State:   state,
			Scratch: scratch,
			CWD:     cwd,
		},
		FS: sandbox.FilesystemAccess{
			Read:  []sandbox.PathRef{{Root: sandbox.BootRoot}},
			Write: []sandbox.PathRef{{Root: sandbox.ProjectRoot}},
			Deny:  []sandbox.PathRef{{Root: sandbox.ProjectRoot, Relative: "secrets"}},
		},
		Runtime:       sandbox.RuntimeAccess{Executable: sandbox.PathRef{Path: "/bin/sh"}},
		ProviderState: sandbox.ProviderStateAccess{Write: []sandbox.PathRef{{Root: sandbox.StateRoot}}},
		Scratch:       sandbox.ScratchAccess{Writable: true},
		Network:       sandbox.NetworkAccess{Mode: sandbox.NetworkDeny},
		Subprocess:    sandbox.SubprocessAllow,
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}

	cmd := exec.Command("/bin/sh", script)
	cmd.Dir = cwd

	outcome, cleanup, err := sandbox.ApplyResolved(cmd, policy)
	if err != nil {
		t.Fatalf("ApplyResolved: outcome=%#v err=%v", outcome, err)
	}
	defer cleanup()
	if outcome.State != sandbox.EnforcementApplied || !outcome.Enforced || outcome.Backend != sandbox.BackendDarwinSeatbelt {
		t.Fatalf("ApplyResolved outcome = %#v", outcome)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("resolved filesystem policy was not enforced as expected: %v\noutput:\n%s", err, out)
	}
}

func TestApplyResolvedDarwin_SubprocessDenyFailsExplicitly(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only resolved seatbelt test")
	}

	project := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	policy, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:         "m09-darwin-subprocess",
		Mode:       sandbox.ConfinementRequired,
		Roots:      sandbox.Roots{Project: project},
		Runtime:    sandbox.RuntimeAccess{Executable: sandbox.PathRef{Path: exe}},
		Network:    sandbox.NetworkAccess{Mode: sandbox.NetworkDeny},
		Subprocess: sandbox.SubprocessDeny,
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}

	cmd := helperCommand(t, "spawn-sh-denied")
	cmd.Dir = project
	outcome, cleanup, err := sandbox.ApplyResolved(cmd, policy)
	if err == nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatalf("ApplyResolved unexpectedly applied subprocess deny: %#v", outcome)
	}
	if outcome.State != sandbox.EnforcementUnsupported || !slices.Contains(outcome.Unsupported, sandbox.CapSubprocessDeny) {
		t.Fatalf("ApplyResolved outcome = %#v, want unsupported subprocess-deny", outcome)
	}
}

func TestApplyResolvedDarwin_LoopbackForwardFailsExplicitly(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only resolved seatbelt test")
	}

	project := t.TempDir()
	policy, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:    "m09-darwin-loopback-forward",
		Mode:  sandbox.ConfinementRequired,
		Roots: sandbox.Roots{Project: project},
		Network: sandbox.NetworkAccess{
			Mode:          sandbox.NetworkLoopback,
			LoopbackPorts: []int{4317},
		},
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}
	cmd := helperCommand(t, "exit-0")
	outcome, cleanup, err := sandbox.ApplyResolved(cmd, policy)
	if err == nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatalf("ApplyResolved unexpectedly allowed unsupported loopback forwarding: %#v", outcome)
	}
	if outcome.State != sandbox.EnforcementUnsupported || !slices.Contains(outcome.Unsupported, sandbox.CapLoopbackForward) {
		t.Fatalf("ApplyResolved outcome = %#v, want unsupported loopback-forward", outcome)
	}
}

func TestApplyResolvedDarwin_NetworkDenied(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only resolved seatbelt test")
	}
	requireSandboxTool(t)
	requireHostCanDial(t, "1.1.1.1:443")

	project := t.TempDir()
	policy, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:         "m09-darwin-network-deny",
		Mode:       sandbox.ConfinementRequired,
		Roots:      sandbox.Roots{Project: project},
		Runtime:    sandbox.RuntimeAccess{Executable: sandbox.PathRef{Path: "/usr/bin/nc"}},
		Network:    sandbox.NetworkAccess{Mode: sandbox.NetworkDeny},
		Subprocess: sandbox.SubprocessAllow,
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}

	cmd := exec.Command("/usr/bin/nc", "-G", "1", "-z", "1.1.1.1", "443")
	cmd.Dir = project
	outcome, cleanup, err := sandbox.ApplyResolved(cmd, policy)
	if err != nil {
		t.Fatalf("ApplyResolved: outcome=%#v err=%v", outcome, err)
	}
	defer cleanup()
	if outcome.State != sandbox.EnforcementApplied || !outcome.Enforced {
		t.Fatalf("ApplyResolved outcome = %#v", outcome)
	}
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("expected network-denied command to fail, but it succeeded\noutput:\n%s", out)
	}
}

func TestApplyResolvedLinux_NetworkDenied(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only resolved bwrap test")
	}
	requireSandboxTool(t)
	requireHostCanDial(t, "1.1.1.1:443")

	project := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	policy, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:         "m10-linux-network-deny",
		Mode:       sandbox.ConfinementRequired,
		Roots:      sandbox.Roots{Project: project},
		Runtime:    sandbox.RuntimeAccess{Executable: sandbox.PathRef{Path: exe}},
		Network:    sandbox.NetworkAccess{Mode: sandbox.NetworkDeny},
		Subprocess: sandbox.SubprocessAllow,
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}
	cmd := helperCommand(t, "tcp-dial", "1.1.1.1:443")
	cmd.Dir = project
	outcome, cleanup, err := sandbox.ApplyResolved(cmd, policy)
	if err != nil {
		t.Fatalf("ApplyResolved: outcome=%#v err=%v", outcome, err)
	}
	defer cleanup()
	if outcome.State != sandbox.EnforcementApplied || !outcome.Enforced {
		t.Fatalf("ApplyResolved outcome = %#v", outcome)
	}
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("expected network-denied command to fail, but it succeeded\noutput:\n%s", out)
	}
}

func TestApplyResolvedLinux_LoopbackAndForwarding(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only resolved bwrap test")
	}
	requireSandboxTool(t)

	listener := newHTTPListener(t, "tcp4", "127.0.0.1:0")
	port := listener.Addr().(*net.TCPAddr).Port
	project := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	policy, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:      "m10-linux-loopback-forward",
		Mode:    sandbox.ConfinementRequired,
		Roots:   sandbox.Roots{Project: project},
		Runtime: sandbox.RuntimeAccess{Executable: sandbox.PathRef{Path: exe}},
		Network: sandbox.NetworkAccess{
			Mode:          sandbox.NetworkLoopback,
			LoopbackPorts: []int{port},
		},
		Subprocess: sandbox.SubprocessAllow,
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}
	cmd := helperCommand(t, "http-get", "http://127.0.0.1:"+fmt.Sprint(port))
	cmd.Dir = project
	outcome, cleanup, err := sandbox.ApplyResolved(cmd, policy)
	if err != nil {
		t.Fatalf("ApplyResolved: outcome=%#v err=%v", outcome, err)
	}
	defer cleanup()
	if outcome.State != sandbox.EnforcementApplied || !outcome.Enforced {
		t.Fatalf("ApplyResolved outcome = %#v", outcome)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("forwarded host loopback GET failed: %v\noutput:\n%s", err, out)
	}
}

func TestSandboxHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SANDBOX_HELPER_PROCESS") != "1" {
		return
	}

	sep := 0
	for sep < len(os.Args) && os.Args[sep] != "--" {
		sep++
	}
	if sep+1 >= len(os.Args) {
		fmt.Fprintln(os.Stderr, "missing helper command")
		os.Exit(2)
	}

	switch os.Args[sep+1] {
	case "exit-0":
		os.Exit(0)
	case "http-get":
		if sep+2 >= len(os.Args) {
			fmt.Fprintln(os.Stderr, "missing URL")
			os.Exit(2)
		}
		doHTTPGet(os.Args[sep+2])
	case "tcp-dial":
		if sep+2 >= len(os.Args) {
			fmt.Fprintln(os.Stderr, "missing address")
			os.Exit(2)
		}
		doTCPDial(os.Args[sep+2])
	case "list-interfaces":
		ifaces, err := net.Interfaces()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, iface := range ifaces {
			fmt.Println(iface.Name)
		}
		os.Exit(0)
	case "self-http-roundtrip":
		if sep+3 >= len(os.Args) {
			fmt.Fprintln(os.Stderr, "missing network/address")
			os.Exit(2)
		}
		doSelfHTTPRoundTrip(os.Args[sep+2], os.Args[sep+3])
	case "fs-policy":
		doFSPolicyChecks(os.Args[sep+2:])
	case "spawn-sh-denied":
		if err := exec.Command("/bin/sh", "-c", "exit 0").Run(); err == nil {
			fmt.Fprintln(os.Stderr, "subprocess unexpectedly succeeded")
			os.Exit(1)
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown helper command %q\n", os.Args[sep+1])
		os.Exit(2)
	}
}

func helperCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmdArgs := append([]string{"-test.run=TestSandboxHelperProcess", "--"}, args...)
	cmd := exec.Command(exe, cmdArgs...)
	cmd.Env = append(os.Environ(), "GO_WANT_SANDBOX_HELPER_PROCESS=1")
	return cmd
}

func doFSPolicyChecks(args []string) {
	if len(args)%2 != 0 {
		fmt.Fprintln(os.Stderr, "fs-policy expects operation/path pairs")
		os.Exit(2)
	}
	for i := 0; i < len(args); i += 2 {
		op, path := args[i], args[i+1]
		switch op {
		case "read-ok":
			if _, err := os.ReadFile(path); err != nil {
				fmt.Fprintf(os.Stderr, "read-ok %s failed: %v\n", path, err)
				os.Exit(1)
			}
		case "read-fail":
			if b, err := os.ReadFile(path); err == nil {
				fmt.Fprintf(os.Stderr, "read-fail %s unexpectedly succeeded: %q\n", path, b)
				os.Exit(1)
			}
		case "write-ok":
			if err := os.WriteFile(path, []byte("ok"), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "write-ok %s failed: %v\n", path, err)
				os.Exit(1)
			}
		case "write-fail":
			if err := os.WriteFile(path, []byte("blocked"), 0o644); err == nil {
				fmt.Fprintf(os.Stderr, "write-fail %s unexpectedly succeeded\n", path)
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "unknown fs-policy op %q\n", op)
			os.Exit(2)
		}
	}
	os.Exit(0)
}

func writeFixture(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}

func fsProbeScript(ops []string) string {
	var b strings.Builder
	b.WriteString("set -u\n")
	b.WriteString("read_ok() { while IFS= read -r _; do break; done < \"$1\"; }\n")
	b.WriteString("read_fail() { if while IFS= read -r _; do break; done < \"$1\"; then echo \"read unexpectedly succeeded: $1\" >&2; exit 1; fi; }\n")
	b.WriteString("write_ok() { : > \"$1\"; }\n")
	b.WriteString("write_fail() { if { : > \"$1\"; } 2>/dev/null; then echo \"write unexpectedly succeeded: $1\" >&2; exit 1; fi; }\n")
	for i := 0; i < len(ops); i += 2 {
		b.WriteString(strings.ReplaceAll(ops[i], "-", "_"))
		b.WriteString(" ")
		b.WriteString(shellQuote(ops[i+1]))
		b.WriteString("\n")
	}
	return b.String()
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func canonicalAliasPath(path string) string {
	path = filepath.Clean(path)
	const privateTmp = "/private/tmp"
	if path == privateTmp {
		return "/tmp"
	}
	if strings.HasPrefix(path, privateTmp+"/") {
		return "/tmp/" + strings.TrimPrefix(path, privateTmp+"/")
	}
	if path == "/tmp" {
		return privateTmp
	}
	if strings.HasPrefix(path, "/tmp/") {
		return privateTmp + "/" + strings.TrimPrefix(path, "/tmp/")
	}
	return path
}

func newHTTPListener(t *testing.T, network, addr string) net.Listener {
	t.Helper()

	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("listen on %s %s failed: %v", network, addr, err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}),
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return ln
}

func requireHostCanDial(t *testing.T, addr string) {
	t.Helper()

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("tcp", addr)
	if err != nil {
		t.Skipf("host cannot reach %s: %v", addr, err)
	}
	_ = conn.Close()
}

func supportsIPv6Loopback() bool {
	conn, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func doHTTPGet(url string) {
	client := &http.Client{
		Timeout: 500 * time.Millisecond,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout: 250 * time.Millisecond,
			}).DialContext,
		},
	}
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for {
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				os.Exit(0)
			}
			fmt.Fprintf(os.Stderr, "unexpected status %d\n", resp.StatusCode)
			os.Exit(1)
		}
		lastErr = err
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, lastErr)
			os.Exit(1)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func doTCPDial(addr string) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = conn.Close()
	os.Exit(0)
}

func doSelfHTTPRoundTrip(network, addr string) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer ln.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}),
	}
	defer srv.Close()

	go func() {
		_ = srv.Serve(ln)
	}()

	doHTTPGet("http://" + ln.Addr().String())
}
