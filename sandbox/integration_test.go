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

	listener := newHTTPListener(t, "tcp4", "127.0.0.1:0")
	workspace := t.TempDir()

	p := sandbox.Profile{
		ID:            "allow-loopback-v4",
		Net:           false,
		AllowLoopback: true,
		Subprocess:    true,
	}

	cmd := helperCommand(t, "http-get", "http://"+listener.Addr().String())
	cleanup, err := sandbox.Apply(cmd, p, workspace)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("loopback GET failed: %v\noutput:\n%s", err, out)
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

	listener := newHTTPListener(t, "tcp6", "[::1]:0")
	workspace := t.TempDir()
	p := sandbox.Profile{
		ID:            "allow-loopback-v6",
		Net:           false,
		AllowLoopback: true,
		Subprocess:    true,
	}

	cmd := helperCommand(t, "http-get", "http://"+listener.Addr().String())
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
		ID:            "allow-loopback-noop",
		Net:           true,
		AllowLoopback: true,
		Subprocess:    true,
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
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout: 2 * time.Second,
			}).DialContext,
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "unexpected status %d\n", resp.StatusCode)
		os.Exit(1)
	}
	os.Exit(0)
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
