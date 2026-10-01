//go:build darwin

package sandbox

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// CW-20260930-0237: write-protected control-plane paths under seatbelt.
// Written and compiled on Linux (GOOS=darwin go vet); they run only on macOS.

func TestBuildSBPL_ProtectDeniesWritesAfterAllows(t *testing.T) {
	ws := "/Users/test/ws"
	state := "/Users/test/ws/.state"
	sbpl, err := BuildSBPL(Profile{ID: "p", FS: FSSpec{Write: []string{"workspace"}, Protect: []string{state}}, Net: true, Subprocess: true}, ws)
	if err != nil {
		t.Fatalf("BuildSBPL: %v", err)
	}
	allow := strings.Index(sbpl, `(allow file-write* (subpath "/Users/test/ws"))`)
	deny := strings.Index(sbpl, `(deny file-write* (subpath "/Users/test/ws/.state"))`)
	if allow < 0 || deny < 0 || deny < allow {
		t.Fatalf("want the protect deny after the workspace write allow:\n%s", sbpl)
	}
	if strings.Contains(sbpl, `(deny file-read* (subpath "/Users/test/ws/.state"))`) {
		t.Errorf("protection must not deny reads:\n%s", sbpl)
	}
	if _, err := BuildSBPL(Profile{ID: "p", FS: FSSpec{Protect: []string{"/tmp/x\")(allow default"}}}, ws); err == nil {
		t.Error("BuildSBPL accepted an unsafe protected path literal")
	}
}

func TestBuildResolvedSBPL_ProtectDeniesWritesAfterAllows(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(project, "state")
	if err := os.Mkdir(state, 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := ResolveAccessPolicy(AccessPolicy{
		ID:      "resolved-protect",
		Roots:   Roots{Project: project},
		FS:      FilesystemAccess{Write: []PathRef{{Root: ProjectRoot}}, Protect: []PathRef{{Path: state}}},
		Network: NetworkAccess{Mode: NetworkFull},
	})
	if err != nil {
		t.Fatal(err)
	}
	sbpl, err := BuildResolvedSBPL(p)
	if err != nil {
		t.Fatalf("BuildResolvedSBPL: %v", err)
	}
	allow := strings.Index(sbpl, `(allow file-write* (subpath "`+project+`"))`)
	deny := strings.Index(sbpl, `(deny file-write* (subpath "`+state+`"))`)
	if allow < 0 || deny < 0 || deny < allow {
		t.Fatalf("want the protect deny after the project write allow:\n%s", sbpl)
	}
}

func TestApplyProtect_SeatbeltBlocksWrites(t *testing.T) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not found")
	}
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(ws, "state")
	if err := os.Mkdir(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "allow.json"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", `echo ok > "$WS/ok" || exit 10; echo pwned > "$STATE/allow.json" 2>/dev/null && exit 11; echo x > "$STATE/new" 2>/dev/null && exit 12; exit 0`)
	cmd.Env = append(os.Environ(), "WS="+ws, "STATE="+state)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cleanup, err := Apply(cmd, Profile{ID: "protect", Net: true, Subprocess: true, FS: FSSpec{Protect: []string{state}}}, ws)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	defer cleanup()
	if err := cmd.Run(); err != nil {
		t.Fatalf("sandboxed script: %v\n%s", err, out.String())
	}
	if got, _ := os.ReadFile(filepath.Join(state, "allow.json")); string(got) != "original" {
		t.Errorf("protected file = %q after the run, want unchanged", got)
	}
}
