package sandbox_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hollis-labs/go-sandbox/sandbox"
)

func TestLoadProfile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	yaml := `id: workspace-only
description: "Test profile"
fs:
  read:
    - workspace
    - ${HOME}/.config/claude
  write:
    - workspace
  deny:
    - ${HOME}/.ssh
net: false
subprocess: true
`
	path := filepath.Join(dir, "workspace-only.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	p, err := sandbox.LoadProfile(path)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if p.ID != "workspace-only" {
		t.Errorf("ID = %q, want %q", p.ID, "workspace-only")
	}
	if len(p.FS.Read) != 2 {
		t.Errorf("FS.Read len = %d, want 2", len(p.FS.Read))
	}
	if len(p.FS.Write) != 1 || p.FS.Write[0] != "workspace" {
		t.Errorf("FS.Write = %v, want [workspace]", p.FS.Write)
	}
	if len(p.FS.Deny) != 1 {
		t.Errorf("FS.Deny len = %d, want 1", len(p.FS.Deny))
	}
	if p.Net {
		t.Error("Net = true, want false")
	}
	if !p.Subprocess {
		t.Error("Subprocess = false, want true")
	}
}

func TestLoadProfiles_Dir(t *testing.T) {
	dir := t.TempDir()

	for _, content := range []string{
		"id: alpha\nnet: false\nsubprocess: true\n",
		"id: beta\nnet: true\nsubprocess: false\n",
	} {
		id := content[4:9]
		path := filepath.Join(dir, id[:len(id)-1]+".yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	profiles, err := sandbox.LoadProfiles(dir)
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	if len(profiles) != 2 {
		t.Errorf("got %d profiles, want 2", len(profiles))
	}
	if _, ok := profiles["alpha"]; !ok {
		t.Error("alpha not in profiles map")
	}
	if _, ok := profiles["beta"]; !ok {
		t.Error("beta not in profiles map")
	}
}

func TestLoadProfiles_MissingDir(t *testing.T) {
	profiles, err := sandbox.LoadProfiles("/nonexistent/sandbox-profiles")
	if err != nil {
		t.Fatalf("LoadProfiles on missing dir should not error, got: %v", err)
	}
	if len(profiles) != 0 {
		t.Errorf("expected empty map for missing dir, got %d entries", len(profiles))
	}
}

func TestLoadProfile_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(": this is not valid yaml: :\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := sandbox.LoadProfile(path)
	if err == nil {
		t.Error("expected error for malformed YAML, got nil")
	}
}

func TestLoadProfile_MissingID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "noid.yaml")
	if err := os.WriteFile(path, []byte("description: \"no id\"\nnet: false\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := sandbox.LoadProfile(path); err == nil {
		t.Error("expected error for profile without id, got nil")
	}
}
