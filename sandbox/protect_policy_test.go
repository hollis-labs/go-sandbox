package sandbox_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hollis-labs/go-sandbox/sandbox"
)

// CW-20260930-0237: write-protected control-plane paths.

func TestAccessForProtect(t *testing.T) {
	project := t.TempDir()
	state := filepath.Join(project, ".state")
	denied := filepath.Join(state, "secret")
	outside := t.TempDir()
	for _, dir := range []string{state, denied} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:    "protect",
		Roots: sandbox.Roots{Project: project},
		FS: sandbox.FilesystemAccess{
			Write:   []sandbox.PathRef{{Root: sandbox.ProjectRoot}},
			Deny:    []sandbox.PathRef{{Path: denied}},
			Protect: []sandbox.PathRef{{Path: state}, {Path: outside}},
		},
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}
	for path, want := range map[string]sandbox.AccessDecision{
		project:                         sandbox.AccessReadWrite,
		state:                           sandbox.AccessReadOnly, // protect overrides the write grant
		filepath.Join(state, "db.json"): sandbox.AccessReadOnly,
		denied:                          sandbox.AccessDenied,  // deny still wins
		outside:                         sandbox.AccessNoGrant, // protection grants nothing
	} {
		if got := p.AccessFor(path); got != want {
			t.Errorf("AccessFor(%s) = %s, want %s", path, got, want)
		}
	}
}

func TestProtectRequiresWriteProtectCapability(t *testing.T) {
	project := t.TempDir()
	p, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:      "protect-cap",
		Roots:   sandbox.Roots{Project: project},
		FS:      sandbox.FilesystemAccess{Write: []sandbox.PathRef{{Root: sandbox.ProjectRoot}}, Protect: []sandbox.PathRef{{Root: sandbox.ProjectRoot, Relative: "."}}},
		Network: sandbox.NetworkAccess{Mode: sandbox.NetworkFull},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"linux", "darwin"} {
		caps := sandbox.ResolveBackendCapabilities(goos, sandbox.BackendAuto)
		if !slices.Contains(caps.Capabilities, sandbox.CapWriteProtect) {
			t.Errorf("%s backend %s does not list %s", goos, caps.Backend, sandbox.CapWriteProtect)
		}
		if out := sandbox.AssessEnforcement(p, caps); out.State != sandbox.EnforcementConfigured {
			t.Errorf("%s: AssessEnforcement = %+v, want configured", goos, out)
		}
	}
	missing := sandbox.BackendCapabilities{Backend: "test", GOOS: "test", Supported: true, Capabilities: []sandbox.Capability{sandbox.CapFilesystemAllowlist}}
	out := sandbox.AssessEnforcement(p, missing)
	if out.State != sandbox.EnforcementUnsupported || !slices.Contains(out.Unsupported, sandbox.CapWriteProtect) {
		t.Errorf("AssessEnforcement without %s = %+v, want unsupported", sandbox.CapWriteProtect, out)
	}
}

func TestWithProtected(t *testing.T) {
	project := t.TempDir()
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	base, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{ID: "base", Roots: sandbox.Roots{Project: project}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := base.WithProtected(link, real, project)
	if err != nil {
		t.Fatalf("WithProtected: %v", err)
	}
	var paths []string
	for _, item := range got.FS.Protect {
		if item.Kind != sandbox.AccessProtect {
			t.Errorf("protected %s has kind %s", item.Path, item.Kind)
		}
		paths = append(paths, item.Path)
	}
	realResolved, _ := filepath.EvalSymlinks(real)
	projectResolved, _ := filepath.EvalSymlinks(project)
	want := []string{realResolved, projectResolved}
	slices.Sort(want)
	if !slices.Equal(paths, want) {
		t.Errorf("Protect = %v, want %v (symlink resolved, duplicates dropped)", paths, want)
	}
	if len(base.FS.Protect) != 0 {
		t.Errorf("WithProtected mutated its receiver: %v", base.FS.Protect)
	}
	if _, err := base.WithProtected("relative/path"); err == nil {
		t.Error("WithProtected(relative) = nil error, want refusal")
	}
}

func TestProtectSurvivesLegacyConversions(t *testing.T) {
	project := t.TempDir()
	protected := filepath.Join(project, "state")
	if err := os.Mkdir(protected, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := sandbox.PolicyFromProfile(sandbox.Profile{ID: "legacy", FS: sandbox.FSSpec{Protect: []string{protected}}}, project)
	if len(policy.FS.Protect) != 1 || policy.FS.Protect[0].Path != protected {
		t.Fatalf("PolicyFromProfile Protect = %+v", policy.FS.Protect)
	}
	resolved, err := sandbox.ResolveAccessPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(protected)
	if got := resolved.LegacyProfile().FS.Protect; !slices.Equal(got, []string{want}) {
		t.Errorf("LegacyProfile Protect = %v, want [%s]", got, want)
	}
}

func TestLoadProfileProtectAndHostFilesystem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	body := "id: control-plane\nhost_filesystem: true\nnet: true\nfs:\n  protect:\n    - /var/lib/app\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := sandbox.LoadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HostFilesystem || !slices.Equal(p.FS.Protect, []string{"/var/lib/app"}) {
		t.Errorf("LoadProfile = %+v, want host_filesystem and fs.protect", p)
	}
}
