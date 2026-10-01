package sandbox_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hollis-labs/go-sandbox/sandbox"
)

// CW-20261001-0057. A symlink inside a root whose target does not exist yet
// must be judged by where it points. filepath.EvalSymlinks reports not-exist
// for a dangling link, and a best-effort resolver that then falls back to
// the link's lexical path returns "root/link" as if it were inside the root;
// anything that later creates that path writes through the link to wherever
// it points. nanite#352 proved this on Nanite's copy of pathsafe.

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func TestResolveAccessPolicy_DanglingSymlinkEscapeIsRejected(t *testing.T) {
	cases := []struct {
		name     string
		relative string
		plant    func(t *testing.T, r roots)
	}{
		{
			name:     "leaf link to a missing file outside",
			relative: "link",
			plant: func(t *testing.T, r roots) {
				symlink(t, filepath.Join(r.base, "lib", "planted"), filepath.Join(r.project, "link"))
			},
		},
		{
			name:     "leaf link to a missing directory outside",
			relative: "link",
			plant: func(t *testing.T, r roots) {
				symlink(t, filepath.Join(r.base, "nowhere", "planted"), filepath.Join(r.project, "link"))
			},
		},
		{
			name:     "nested link",
			relative: "sub/dir/link",
			plant: func(t *testing.T, r roots) {
				symlink(t, filepath.Join(r.base, "lib", "planted"), filepath.Join(r.project, "sub", "dir", "link"))
			},
		},
		{
			name:     "relative target climbing out",
			relative: "link",
			plant: func(t *testing.T, r roots) {
				symlink(t, filepath.Join("..", "lib", "planted"), filepath.Join(r.project, "link"))
			},
		},
		{
			name:     "chain of dangling links",
			relative: "first",
			plant: func(t *testing.T, r roots) {
				symlink(t, "second", filepath.Join(r.project, "first"))
				symlink(t, filepath.Join(r.base, "lib", "planted"), filepath.Join(r.project, "second"))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := makeRoots(t)
			tc.plant(t, r)
			for _, kind := range []string{"read", "write", "deny"} {
				ref := []sandbox.PathRef{{Root: sandbox.ProjectRoot, Relative: tc.relative}}
				fs := sandbox.FilesystemAccess{}
				switch kind {
				case "read":
					fs.Read = ref
				case "write":
					fs.Write = ref
				case "deny":
					fs.Deny = ref
				}
				got, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
					ID:    "dangling",
					Roots: sandbox.Roots{Project: r.project},
					FS:    fs,
				})
				if err == nil {
					t.Fatalf("%s ref %q resolved to %+v, want an escape error", kind, tc.relative, got.FS)
				}
				if !strings.Contains(err.Error(), "escapes root") {
					t.Fatalf("%s ref %q: err = %v, want an escape error", kind, tc.relative, err)
				}
			}
		})
	}
}

// A dangling link that stays inside the root is still allowed, and resolves
// to its target.
func TestResolveAccessPolicy_DanglingSymlinkInsideRootResolvesToTarget(t *testing.T) {
	r := makeRoots(t)
	symlink(t, filepath.Join(r.project, "out", "file"), filepath.Join(r.project, "link"))
	got, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:    "dangling-inside",
		Roots: sandbox.Roots{Project: r.project},
		FS:    sandbox.FilesystemAccess{Write: []sandbox.PathRef{{Root: sandbox.ProjectRoot, Relative: "link"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	realProject, err := filepath.EvalSymlinks(r.project)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.FS.Write) != 1 || got.FS.Write[0].Path != filepath.Join(realProject, "out", "file") {
		t.Fatalf("write grants = %+v, want the link's target under the project", got.FS.Write)
	}
}

// AccessFor is the policy's own decision helper. A dangling link inside a
// writable root must be judged by its target: one pointing outside every
// grant has no grant, and one pointing into a denied subtree is denied.
func TestAccessFor_DanglingSymlinkIsJudgedByItsTarget(t *testing.T) {
	r := makeRoots(t)
	got, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:    "access-for-dangling",
		Roots: sandbox.Roots{Project: r.project},
		FS: sandbox.FilesystemAccess{
			Write: []sandbox.PathRef{{Root: sandbox.ProjectRoot}},
			Deny:  []sandbox.PathRef{{Root: sandbox.ProjectRoot, Relative: "secrets"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	outLink := filepath.Join(r.project, "out-link")
	symlink(t, filepath.Join(r.base, "lib", "planted"), outLink)
	denyLink := filepath.Join(r.project, "deny-link")
	symlink(t, filepath.Join(r.project, "secrets", "planted"), denyLink)

	if d := got.AccessFor(outLink); d != sandbox.AccessNoGrant {
		t.Errorf("AccessFor(link to outside) = %v, want %v", d, sandbox.AccessNoGrant)
	}
	if d := got.AccessFor(denyLink); d != sandbox.AccessDenied {
		t.Errorf("AccessFor(link into denied subtree) = %v, want %v", d, sandbox.AccessDenied)
	}
	// Control: an ordinary new file in the project is still writable.
	if d := got.AccessFor(filepath.Join(r.project, "new.txt")); d != sandbox.AccessReadWrite {
		t.Errorf("AccessFor(new file) = %v, want %v", d, sandbox.AccessReadWrite)
	}
}
