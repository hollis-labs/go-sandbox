//go:build darwin

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSeatbeltLiteral_RejectsInjection verifies that workspace paths containing
// bytes with meaning to the TinyScheme profile parser (quotes, parens,
// semicolons, backslashes, control chars) are rejected before a profile is
// emitted. Before the validator existed, `fmt.Fprintf(&b, "(subpath \"%s\")", absDir)`
// let a crafted dir inject arbitrary seatbelt rules — `foo") (allow
// file-write*) (allow network*) ;"` turned the sandbox into a no-op.
//
// This is the regression suite for that injection vector. The validator is
// non-optional — see comment in apply_darwin.go.
func TestSeatbeltLiteral_RejectsInjection(t *testing.T) {
	hostile := []string{
		`/tmp/foo") (allow file-write*) (allow network*) ;"`,
		`/tmp/a"b`,
		`/tmp/a\b`,
		`/tmp/a(b`,
		`/tmp/a)b`,
		`/tmp/a;b`,
		"/tmp/a\x00b",
		"/tmp/a\x1fb",
	}
	for _, ws := range hostile {
		t.Run(ws, func(t *testing.T) {
			_, err := BuildSBPL(Profile{ID: "test"}, ws)
			if err == nil {
				t.Fatalf("BuildSBPL(workspace=%q) accepted hostile path", ws)
			}
		})
	}
}

// TestSeatbeltLiteral_ValidatesFSEntries ensures that every FS.Read/Write/Deny
// entry is also validated, so a profile YAML cannot smuggle injection bytes
// through path lists.
func TestSeatbeltLiteral_ValidatesFSEntries(t *testing.T) {
	cases := []struct {
		name string
		p    Profile
	}{
		{
			name: "deny",
			p: Profile{
				ID:  "t",
				FS:  FSSpec{Deny: []string{`/tmp/evil") (allow network*`}},
				Net: false,
			},
		},
		{
			name: "write",
			p: Profile{
				ID: "t",
				FS: FSSpec{Write: []string{`/tmp/evil") (allow file-write*`}},
			},
		},
		{
			name: "read",
			p: Profile{
				ID: "t",
				FS: FSSpec{Read: []string{`/tmp/evil") (allow file-read*`}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildSBPL(tc.p, "/Users/test/ws"); err == nil {
				t.Fatalf("BuildSBPL accepted hostile FS.%s entry", tc.name)
			}
		})
	}
}

// TestBuildSBPL_AcceptsSafe confirms a well-formed profile emits an SBPL
// that contains the expected workspace allow rule and version header.
func TestBuildSBPL_AcceptsSafe(t *testing.T) {
	p := Profile{
		ID: "ok",
		FS: FSSpec{
			Write: []string{"workspace"},
			Read:  []string{"workspace"},
		},
		Net:        false,
		Subprocess: true,
	}
	sbpl, err := BuildSBPL(p, "/Users/test/ws")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(sbpl), "(version 1)") {
		t.Errorf("SBPL missing version header; got first 80: %q", truncate(sbpl, 80))
	}
	if !strings.Contains(sbpl, `(allow file-write* (subpath "/Users/test/ws"))`) {
		t.Errorf("profile missing expected workspace allow rule:\n%s", sbpl)
	}
	if strings.Contains(sbpl, "(allow file-write*)") {
		t.Errorf("profile unexpectedly contains unscoped file-write allow:\n%s", sbpl)
	}
}

func TestBuildSBPL_DenyNetwork(t *testing.T) {
	p := Profile{ID: "no-net", Net: false, Subprocess: true}
	sbpl, err := BuildSBPL(p, "/tmp/ws/abc")
	if err != nil {
		t.Fatalf("BuildSBPL: %v", err)
	}
	if !strings.Contains(sbpl, "(deny network*)") {
		t.Errorf("expected (deny network*) in SBPL:\n%s", sbpl)
	}
}

func TestBuildSBPL_AllowLoopbackWhileNetFalse(t *testing.T) {
	p := Profile{ID: "loopback", Net: false, AllowLoopback: true, Subprocess: true}
	sbpl, err := BuildSBPL(p, "/tmp/ws/loopback")
	if err != nil {
		t.Fatalf("BuildSBPL: %v", err)
	}
	for _, want := range []string{
		`(allow network-bind (local ip "localhost:*"))`,
		`(allow network-inbound (local ip "localhost:*"))`,
		`(allow network-outbound (remote ip "localhost:*"))`,
		`(deny network*)`,
	} {
		if !strings.Contains(sbpl, want) {
			t.Errorf("expected SBPL to contain %q\n%s", want, sbpl)
		}
	}
}

func TestBuildSBPL_AllowNetwork(t *testing.T) {
	p := Profile{ID: "with-net", Net: true, Subprocess: true}
	sbpl, err := BuildSBPL(p, "/tmp/ws/xyz")
	if err != nil {
		t.Fatalf("BuildSBPL: %v", err)
	}
	if strings.Contains(sbpl, "(deny network*") {
		t.Errorf("expected no network deny for net=true; got:\n%s", sbpl)
	}
}

func TestBuildSBPL_DenySubprocess(t *testing.T) {
	p := Profile{ID: "no-subprocess", Net: true, Subprocess: false}
	sbpl, err := BuildSBPL(p, "/tmp/ws/xyz")
	if err != nil {
		t.Fatalf("BuildSBPL: %v", err)
	}
	if !strings.Contains(sbpl, "(deny process-fork)") {
		t.Errorf("expected (deny process-fork) for subprocess=false; got:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, "(deny process-exec*)") {
		t.Errorf("expected (deny process-exec*) for subprocess=false; got:\n%s", sbpl)
	}
}

func TestBuildSBPL_DenyPaths(t *testing.T) {
	p := Profile{
		ID: "locked",
		FS: FSSpec{
			Deny: []string{"${HOME}/.ssh"},
		},
		Net:        false,
		Subprocess: true,
	}
	sbpl, err := BuildSBPL(p, "/tmp/ws/abc")
	if err != nil {
		t.Fatalf("BuildSBPL: %v", err)
	}
	if !strings.Contains(sbpl, ".ssh") {
		t.Errorf("expected .ssh deny in SBPL:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, "(deny file-read* (subpath ") {
		t.Errorf("expected file-read deny in SBPL:\n%s", sbpl)
	}
}

func TestBuildResolvedSBPL_DefaultDenyAllowlist(t *testing.T) {
	base := t.TempDir()
	project := filepath.Join(base, "project root")
	boot := filepath.Join(base, "boot root")
	state := filepath.Join(base, "state root")
	scratch := filepath.Join(base, "scratch root")
	for _, path := range []string{
		filepath.Join(project, "secrets"),
		boot,
		state,
		scratch,
	} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}

	resolved, err := ResolveAccessPolicy(AccessPolicy{
		ID:    "resolved",
		Mode:  ConfinementRequired,
		Roots: Roots{Project: project, Boot: boot, State: state, Scratch: scratch},
		FS: FilesystemAccess{
			Read:  []PathRef{{Root: BootRoot}},
			Write: []PathRef{{Root: ProjectRoot}},
			Deny:  []PathRef{{Root: ProjectRoot, Relative: "secrets"}},
		},
		Runtime:       RuntimeAccess{Executable: PathRef{Path: "/bin/sh"}},
		ProviderState: ProviderStateAccess{Write: []PathRef{{Root: StateRoot}}},
		Scratch:       ScratchAccess{Writable: true},
		Network:       NetworkAccess{Mode: NetworkLoopback},
		Subprocess:    SubprocessAllow,
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}

	sbpl, err := BuildResolvedSBPL(resolved)
	if err != nil {
		t.Fatalf("BuildResolvedSBPL: %v", err)
	}
	if !strings.Contains(sbpl, "(deny default)") {
		t.Fatalf("resolved SBPL missing default deny:\n%s", sbpl)
	}
	if strings.Contains(sbpl, "(allow default)") {
		t.Fatalf("resolved SBPL contains legacy allow default:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, `(allow file-read* (subpath "`+resolved.Roots.Boot+`"))`) {
		t.Fatalf("resolved SBPL missing boot read allow:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, `(allow file-write* (subpath "`+resolved.Roots.Project+`"))`) {
		t.Fatalf("resolved SBPL missing project write allow:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, `(deny file-read* (subpath "`+filepath.Join(resolved.Roots.Project, "secrets")+`"))`) {
		t.Fatalf("resolved SBPL missing denied descendant:\n%s", sbpl)
	}
	if !strings.Contains(sbpl, "(deny network*)") {
		t.Fatalf("resolved SBPL missing network deny:\n%s", sbpl)
	}
}

func TestBuildResolvedSBPL_RejectsUnsafeResolvedPath(t *testing.T) {
	_, err := BuildResolvedSBPL(ResolvedAccessPolicy{
		ID:   "unsafe",
		Mode: ConfinementRequired,
		FS: ResolvedFilesystemAccess{
			Read: []ResolvedPath{{Kind: AccessRead, Path: `/tmp/evil") (allow default)`}},
		},
		Network:    NetworkAccess{Mode: NetworkDeny},
		Subprocess: SubprocessAllow,
	})
	if err == nil {
		t.Fatal("BuildResolvedSBPL accepted unsafe resolved path")
	}
}

// TestExpandPath_TildeExpansion ensures that only a leading "~" or "~/"
// is treated as the home directory — a tilde mid-path (e.g. "/cache/foo~2")
// must not be corrupted. Regression test for the strings.ReplaceAll bug.
func TestExpandPath_TildeExpansion(t *testing.T) {
	// We can't hard-code os.UserHomeDir() in the test, so test with the
	// SBPL builder: a mid-path tilde must survive into the emitted profile
	// unchanged (it's a valid filesystem byte, not a POSIX unsafe char).
	safe := "/tmp/cache~2"
	sbpl, err := BuildSBPL(Profile{ID: "t", FS: FSSpec{Deny: []string{safe}}}, "/tmp/ws")
	if err != nil {
		t.Fatalf("BuildSBPL: %v", err)
	}
	if !strings.Contains(sbpl, safe) {
		t.Errorf("BuildSBPL corrupted mid-path tilde: want %q in output\n%s", safe, sbpl)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
