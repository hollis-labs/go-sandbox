//go:build darwin || linux

package sandbox_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hollis-labs/go-sandbox/sandbox"
)

func TestApplyResolvedPolicyParity_FilesystemAllowlist(t *testing.T) {
	requireSandboxTool(t)
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("resolved policy parity is not implemented on %s", runtime.GOOS)
	}

	fx := newResolvedPolicyParityFixture(t, "resolved-policy-parity")
	cmd := helperCommand(t, append([]string{"fs-policy"}, fx.ops...)...)
	cmd.Dir = fx.resolved.Roots.CWD

	outcome, cleanup, err := sandbox.ApplyResolved(cmd, fx.resolved)
	if err != nil {
		t.Fatalf("ApplyResolved: outcome=%#v err=%v", outcome, err)
	}
	defer cleanup()
	if outcome.State != sandbox.EnforcementApplied || !outcome.Enforced {
		t.Fatalf("ApplyResolved outcome = %#v, want applied/enforced", outcome)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("resolved filesystem policy was not enforced as expected: %v\noutput:\n%s", err, out)
	}
}

func TestApplyResolvedPolicyParity_NetworkDeny(t *testing.T) {
	requireSandboxTool(t)
	requireHostCanDial(t, "1.1.1.1:443")

	project := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	resolved, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:         "resolved-network-deny",
		Mode:       sandbox.ConfinementRequired,
		Roots:      sandbox.Roots{Project: project, CWD: project},
		Runtime:    sandbox.RuntimeAccess{Executable: sandbox.PathRef{Path: exe}},
		Network:    sandbox.NetworkAccess{Mode: sandbox.NetworkDeny},
		Subprocess: sandbox.SubprocessAllow,
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}

	cmd := helperCommand(t, "tcp-dial", "1.1.1.1:443")
	cmd.Dir = project
	outcome, cleanup, err := sandbox.ApplyResolved(cmd, resolved)
	if err != nil {
		t.Fatalf("ApplyResolved: outcome=%#v err=%v", outcome, err)
	}
	defer cleanup()
	if outcome.State != sandbox.EnforcementApplied || !outcome.Enforced {
		t.Fatalf("ApplyResolved outcome = %#v", outcome)
	}
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("expected resolved network-denied command to fail, but it succeeded\noutput:\n%s", out)
	}
}

type resolvedPolicyParityFixture struct {
	resolved sandbox.ResolvedAccessPolicy
	ops      []string
}

func newResolvedPolicyParityFixture(t *testing.T, id string) resolvedPolicyParityFixture {
	t.Helper()
	base := t.TempDir()
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

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	resolved, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:   id,
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
		Runtime:       sandbox.RuntimeAccess{Executable: sandbox.PathRef{Path: exe}},
		ProviderState: sandbox.ProviderStateAccess{Write: []sandbox.PathRef{{Root: sandbox.StateRoot}}},
		Scratch:       sandbox.ScratchAccess{Writable: true},
		Network:       sandbox.NetworkAccess{Mode: sandbox.NetworkDeny},
		Subprocess:    sandbox.SubprocessAllow,
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}

	return resolvedPolicyParityFixture{
		resolved: resolved,
		ops: []string{
			"read-ok", filepath.Join(resolved.Roots.Project, "approved.txt"),
			"write-ok", filepath.Join(resolved.Roots.Project, "created via resolved root.txt"),
			"read-ok", filepath.Join(resolved.Roots.Boot, "boot.txt"),
			"write-fail", filepath.Join(resolved.Roots.Boot, "blocked write.txt"),
			"write-ok", filepath.Join(resolved.Roots.State, "cache.txt"),
			"write-ok", filepath.Join(resolved.Roots.Scratch, "scratch.txt"),
			"read-fail", filepath.Join(sibling, "sibling.txt"),
			"write-fail", filepath.Join(sibling, "blocked.txt"),
			"read-fail", filepath.Join(resolved.Roots.Project, "secrets", "token.txt"),
			"write-fail", filepath.Join(resolved.Roots.Project, "secrets", "blocked.txt"),
		},
	}
}
