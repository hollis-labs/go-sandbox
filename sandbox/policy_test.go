package sandbox_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hollis-labs/go-sandbox/sandbox"
)

func TestResolveAccessPolicy_Table(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, r roots) sandbox.AccessPolicy
		check func(t *testing.T, r roots, got sandbox.ResolvedAccessPolicy)
	}{
		{
			name: "distinct roots and boot outside project",
			build: func(t *testing.T, r roots) sandbox.AccessPolicy {
				t.Helper()
				return sandbox.AccessPolicy{
					ID:   "distinct-roots",
					Mode: sandbox.ConfinementRequired,
					Roots: sandbox.Roots{
						Project: r.project,
						Boot:    r.boot,
						State:   r.state,
						Scratch: r.scratch,
						CWD:     r.cwd,
					},
					FS: sandbox.FilesystemAccess{
						Read:  []sandbox.PathRef{{Root: sandbox.ProjectRoot}},
						Write: []sandbox.PathRef{{Root: sandbox.BootRoot}},
					},
				}
			},
			check: func(t *testing.T, r roots, got sandbox.ResolvedAccessPolicy) {
				t.Helper()
				if got.Roots.Project != clean(t, r.project) {
					t.Fatalf("project root = %q, want %q", got.Roots.Project, clean(t, r.project))
				}
				if got.Roots.Boot != clean(t, r.boot) {
					t.Fatalf("boot root = %q, want %q", got.Roots.Boot, clean(t, r.boot))
				}
				if got.AccessFor(filepath.Join(r.boot, "AGENTS.md")) != sandbox.AccessReadWrite {
					t.Fatal("boot root write grant was not effective")
				}
				if got.AccessFor(filepath.Join(r.project, "README.md")) != sandbox.AccessReadOnly {
					t.Fatal("project root read grant was not effective")
				}
			},
		},
		{
			name: "cwd changes do not enlarge project access",
			build: func(t *testing.T, r roots) sandbox.AccessPolicy {
				t.Helper()
				t.Chdir(r.base)
				return sandbox.AccessPolicy{
					ID:   "cwd-is-distinct",
					Mode: sandbox.ConfinementRequired,
					Roots: sandbox.Roots{
						Project: r.project,
						Boot:    r.boot,
						CWD:     r.cwd,
					},
					FS: sandbox.FilesystemAccess{
						Read: []sandbox.PathRef{{Root: sandbox.CWDRoot}},
					},
				}
			},
			check: func(t *testing.T, r roots, got sandbox.ResolvedAccessPolicy) {
				t.Helper()
				if got.Roots.CWD != clean(t, r.cwd) {
					t.Fatalf("cwd root = %q, want %q", got.Roots.CWD, clean(t, r.cwd))
				}
				if got.AccessFor(filepath.Join(r.cwd, "local.txt")) != sandbox.AccessReadOnly {
					t.Fatal("cwd read grant was not effective")
				}
				if got.AccessFor(filepath.Join(r.base, "ambient.txt")) != sandbox.AccessNoGrant {
					t.Fatal("process cwd leaked into execution grants")
				}
			},
		},
		{
			name: "source reads are not execution grants",
			build: func(t *testing.T, r roots) sandbox.AccessPolicy {
				t.Helper()
				return sandbox.AccessPolicy{
					ID:   "source-read",
					Mode: sandbox.ConfinementRequired,
					Roots: sandbox.Roots{
						Project: r.project,
						Boot:    r.boot,
					},
					FS: sandbox.FilesystemAccess{
						Read:       []sandbox.PathRef{{Root: sandbox.ProjectRoot}},
						SourceRead: []sandbox.PathRef{{Path: r.source}},
					},
				}
			},
			check: func(t *testing.T, r roots, got sandbox.ResolvedAccessPolicy) {
				t.Helper()
				if len(got.FS.SourceRead) != 1 {
					t.Fatalf("SourceRead len = %d, want 1", len(got.FS.SourceRead))
				}
				if got.AccessFor(filepath.Join(r.source, "profile.yaml")) != sandbox.AccessNoGrant {
					t.Fatal("source-read path became a child execution grant")
				}
			},
		},
		{
			name: "deny precedence under allowed parent",
			build: func(t *testing.T, r roots) sandbox.AccessPolicy {
				t.Helper()
				return sandbox.AccessPolicy{
					ID:   "deny-under-parent",
					Mode: sandbox.ConfinementRequired,
					Roots: sandbox.Roots{
						Project: r.project,
						Boot:    r.boot,
					},
					FS: sandbox.FilesystemAccess{
						Write: []sandbox.PathRef{{Root: sandbox.ProjectRoot}},
						Deny:  []sandbox.PathRef{{Root: sandbox.ProjectRoot, Relative: "secrets"}},
					},
				}
			},
			check: func(t *testing.T, r roots, got sandbox.ResolvedAccessPolicy) {
				t.Helper()
				if got.AccessFor(filepath.Join(r.project, "notes.txt")) != sandbox.AccessReadWrite {
					t.Fatal("allowed parent write grant was not effective")
				}
				if got.AccessFor(filepath.Join(r.project, "secrets", "token")) != sandbox.AccessDenied {
					t.Fatal("deny descendant did not override allowed parent")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := makeRoots(t)
			got, err := sandbox.ResolveAccessPolicy(tc.build(t, r))
			if err != nil {
				t.Fatalf("ResolveAccessPolicy: %v", err)
			}
			tc.check(t, r, got)
		})
	}
}

func TestResolveAccessPolicy_RuntimeProviderScratchAndNetwork(t *testing.T) {
	r := makeRoots(t)
	policy := sandbox.AccessPolicy{
		ID:   "runtime-state-scratch",
		Mode: sandbox.ConfinementRequired,
		Roots: sandbox.Roots{
			Project: r.project,
			Boot:    r.boot,
			State:   r.state,
			Scratch: r.scratch,
			CWD:     r.cwd,
		},
		Runtime: sandbox.RuntimeAccess{
			Executable: sandbox.PathRef{Path: filepath.Join(r.base, "bin", "provider")},
			Read:       []sandbox.PathRef{{Path: filepath.Join(r.base, "lib")}},
		},
		ProviderState: sandbox.ProviderStateAccess{
			Read:  []sandbox.PathRef{{Root: sandbox.StateRoot, Relative: "config"}},
			Write: []sandbox.PathRef{{Root: sandbox.StateRoot, Relative: "cache"}},
		},
		Scratch: sandbox.ScratchAccess{Writable: true},
		Network: sandbox.NetworkAccess{
			Mode:          sandbox.NetworkLoopback,
			LoopbackPorts: []int{8123, 4317},
		},
		Subprocess: sandbox.SubprocessDeny,
	}

	got, err := sandbox.ResolveAccessPolicy(policy)
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}

	if got.AccessFor(filepath.Join(r.base, "bin", "provider")) != sandbox.AccessReadOnly {
		t.Fatal("runtime executable was not readable")
	}
	if got.AccessFor(filepath.Join(r.state, "config", "settings.json")) != sandbox.AccessReadOnly {
		t.Fatal("provider state read grant was not effective")
	}
	if got.AccessFor(filepath.Join(r.state, "cache", "db")) != sandbox.AccessReadWrite {
		t.Fatal("provider state write grant was not effective")
	}
	if got.AccessFor(filepath.Join(r.scratch, "tmp.txt")) != sandbox.AccessReadWrite {
		t.Fatal("scratch write grant was not effective")
	}
	if !slices.Equal(got.Network.LoopbackPorts, []int{4317, 8123}) {
		t.Fatalf("loopback ports = %v, want [4317 8123]", got.Network.LoopbackPorts)
	}

	out := sandbox.AssessEnforcement(got, sandbox.ResolveBackendCapabilities("linux", sandbox.BackendLinuxBwrap))
	if out.State != sandbox.EnforcementUnsupported {
		t.Fatalf("linux outcome state = %s, want unsupported", out.State)
	}
	if !slices.Contains(out.Unsupported, sandbox.CapSubprocessDeny) {
		t.Fatalf("linux unsupported = %v, want subprocess-deny", out.Unsupported)
	}
}

func TestResolveAccessPolicy_RejectsEscapesAndInvalidPorts(t *testing.T) {
	r := makeRoots(t)
	cases := []struct {
		name string
		p    sandbox.AccessPolicy
	}{
		{
			name: "relative escape",
			p: sandbox.AccessPolicy{
				ID:    "escape",
				Roots: sandbox.Roots{Project: r.project},
				FS:    sandbox.FilesystemAccess{Read: []sandbox.PathRef{{Root: sandbox.ProjectRoot, Relative: "../outside"}}},
			},
		},
		{
			name: "missing scratch root",
			p: sandbox.AccessPolicy{
				ID:      "scratch",
				Roots:   sandbox.Roots{Project: r.project},
				Scratch: sandbox.ScratchAccess{Writable: true},
			},
		},
		{
			name: "invalid loopback port",
			p: sandbox.AccessPolicy{
				ID:      "ports",
				Roots:   sandbox.Roots{Project: r.project},
				Network: sandbox.NetworkAccess{Mode: sandbox.NetworkLoopback, LoopbackPorts: []int{0}},
			},
		},
		{
			name: "invalid subprocess mode",
			p: sandbox.AccessPolicy{
				ID:         "subprocess",
				Roots:      sandbox.Roots{Project: r.project},
				Subprocess: sandbox.SubprocessMode("maybe"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sandbox.ResolveAccessPolicy(tc.p); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestAssessEnforcement_RequiredFailClosedDisabledHonestAndCapabilities(t *testing.T) {
	r := makeRoots(t)
	required, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:   "required-fs",
		Mode: sandbox.ConfinementRequired,
		Roots: sandbox.Roots{
			Project: r.project,
			Boot:    r.boot,
		},
		FS:      sandbox.FilesystemAccess{Read: []sandbox.PathRef{{Root: sandbox.ProjectRoot}}},
		Network: sandbox.NetworkAccess{Mode: sandbox.NetworkDeny},
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy required: %v", err)
	}

	darwin := sandbox.AssessEnforcement(required, sandbox.ResolveBackendCapabilities("darwin", sandbox.BackendDarwinSeatbelt))
	if darwin.State != sandbox.EnforcementConfigured {
		t.Fatalf("darwin state = %s, want configured", darwin.State)
	}

	unsupported := sandbox.AssessEnforcement(required, sandbox.ResolveBackendCapabilities("plan9", sandbox.BackendAuto))
	if unsupported.State != sandbox.EnforcementUnsupported || unsupported.Backend != sandbox.BackendNone {
		t.Fatalf("unsupported goos outcome = %#v", unsupported)
	}

	disabled, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:    "disabled",
		Mode:  sandbox.ConfinementDisabled,
		Roots: sandbox.Roots{Project: r.project},
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy disabled: %v", err)
	}
	disabledOut := sandbox.AssessEnforcement(disabled, sandbox.ResolveBackendCapabilities("darwin", sandbox.BackendDarwinSeatbelt))
	if disabledOut.State != sandbox.EnforcementDisabled || !disabledOut.Disabled || disabledOut.Enforced {
		t.Fatalf("disabled outcome = %#v", disabledOut)
	}

	emptyRequired, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:      "empty-required",
		Mode:    sandbox.ConfinementRequired,
		Roots:   sandbox.Roots{Project: r.project},
		Network: sandbox.NetworkAccess{Mode: sandbox.NetworkFull},
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy empty required: %v", err)
	}
	emptyOut := sandbox.AssessEnforcement(emptyRequired, sandbox.ResolveBackendCapabilities("darwin", sandbox.BackendDarwinSeatbelt))
	if emptyOut.State != sandbox.EnforcementUnsupported || len(emptyOut.Diagnostics) == 0 {
		t.Fatalf("empty required outcome = %#v", emptyOut)
	}

	configured := sandbox.AssessEnforcement(required, sandbox.BackendCapabilities{
		Backend:   sandbox.BackendLinuxBwrap,
		GOOS:      "linux",
		Supported: true,
		Capabilities: []sandbox.Capability{
			sandbox.CapFilesystemAllowlist,
			sandbox.CapNetworkDeny,
		},
	})
	if configured.State != sandbox.EnforcementConfigured || configured.Enforced {
		t.Fatalf("configured outcome = %#v", configured)
	}
	applied := sandbox.AppliedOutcome(configured)
	if applied.State != sandbox.EnforcementApplied || !applied.Enforced {
		t.Fatalf("applied outcome = %#v", applied)
	}

	loopbackForward, err := sandbox.ResolveAccessPolicy(sandbox.AccessPolicy{
		ID:    "darwin-loopback-forward",
		Mode:  sandbox.ConfinementRequired,
		Roots: sandbox.Roots{Project: r.project},
		Network: sandbox.NetworkAccess{
			Mode:          sandbox.NetworkLoopback,
			LoopbackPorts: []int{4317},
		},
	})
	if err != nil {
		t.Fatalf("ResolveAccessPolicy loopback forward: %v", err)
	}
	forwardOut := sandbox.AssessEnforcement(loopbackForward, sandbox.ResolveBackendCapabilities("darwin", sandbox.BackendDarwinSeatbelt))
	if forwardOut.State != sandbox.EnforcementUnsupported {
		t.Fatalf("darwin loopback-forward state = %s, want unsupported", forwardOut.State)
	}
	if !slices.Contains(forwardOut.Unsupported, sandbox.CapLoopbackForward) {
		t.Fatalf("darwin loopback-forward unsupported = %v, want loopback-forward", forwardOut.Unsupported)
	}
}

func TestPolicyFromProfile_LegacyCompatibility(t *testing.T) {
	r := makeRoots(t)
	legacy := sandbox.Profile{
		ID: "workspace-only",
		FS: sandbox.FSSpec{
			Read:  []string{"workspace"},
			Write: []string{"workspace"},
			Deny:  []string{filepath.Join(r.project, "secrets")},
		},
		Net:                  false,
		AllowLoopback:        true,
		LoopbackForwardPorts: []int{4317},
		Subprocess:           false,
	}

	policy := sandbox.PolicyFromProfile(legacy, r.project)
	got, err := sandbox.ResolveAccessPolicy(policy)
	if err != nil {
		t.Fatalf("ResolveAccessPolicy: %v", err)
	}
	if !got.Legacy.Enabled || !got.Legacy.DefaultAllow {
		t.Fatalf("legacy marker = %#v, want enabled default-allow", got.Legacy)
	}
	if got.Roots.Project != clean(t, r.project) || got.Roots.CWD != clean(t, r.project) {
		t.Fatalf("legacy roots = %#v, want workspace roots", got.Roots)
	}
	if got.AccessFor(filepath.Join(r.project, "file.txt")) != sandbox.AccessReadWrite {
		t.Fatal("legacy workspace read/write did not resolve")
	}
	if got.AccessFor(filepath.Join(r.project, "secrets", "token")) != sandbox.AccessDenied {
		t.Fatal("legacy deny did not take precedence")
	}
	if got.Network.Mode != sandbox.NetworkLoopback || !slices.Equal(got.Network.LoopbackPorts, []int{4317}) {
		t.Fatalf("legacy network = %#v", got.Network)
	}
	if got.Subprocess != sandbox.SubprocessDeny {
		t.Fatalf("legacy subprocess = %s, want deny", got.Subprocess)
	}

	profile := got.LegacyProfile()
	if profile.ID != legacy.ID || profile.Net || !profile.AllowLoopback || profile.Subprocess {
		t.Fatalf("LegacyProfile = %#v", profile)
	}
	if len(profile.FS.Read) == 0 || len(profile.FS.Write) == 0 || len(profile.FS.Deny) == 0 {
		t.Fatalf("LegacyProfile missing fs grants: %#v", profile.FS)
	}
}

func makeRoots(t *testing.T) roots {
	t.Helper()
	base := t.TempDir()
	r := roots{
		base:    base,
		project: filepath.Join(base, "project root"),
		boot:    filepath.Join(base, "boot root"),
		state:   filepath.Join(base, "state root"),
		scratch: filepath.Join(base, "scratch root"),
		cwd:     filepath.Join(base, "cwd root"),
		source:  filepath.Join(base, "source root"),
	}
	for _, path := range []string{
		r.project,
		filepath.Join(r.project, "secrets"),
		r.boot,
		r.state,
		filepath.Join(r.state, "config"),
		filepath.Join(r.state, "cache"),
		r.scratch,
		r.cwd,
		r.source,
		filepath.Join(r.base, "bin"),
		filepath.Join(r.base, "lib"),
	} {
		if err := mkdirAll(path); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	return r
}

type roots struct {
	base    string
	project string
	boot    string
	state   string
	scratch string
	cwd     string
	source  string
}

func clean(t *testing.T, path string) string {
	t.Helper()
	got, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", path, err)
	}
	return got
}

func mkdirAll(path string) error {
	return os.MkdirAll(path, 0o755)
}
