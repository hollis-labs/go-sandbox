package sandbox

import (
	"slices"
	"testing"
)

// CW-20261001-0128: DenyUserServiceManager survives every conversion and is
// enforced only where a backend can.

func TestDenyUserServiceManagerCarriedThroughConversions(t *testing.T) {
	ws := t.TempDir()
	policy := PolicyFromProfile(Profile{ID: "p", DenyUserServiceManager: true}, ws)
	if !policy.DenyUserServiceManager {
		t.Fatal("PolicyFromProfile dropped DenyUserServiceManager")
	}
	resolved, err := ResolveAccessPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.DenyUserServiceManager {
		t.Fatal("ResolveAccessPolicy dropped DenyUserServiceManager")
	}
	if !resolved.LegacyProfile().DenyUserServiceManager {
		t.Fatal("LegacyProfile dropped DenyUserServiceManager")
	}
}

func TestDenyUserServiceManagerCapability(t *testing.T) {
	resolved, err := ResolveAccessPolicy(AccessPolicy{ID: "p", Roots: Roots{Project: t.TempDir()}, DenyUserServiceManager: true})
	if err != nil {
		t.Fatal(err)
	}
	linux := AssessEnforcement(resolved, ResolveBackendCapabilities("linux", BackendAuto))
	if linux.State != EnforcementConfigured {
		t.Errorf("linux bwrap: state %s (%v), want configured", linux.State, linux.Diagnostics)
	}
	darwin := AssessEnforcement(resolved, ResolveBackendCapabilities("darwin", BackendAuto))
	if darwin.State != EnforcementUnsupported || !slices.Contains(darwin.Unsupported, CapUserServiceManagerDeny) {
		t.Errorf("darwin seatbelt: state %s, unsupported %v; want it to fail closed on %s", darwin.State, darwin.Unsupported, CapUserServiceManagerDeny)
	}
	resolved.DenyUserServiceManager = false
	if got := AssessEnforcement(resolved, ResolveBackendCapabilities("darwin", BackendAuto)); slices.Contains(got.Unsupported, CapUserServiceManagerDeny) {
		t.Errorf("darwin requires %s when the option is off", CapUserServiceManagerDeny)
	}
}
