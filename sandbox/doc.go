// Package sandbox defines and applies per-process OS-level sandboxes (macOS
// sandbox-exec / Linux bubblewrap) on top of an already-built *exec.Cmd.
//
// New callers should build an AccessPolicy, resolve it with
// ResolveAccessPolicy, and wrap the launch with ApplyResolved. Callers that
// need to preflight can check ResolveBackendCapabilities and AssessEnforcement
// first; ApplyResolved performs the same check before changing the command and
// returns the EnforcementOutcome that should be recorded at launch.
// AccessPolicy names ProjectRoot, BootRoot, StateRoot, ScratchRoot and CWDRoot
// independently so a boot directory or changed process cwd cannot silently
// become the workspace boundary. SourceRead paths are preparation inputs only;
// they are not child execution grants. Deny paths take precedence beneath
// allowed parents. On Linux, resolved bwrap enforcement binds explicit grants
// into a private namespace and reports unavailable bwrap/kernel prerequisites as
// unsupported rather than silently downgrading.
//
// Profile remains supported as the legacy compatibility shape for existing
// Apply callers. PolicyFromProfile marks that conversion as Legacy.DefaultAllow
// because the old shape is selective-deny rather than strict workspace
// confinement. Callers must not report that legacy mode as required allowlist
// confinement unless AssessEnforcement confirms the selected backend has the
// requested capabilities.
package sandbox
