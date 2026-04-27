// Package sandbox applies per-process OS-level sandboxes (macOS sandbox-exec
// / Linux bubblewrap) on top of an already-built *exec.Cmd, driven by a
// declarative Profile.
//
// The Profile shape (FS read/write/deny + net + subprocess gates) comes from
// agent-mux's earlier sandbox package. The macOS and Linux backends and their
// hardening posture (SBPL literal validator, narrowed bwrap --ro-bind set,
// per-invocation tmpfs, namespace unsharing, --die-with-parent, cleanup
// pattern) come from nanite's hardened implementation. See README for the
// extraction lineage and audit-trace pointers.
//
// Posture: default-allow with selective denies. Tightening to default-deny
// requires a well-tested per-OS allowlist and is intentionally left to a
// future sprint. See README for in-scope / out-of-scope details.
package sandbox
