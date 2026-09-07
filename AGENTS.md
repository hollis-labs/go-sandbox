# go-sandbox

Defines resolved process access policy and applies per-process OS-level
sandboxes on top of an already-built `*exec.Cmd` — macOS `sandbox-exec`
(SBPL/seatbelt) on darwin, `bwrap` (bubblewrap) on linux. It confines a
process the caller constructed; it does not build the command, choose the
binary, or manage network egress (that is `go-egress-proxy`).

## Start Here

- `README.md` shows the resolve-then-apply shape new code should use.
- `sandbox/policy.go` owns `AccessPolicy`, `ResolveAccessPolicy` and the
  confinement modes.
- `sandbox/apply_policy.go` owns `ApplyResolved` and the enforcement outcome.
- `sandbox/apply_darwin.go` builds SBPL; `sandbox/apply_linux.go` builds bwrap
  args.
- `sandbox/apply_resolved_unsupported.go` and `apply_unsupported.go` are the
  honest no-backend paths.
- `sandbox/profile.go` is the legacy `Profile` / `Apply` API kept for
  compatibility.
- `internal/pathsafe/pathsafe.go` owns path-escape rejection.

## Commands

```bash
gofmt -l .
go vet ./...
go test -race -count=1 ./...
```

Backend-specific tests skip on the wrong OS, so a full picture needs a run on
both darwin and linux. There is no CI workflow in this repo.

## Boundaries

`ConfinementRequired` means fail closed: if the selected backend cannot enforce
every requested capability, the child must not start. `ConfinementDisabled` is
an explicit unconfined launch and is represented in the outcome so a caller can
never mistake it for applied enforcement. `AssessEnforcement` reporting honestly
— including reporting that it did nothing — is the whole contract
(`TestAssessEnforcement_RequiredFailClosedDisabledHonestAndCapabilities`), and
a missing `bwrap` reports unsupported rather than silently running unconfined
(`TestApplyResolved_BwrapMissingReportsUnsupported`).

Both backends are default-deny with an explicit allowlist
(`TestBuildResolvedSBPL_DefaultDenyAllowlist`,
`TestBuildResolvedBwrap_DefaultDenyBindingsAndDenyOverlay`). A change that
makes an unlisted path reachable is a sandbox escape, not a convenience.

Policy input is untrusted text that becomes an SBPL program. The seatbelt
literal validator rejects injection and validates every filesystem entry
(`TestSeatbeltLiteral_RejectsInjection`,
`TestSeatbeltLiteral_ValidatesFSEntries`), and resolution rejects path escapes
and invalid ports before anything is built
(`TestResolveAccessPolicy_RejectsEscapesAndInvalidPorts`,
`TestBuildResolvedSBPL_RejectsUnsafeResolvedPath`). Never interpolate a path
into SBPL without going through the validator.

Darwin and linux must reach the same decisions for the same policy —
`TestApplyResolvedPolicyParity_FilesystemAllowlist` and
`TestApplyResolvedPolicyParity_NetworkDeny` are what keep one platform from
quietly becoming more permissive than the other.
