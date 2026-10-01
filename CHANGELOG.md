# Changelog

All notable changes to this project will be documented in this file. This
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.5.0 — 2026-10-01

Write-protected control-plane paths (CW-20260930-0237).

### Added

- **`FS.Protect`** on `FilesystemAccess`, `ResolvedFilesystemAccess` (with
  the `AccessProtect` kind) and the legacy `Profile.FS` (yaml `protect`).
  - It lists paths the child must never write, even inside a write grant:
    a host's database, config, catalog or allow-lists. An agent running as
    the operator's uid could otherwise rewrite them to grant itself
    authority.
  - It stays readable where a grant covers it, and grants nothing. `Deny`
    still overrides it.
  - `AccessFor` reports a protected path as read-only, or no-grant when
    nothing covers it.
- **The `write-protect` capability (`CapWriteProtect`)**, provided by linux
  bwrap and darwin seatbelt. `AssessEnforcement` requires it when a
  resolved policy protects anything.
- **`ResolvedAccessPolicy.WithProtected(paths...)`** adds absolute paths to
  an already-resolved policy, canonicalized and deduplicated. This is how a
  host composes its control-plane paths into a policy built elsewhere.
- **`Profile.HostFilesystem`** (yaml `host_filesystem`) is the minimal
  protect-only sandbox for hosts whose agents otherwise run unconfined.
  - On Linux it binds the host filesystem writable with devices
    (`--dev-bind / /`). It shares the pid, ipc and uts namespaces and the
    session, so a PTY keeps its terminal, and it unshares the network only
    when `Net` is false.
  - It refuses `FS.Deny` rather than ignore it.
  - macOS legacy profiles are already default-allow, so it changes nothing
    there.
- **Linux enforcement.** Each protected path that exists and is visible is
  read-only-bound over the writable mounts and under the deny overlays.
  - This applies to legacy `Apply`, `ApplyResolved` and `BuildResolvedBwrap`.
  - Writes, creates, renames, unlinks and mkdir inside it fail with EROFS,
    pinned by tests that run real bwrap.
  - A protected path that does not exist is refused where the child could
    create it, and skipped elsewhere.
- **macOS enforcement.** `BuildSBPL` and `BuildResolvedSBPL` emit
  `(deny file-write* …)` for each protected path after every write allow.
  These were checked by reasoning and by darwin-only tests compiled with
  `GOOS=darwin`; they have not run on a Mac.

### Not covered

- A read-only mount does not stop `connect(2)` on a Unix socket. Use `Deny`
  for a control socket.
- A path reached through a symlink in an agent-writable directory can be
  re-pointed. Protect the real path.

## v0.4.1 — 2026-10-01

Security fix (CW-20261001-0057).

- **Security: a dangling symlink inside a root no longer escapes it.**
  - Path refs under a root (`PathRef{Root, Relative}`) went through
    `internal/pathsafe.ResolveUnder`. When the final component was a symlink
    whose target did not exist yet, `filepath.EvalSymlinks` reported
    not-exist and the resolver fell back to the link's own path, so
    `project/link -> /outside/newfile` resolved to `project/link` and passed
    the root check. A caller that used the resolved path to create or write
    the file wrote through the link to `/outside/newfile`. nanite#352 proved
    the same defect in Nanite's copy.
  - `ResolveUnder` now comes from `github.com/hollis-labs/go-safefs/pathsafe`
    v0.1.0, which follows a dangling link (relative targets against the
    link's real directory, chains up to 40 hops, cycles refused) and judges
    where it points. `internal/pathsafe` is deleted.
  - `ResolvedAccessPolicy.AccessFor`, and root/absolute-path canonicalization
    in `ResolveAccessPolicy`, had the same fallback in their own resolver: a
    dangling link inside a writable root was reported `AccessReadWrite` even
    when it pointed outside every grant or into a denied subtree. That
    resolver now follows dangling links the same way.
  - A dangling link whose target stays inside the root is still allowed and
    now resolves to that target.
- New dependency: `github.com/hollis-labs/go-safefs` v0.1.0 (standard library
  only).

## v0.4.0 — 2026-09-30

- Add `DenyGUILaunch` to `AccessPolicy`, `ResolvedAccessPolicy` and the legacy
  `Profile` (`deny_gui_launch`), and the `CapGUILaunchDeny` capability. Both
  macOS emitters (`BuildSBPL`, `BuildResolvedSBPL`) deny exec of
  `/usr/bin/open` and Mach lookups of `com.apple.coreservices.launchservicesd`
  and `com.apple.lsd.*`; the resolved emitter writes the denies last so they
  follow the `system.sb` and `process*` allows. Linux bwrap does not provide
  the capability, so a required resolved policy that sets it is reported
  unsupported there. Tests launch real processes under `sandbox-exec`.

## v0.3.0 — 2026-09-06

- Add resolved filesystem, network and subprocess access policies, backend
  capability reporting and explicit enforcement outcomes.
- Enforce macOS filesystem allowlists and deny rules through SBPL; reject
  required policy combinations that cannot be enforced before process start.
- Add Linux bubblewrap resolved-policy enforcement with restricted mounts,
  private networking and explicit loopback forwarding.
- Preserve the legacy `Profile` / `Apply` entry points and add behavioral
  tests for read/write denial, unavailable backends and policy propagation.

## v0.2.1 — 2026-05-10

- Docs: public-release polish — refreshed `Status` section to reflect the
  v0.2.x line, reframed audit-trace and lineage references so they stand on
  their own without pointing into private sibling repos, and synced the
  `sandbox` package doc.go with the README.
- No functional changes; no API changes.

## v0.2.0 — 2026-05-01

- Added: `Profile.AllowLoopback` for permitting `127.0.0.0/8` and `::1` while
  `Net=false`. macOS emits explicit localhost `allow` rules ahead of the
  terminal `(deny network*)`; Linux brings up `lo` inside the unshared
  network namespace via a small in-namespace trampoline.
- Added: Linux `Profile.LoopbackForwardPorts` for bridging explicit host
  `127.0.0.1:<port>` listeners into a `--unshare-net` sandbox via a host-side
  Unix-socket bridge plus an in-netns supervisor that binds
  `127.0.0.1:<port>` (and `::1:<port>` when available) inside the sandbox.

## v0.1.0 — 2026-04-27

Initial extraction. Hybrid sandbox library combining the broker-side
`Profile` API with a hardened macOS (sandbox-exec / SBPL) and Linux
(bubblewrap) implementation:

- `Profile{FS{Read,Write,Deny}, Net, Subprocess, ID}` shape and
  `Apply(cmd, profile, workspace) (cleanup, err)` entry point.
- macOS SBPL backend with non-optional `validateSeatbeltLiteral` (rejects
  profile-string injection on workspace path and every FS entry).
- Linux bwrap backend with narrowed `--ro-bind` candidate set,
  per-invocation `--tmpfs /tmp`, full namespace unsharing
  (`--unshare-pid` / `--unshare-ipc` / `--unshare-uts` /
  `--unshare-cgroup-try` / `--unshare-user-try`), `--die-with-parent`,
  `--new-session`, conditional `--unshare-net`.
- `LoadProfile` / `LoadProfiles` YAML loaders.
- `examples/mux_integration` and `examples/clockwork_integration`.
- Hard-error stub on platforms other than darwin/linux (no silent
  downgrade).
