# Changelog

All notable changes to this project will be documented in this file. This
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
