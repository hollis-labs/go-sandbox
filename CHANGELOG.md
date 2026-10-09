# Changelog

## Repository retirement — 2026-10-09

- Deprecated this standalone repository in favor of `github.com/hollis-labs/substrate/harness@v0.3.0`
  ([migration guide](https://github.com/hollis-labs/substrate/blob/harness/v0.3.0/harness/docs/units/go-sandbox/MIGRATION.md)).
- Preserved existing release tags and history. This documentation change does
  not create a new standalone release or migrate applications.

All notable changes to this project will be documented in this file. This
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.6.0 — 2026-10-01

Stop writes delegated to the user service manager (CW-20261001-0128).

### Added

- **`DenyUserServiceManager`** on `AccessPolicy`, `ResolvedAccessPolicy` and
  the legacy `Profile` (yaml `deny_user_service_manager`), with the
  `user-service-manager-deny` capability (`CapUserServiceManagerDeny`).
  - It stops the child reaching the user service manager, which would run a
    command for it outside the sandbox: `systemd-run --user touch
    /protected/x` gets past `FS.Protect` in HostFilesystem mode, or under any
    grant that shows `$XDG_RUNTIME_DIR`.
  - Measured on systemd 259: the manager answers on
    `$XDG_RUNTIME_DIR/systemd/` (its private socket and Varlink sockets), and
    on the session bus as `org.freedesktop.systemd1`. With only `systemd/`
    hidden, `systemd-run --user --wait` and any D-Bus client still get through
    the bus. So the option hides both.
- **Linux enforcement:** the masks come after every other mount, wherever the
  sandbox shows the path. That includes read-only grants, since a read-only
  mount does not stop `connect(2)`. It applies to legacy `Apply` (narrowed
  and HostFilesystem), `ApplyResolved` and `BuildResolvedBwrap`.
  - Each `systemd/` directory gets an empty read-only tmpfs.
  - `/dev/null` goes over each of these:
    - the session-bus socket;
    - any `unix:path=` socket in `DBUS_SESSION_BUS_ADDRESS`;
    - any hard link to one of them, or to a socket under `systemd/`, planted
      in the runtime directory. The search skips other mounts beneath it,
      untouched.
  - The runtime directory and bus address come from the child's environment
    and the parent's, plus logind's `/run/user/<uid>`.
  - Other sockets in the runtime directory (ssh-agent, gpg-agent) stay.
- **What it refuses:**
  - A session-bus address the mounts can't hide (an abstract socket, or a TCP
    address) while the sandbox shares the host network.
  - Any other bus transport.
  - A runtime directory it can't fully search for links.
- **Not covered:**
  - Other same-uid services that act for a caller (a rootless container
    socket, a terminal multiplexer).
  - A second mount of the runtime directory's filesystem.
  - A socket the host recreates during the session (a dbus restart). That
    detaches its mask. The child can't cause it.
- **The cost:** everything else on the session bus goes too, including the
  Secret Service keyring, notifications and portals. It is for hosts whose
  agents need no keyring (Torque, Hadron).
- **macOS refuses it** (`BuildSBPL`, `BuildResolvedSBPL`), because launchd
  would still run a job for the child. Resolved policies report the
  capability as unsupported, which fails closed under required confinement.
- **Tests:**
  - Real bwrap, both directions: under a HostFilesystem profile protecting a
    directory, `systemd-run --user --wait` writes into it from outside without
    the option. With the option it can't, by the bus or the private socket,
    and `busctl --user` can't reach the manager.
  - A resolved policy whose read grant shows the runtime directory: the bus
    answers without the option, and doesn't with it.
  - The masks leave other sockets alone, catch planted hard links, and come
    after the protect binds.
  - Removing the socket masks, or the hard-link search, fails these tests.

## v0.5.1 — 2026-10-01

### Fixed

- **A host-filesystem profile runs the command at the path the caller gave**
  (CW-20260930-0237).
  - On Linux, `Apply` with `Profile.HostFilesystem` still ran the narrowed
    profile's payload logic. For a command that is a symlink to a target
    outside the workspace and system dirs (an installed CLI shim,
    `~/.local/bin/<tool>`), it judged the target "not visible", bound it
    and executed the resolved target instead.
  - That changed `argv[0]`, so a multi-call binary, or a launcher that
    dispatches on its own name, did something else entirely.
  - A host-filesystem profile binds `/` itself, so everything is visible at
    its own path, and the command now runs unchanged.
- Pinned by `TestApplyHostFilesystemKeepsSymlinkedCommandPath`, which fails
  on v0.5.0.

## v0.5.0 — 2026-10-01

Write-protected control-plane paths (CW-20260930-0237).

### Added

- **`FS.Protect`** on `FilesystemAccess`, `ResolvedFilesystemAccess` (with
  the `AccessProtect` kind) and the legacy `Profile.FS` (yaml `protect`).
  - It lists directories the child must never write, even inside a write
    grant: a host's state, database, config, catalog or allow-lists. An
    agent running as the operator's uid could otherwise rewrite them to
    grant itself authority.
  - A protected directory stays readable where a grant covers it, and
    grants nothing. `Deny` still overrides it.
  - `AccessFor` reports it as read-only, or no-grant when nothing covers
    it.
- **What it accepts:**
  - **No write grants inside.** A write grant or workspace at or inside a
    protected directory is refused on both platforms
    (`ResolveAccessPolicy`, `WithProtected` and the legacy builders). On
    Linux the grant stayed writable through the protection, and an outer
    protect even disabled an inner one's bind.
  - **Directories only.** A file entry is refused unless a protected
    directory covers it: the file's directory stays writable, so the host's
    own atomic save, or a sidecar planted beside it (SQLite's `-wal`),
    defeats file-level protection.
  - **Absolute paths only.**
  - **No re-pointable symlinks.** An entry that goes through a symlink in a
    directory the uid can write is refused: protect the real path.
    - A directory the uid owns counts as writable even at 0555.
    - The check follows the whole resolution, including link targets.
- **The `write-protect` capability (`CapWriteProtect`)**, provided by linux
  bwrap and darwin seatbelt. `AssessEnforcement` requires it when a
  resolved policy protects anything.
- **`ResolvedAccessPolicy.WithProtected(paths...)`** adds absolute paths to
  an already-resolved policy, canonicalized, deduplicated and validated the
  same way. This is how a host composes its control-plane paths into a
  policy built elsewhere.
- **`Profile.HostFilesystem`** (yaml `host_filesystem`) is the minimal
  protect-only sandbox for hosts whose agents otherwise run unconfined.
  - On Linux it binds the host filesystem writable with devices
    (`--dev-bind / /`).
  - It gives the child a private pid namespace and `/proc`, and requires the
    user namespace (`--unshare-user`) when anything is protected. Together
    these make the kernel refuse `/proc/<pid>/root` and ptrace of host
    processes.
  - It shares the ipc and uts namespaces and the session. There is no
    `--new-session`, because a PTY needs its controlling terminal.
  - It unshares the network only when `Net` is false, and refuses `FS.Deny`.
  - macOS legacy profiles are already default-allow.
- **Linux enforcement:** each protected directory is read-only-bound where
  the child sees it, over the writable mounts and under the deny overlays.
  - This applies to legacy `Apply`, `ApplyResolved` and `BuildResolvedBwrap`.
  - **Pins:** every ancestor the child could rename is first bound onto
    itself, rw, except inside a protected directory. A mount point can't be
    renamed or removed (EBUSY), so the child can't `mv /W /W2` to carry the
    read-only mount away and recreate `/W/state` for the host to read. Pins
    come before any read mount in legacy and resolved mode alike, so they
    never cover a read-only grant beneath them.
  - **Nested protected directories:** every protected directory under a
    writable mount is bound, nested or not.
  - **Symlinked roots:** a workspace or write root reached through a symlink
    gets the bind at its symlinked path. An existing protected directory
    under a writable mount that ends up unbound fails the launch.
  - **Missing paths:** a protected path that doesn't exist is refused where
    the child could create it, and skipped elsewhere.
  - Writes, creates, renames, unlinks, mkdir, hard links and planted
    sidecars inside a protected directory all fail. This is pinned by
    real-bwrap tests, each of which fails without its fix.
- **macOS enforcement:** `BuildSBPL` and `BuildResolvedSBPL` emit
  `(deny file-write* …)` and `(deny file-link …)` for each protected path.
  They use its real path plus the `/tmp` or `/var` alias, and come after
  every write allow.
  - Each ancestor also gets a literal write deny (the entry, not its
    contents).
  - **Not run on a Mac.** These were checked by reasoning and by darwin-only
    tests compiled with `GOOS=darwin`. `file-link` must be confirmed as an
    operation `sandbox-exec` accepts before release.

### Not covered

- **Boundary:**
  - Protect stops direct writes to the protected paths in every mode.
  - Against writes delegated to another process (for example
    `systemd-run --user` over `$XDG_RUNTIME_DIR/bus` or
    `$XDG_RUNTIME_DIR/systemd/private`), it holds only under a narrowed or
    resolved policy that doesn't mount those sockets.
  - HostFilesystem mode is not an isolation boundary. Its child reaches the
    user's runtime sockets, terminal-multiplexer sockets and the host apps'
    own APIs. With `$HOME` writable it can plant code that runs outside the
    sandbox later: `~/.bashrc`, `~/.config/systemd/user`, git hooks.
  - `$XDG_RUNTIME_DIR` is not hidden wholesale: that would break ssh-agent
    and the keyring. An opt-in to hide the systemd user-manager sockets is a
    backlog follow-up.
- A read-only mount doesn't stop `connect(2)` on a Unix socket. Use `Deny`
  for a control socket.
- **Second host mounts:** protection follows the paths given. A directory
  also reachable through a second host mount the sandbox exposes writable
  (a bind mount, a btrfs subvolume) is not covered on that path.

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
