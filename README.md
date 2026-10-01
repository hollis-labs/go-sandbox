# go-sandbox

`go-sandbox` is a small, standalone Go library that defines resolved process access policy and applies per-process OS-level sandboxes — macOS `sandbox-exec` (SBPL/seatbelt) on darwin, `bwrap` (bubblewrap) on linux — on top of an already-built `*exec.Cmd`.

It is the substrate library that consumers (`agent-mux`, `clockwork-manifold`, `nanite`, ...) use to wrap a CLI provider invocation in a sandbox without each consumer reinventing the seatbelt / bwrap wrapping themselves.

## Status

v0.3.0 — keeps the legacy `Profile` / `Apply` API and adds explicit resolved access policy contracts for shared materialization and prepared launch flows. Resolved policies can be applied on macOS through SBPL and on Linux through bubblewrap. The macOS SBPL literal validator and the Linux bwrap narrowed-mounts / namespace-unsharing posture remain non-optional and covered by tests.

## Install

```bash
go get github.com/hollis-labs/go-sandbox
```

## Usage

New code should resolve policy before launch and record the enforcement outcome:

```go
p := sandbox.AccessPolicy{
    ID:   "session-required",
    Mode: sandbox.ConfinementRequired,
    Roots: sandbox.Roots{
        Project: "/work/project",
        Boot:    "/tmp/session/boot",
        State:   "/tmp/session/state",
        Scratch: "/tmp/session/scratch",
        CWD:     "/work/project/subdir",
    },
    FS: sandbox.FilesystemAccess{
        Read:       []sandbox.PathRef{{Root: sandbox.ProjectRoot}},
        Write:      []sandbox.PathRef{{Root: sandbox.BootRoot}},
        Deny:       []sandbox.PathRef{{Root: sandbox.ProjectRoot, Relative: ".git"}},
        SourceRead: []sandbox.PathRef{{Path: "/catalog/source"}}, // preparation only
    },
    Runtime: sandbox.RuntimeAccess{
        Executable: sandbox.PathRef{Path: "/usr/bin/codex"},
        Read:       []sandbox.PathRef{{Path: "/usr/lib"}},
    },
    ProviderState: sandbox.ProviderStateAccess{
        Write: []sandbox.PathRef{{Root: sandbox.StateRoot}},
    },
    Scratch:    sandbox.ScratchAccess{Writable: true},
    Network:    sandbox.NetworkAccess{Mode: sandbox.NetworkLoopback, LoopbackPorts: []int{4317}},
    Subprocess: sandbox.SubprocessAllow,
}

resolved, err := sandbox.ResolveAccessPolicy(p)
if err != nil {
    log.Fatal(err)
}
caps := sandbox.ResolveBackendCapabilities("", resolved.Backend)
outcome := sandbox.AssessEnforcement(resolved, caps)
if outcome.State != sandbox.EnforcementConfigured {
    log.Fatalf("sandbox unsupported: %v", outcome.Diagnostics)
}
```

The resolved policy is a contract value. It separates `ProjectRoot`, `BootRoot`, `StateRoot`, `ScratchRoot` and `CWDRoot`; a changed process cwd never widens project access. Write grants imply read access, explicit denies win beneath allowed parents, and source/catalog reads used during launch preparation are recorded separately from child access grants. Required confinement fails closed when a backend lacks a requested capability. `ConfinementDisabled` is explicit and produces an honest disabled outcome rather than a successful enforcement report.

On macOS, resolved policy is applied directly through a default-deny `sandbox-exec` profile with explicit filesystem/runtime grants. On Linux, resolved policy is applied through a default-deny bwrap namespace that binds only runtime/system support paths plus explicit read/write, provider-state and scratch grants; source-read paths remain preparation-only and are never child grants. Directory denies are emitted as unreadable overlays by the pure argument builder, while `ApplyResolved` uses temporary unreadable shadow binds so file and directory denies both fail closed. `ApplyResolved` returns an applied outcome only after wrapping the exact command that will be started:

```go
outcome, cleanup, err := sandbox.ApplyResolved(cmd, resolved)
if err != nil {
    log.Fatalf("sandbox unsupported: %v", outcome.Diagnostics)
}
defer cleanup()
```

Unsupported resolved capabilities fail explicitly rather than falling back to broad grants. `SubprocessDeny` remains unsupported for resolved bwrap because bubblewrap isolates namespaces but does not prevent a sandboxed process from forking within that namespace. Legacy `Profile` callers can continue using `Apply`.

`DenyGUILaunch` (on `AccessPolicy`, `ResolvedAccessPolicy` and the legacy `Profile`) stops the child from launching GUI applications, such as a CLI whose sign-in fallback opens a browser. On macOS both emitters deny `exec` of `/usr/bin/open` and Mach lookups of LaunchServices (`launchservicesd`, `lsd.*`), so a copy of `open` or any other LaunchServices client is cut off too. It is reported as the `gui-launch-deny` capability: macOS seatbelt provides it, Linux bwrap does not, and a required resolved policy that asks for it on Linux is refused rather than run unenforced. It is macOS-only and a no-op for legacy `Apply` on Linux, like `Subprocess`. Note that a resolved policy is default-deny, so one that sets only `DenyGUILaunch` would also deny everything else; to deny GUI launch and nothing more, use a legacy default-allow `Profile{Net: true, Subprocess: true, DenyGUILaunch: true}` (what agentkit does).

`FS.Protect` (on `AccessPolicy`, `ResolvedAccessPolicy` and the legacy `Profile`, yaml `protect`) write-protects control-plane state: a host's database, config, catalog or allow-lists, which an agent running as the operator's uid could otherwise rewrite to grant itself authority.
- **Semantics:**
  - A protected path is never writable, even inside a write grant or the workspace.
  - It stays readable where a grant covers it, and protection grants nothing: a protected path outside every grant stays invisible.
  - `Deny` still wins over it.
  - `ResolvedAccessPolicy.WithProtected(paths...)` adds absolute paths to a policy resolved elsewhere.
  - It is reported as the `write-protect` capability, which both backends provide.
- **What may be protected:**
  - **No write grants inside.** A write grant or workspace at or inside a protected directory is refused on both platforms. On Linux it would stay writable through the protection; on macOS the deny would win. Refusing it means the platforms can't disagree.
  - **Directories only.** A file's directory stays writable, so the host's own atomic save (rename over the file) or a database sidecar planted beside it (SQLite's `-wal`) defeats file-level protection. A non-directory entry is refused unless a protected directory covers it.
  - **Absolute paths only.** A relative entry is refused.
  - **No re-pointable symlinks.** An entry that goes through a symlink in a directory the uid can write is refused, because the child could swap the link after launch. Pass the real path.
    - A directory the uid owns counts as writable even at 0555, because its owner can chmod it back.
    - The check follows the whole resolution, including link targets, so a fixed symlink whose target crosses a re-pointable one is refused too.
- **Linux:** bwrap read-only-binds each protected directory over the writable mounts, so writes, creates, renames and unlinks inside it fail.
  - Every ancestor the child could rename is bound onto itself first, rw. A mount point can't be renamed or removed, so the child can't `mv` the protected tree aside and recreate it with its own content.
  - The pins come before any read mount, in legacy and resolved mode alike, so they never cover a read-only grant beneath them.
  - Every protected directory under a writable mount is bound, including one nested inside another protected directory, and the fail-closed check covers each.
  - Binds go where the child sees the path. A workspace or write root reached through a symlink gets the bind at its symlinked path, and an existing protected directory under a writable mount that can't be bound fails the launch.
  - A protected path that does not exist cannot be bound without creating it on the host. Where the child could create it, it is refused at launch; create it first or protect its existing parent. Elsewhere it is skipped.
- **macOS:** seatbelt denies `file-write*` and `file-link` on each protected path, by its real path and the `/tmp` or `/var` alias, after every allow.
  - Each ancestor is also denied writes by literal (the entry, not its contents), so it can't be renamed away and replaced with a symlink to a writable dir.
  - These macOS rules are reasoned and their tests compile, but they have **not yet run on a Mac**. In particular, `file-link` must be confirmed as an operation `sandbox-exec` accepts before a release.
- **No sandbox today:** for a host whose agents run unconfined and only need this protection, `Profile{HostFilesystem: true, Net: true, Subprocess: true, FS: FSSpec{Protect: …}}` is the minimal sandbox.
  - On Linux it binds the host filesystem writable with devices (`--dev-bind / /`).
  - It gives the child its own pid namespace and `/proc`. With paths to protect it requires the user namespace (`--unshare-user`), so the kernel refuses `/proc/<pid>/root` and ptrace of host processes from inside.
  - It shares the ipc and uts namespaces and the session. There is no `--new-session`, because a PTY session needs its controlling terminal; TIOCSTI injection into a parent's terminal is off by default since Linux 6.2.
  - It refuses `FS.Deny`.
  - macOS legacy profiles are already default-allow.
- **Boundary:**
  - Protect stops **direct writes** to the protected paths in every mode.
  - Against writes **delegated** to another process, it holds only under a narrowed or resolved policy that doesn't show the sockets involved (a read-only grant counts as showing them). An example is `systemd-run --user`; `DenyUserServiceManager` (below) closes that one in every mode.
  - **HostFilesystem mode is not an isolation boundary.** Its child reaches the user's runtime sockets, terminal-multiplexer sockets and the host apps' own APIs, and any same-uid service behind them can write for it. With `$HOME` writable it can also plant code that runs outside the sandbox later: `~/.bashrc`, `~/.config/systemd/user`, git hooks.
  - Hiding `$XDG_RUNTIME_DIR` wholesale would break ssh-agent and the keyring, which uses the session bus. `DenyUserServiceManager` hides only the user service manager's sockets and the session bus.
- **Delegation through the user service manager (`DenyUserServiceManager`):**
  - The systemd user manager runs whatever it's asked to, outside the sandbox and as the same uid: `systemd-run --user touch /protected/x` writes a protected path for the child.
  - It answers on `$XDG_RUNTIME_DIR/systemd/` (its private socket and Varlink sockets) and on the session bus, where it is `org.freedesktop.systemd1`. With only `systemd/` hidden, `systemd-run --user --wait`, or any D-Bus client calling `StartTransientUnit`, still gets through the bus (measured on systemd 259).
  - `DenyUserServiceManager: true` (on `Profile`, yaml `deny_user_service_manager`, `AccessPolicy` and `ResolvedAccessPolicy`) hides both on Linux, wherever the sandbox shows them. It puts an empty read-only tmpfs over each `systemd/` directory, and `/dev/null` over each of these: the session-bus socket, any `unix:path=` socket in `DBUS_SESSION_BUS_ADDRESS`, and any hard link to one of them planted in the runtime directory. The runtime directory and bus address come from the child's environment and the parent's, plus logind's `/run/user/<uid>`.
  - **The cost:** the session bus goes too, and with it everything on it: the Secret Service keyring (`org.freedesktop.secrets`, gnome-keyring), notifications and portals. ssh-agent, gpg-agent and the other sockets in the runtime directory stay. Turn it on for agents that need no keyring.
  - It applies wherever the runtime directory is visible, read-only grants included, since a read-only mount does not stop `connect(2)`.
  - A session bus the mounts can't hide (an abstract socket or a TCP address) is refused while the sandbox shares the host network. With the network unshared it's unreachable anyway.
  - The masks are mounts the child can't remove: it has no capabilities, and a nested user namespace would inherit them locked (`mount_namespaces(7)`).
  - **macOS refuses it**, because launchd would still run a job for the child. A resolved policy asking for it reports `user-service-manager-deny` as unsupported there, which fails closed under required confinement.
  - **Not covered:**
    - Other same-uid services that act for a caller, such as a rootless docker or podman socket, a terminal multiplexer, or the host apps' own APIs.
    - The system manager. polkit asks for interactive authentication, and the sandbox can't answer it.
    - A hard link to the bus outside the runtime directory. When the runtime directory is not its own filesystem, a link elsewhere on that filesystem is not found.
    - A second mount of the runtime directory's filesystem, as for Protect: the masks follow the paths found.
    - A socket recreated during the session. The masks cover the sockets present at launch. If the host unlinks and recreates one (a dbus restart, a re-login), the kernel detaches the mask from the old file and the new socket is visible. The child can't cause that itself: it reaches neither the manager nor the bus, and can't signal host processes from its own pid namespace.
- **Other limits:**
  - Protection follows the paths given. If the same directory is also reachable through a second host mount (a bind mount, a btrfs subvolume, a second mount of the same filesystem) that the sandbox exposes writable, writes through that path are not covered. Protect each path the sandbox can reach it by.
  - A read-only mount does not stop `connect(2)` to a Unix socket, so hide a control socket with `Deny` instead. A socket is not a directory, so it can't be protected anyway.

Existing callers can continue using `Profile` directly:

```go
package main

import (
    "log"
    "os"
    "os/exec"

    "github.com/hollis-labs/go-sandbox/sandbox"
)

func main() {
    p := sandbox.Profile{
        ID: "workspace-only",
        FS: sandbox.FSSpec{
            Write: []string{"workspace"},          // workspace token resolves to the ws root
            Read:  []string{"workspace"},
            Deny:  []string{"${HOME}/.ssh"},       // takes precedence over Read
        },
        Net:           false,                       // deny outbound
        AllowLoopback: true,                        // permit loopback while Net=false
        LoopbackForwardPorts: []int{4317},         // linux: expose host 127.0.0.1:4317 inside the sandbox
        Subprocess: true,                           // allow subprocess (macOS-only enforcement)
    }

    cmd := exec.Command("claude", "--print", "hello")
    cmd.Stdout = os.Stdout

    cleanup, err := sandbox.Apply(cmd, p, "/Users/me/work/session-abc")
    if err != nil {
        log.Fatal(err)
    }
    defer cleanup()

    if err := cmd.Run(); err != nil {
        log.Fatal(err)
    }
}
```

Profiles can also be loaded from YAML via `sandbox.LoadProfile` / `sandbox.LoadProfiles`. See `examples/mux_integration` and `examples/clockwork_integration`.

Use `sandbox.PolicyFromProfile(profile, workspace)` when migrating legacy `Profile` or app-level `SandboxProfile` values into the resolved API. The returned policy is marked `Legacy.DefaultAllow`; callers should report it as legacy compatibility, not strict workspace confinement, unless capability assessment and backend enforcement prove the stronger guarantee.

## What this library is — and isn't

**This is a lib, not a framework.**

In:

- `Profile` shape (`FS{Read,Write,Deny}` + `Net` + `AllowLoopback` + `LoopbackForwardPorts` + `Subprocess` + `ID`)
- `AccessPolicy` / `ResolvedAccessPolicy` with distinct project, boot, state, scratch and cwd roots
- explicit source-read, runtime-read, provider-state, scratch, network/loopback and subprocess requirements
- backend capability resolution and `EnforcementOutcome` states for configured, applied, disabled, unsupported and failed launches
- `ApplyResolved(cmd, resolvedPolicy)` for backend-aware resolved policy application
- `Apply(cmd, profile, workspace) (cleanup, err)` — hardened wrapping of an `*exec.Cmd`
- macOS SBPL backend with the **non-optional `validateSeatbeltLiteral`** (SBPL profile-string injection is a real CVE shape; the validator runs on every interpolated value before profile emit)
- Linux bwrap backend with narrowed `--ro-bind` candidate set, resolved-policy read/write/provider-state/scratch binds, source-read exclusion, deny shadowing, per-invocation `--tmpfs /tmp`, namespace unsharing (`--unshare-pid` / `--unshare-ipc` / `--unshare-uts` / `--unshare-cgroup-try` / `--unshare-user-try`), `--die-with-parent`, `--new-session`, conditional `--unshare-net`
- `LoadProfile` / `LoadProfiles` YAML loaders
- Cleanup-function return on darwin so callers can `defer cleanup()` without leaking temp profile files
- Bounded path resolution through `github.com/hollis-labs/go-safefs/pathsafe` (`ResolveUnder`), which judges a dangling symlink by where it points
- `examples/mux_integration` and `examples/clockwork_integration` showing both YAML and programmatic profile shapes

Out (intentionally):

- **Network proxy subsystem.** A host-side allowlist proxy already exists in one of the source projects (`nanite`) but stays there. If more apps need allowlisted egress, extract a separate `go-egress-proxy` lib later — don't fold it into this one.
- **Windows.** Neither source impl supports Windows. A non-`darwin` non-`linux` `Apply` returns a hard error — no silent downgrade.
- **App vocabulary.** No FSM transitions, no executor tickets, no broker events, no plugin lifecycle. Apps translate raw `*exec.Cmd` invocations + this lib's `Apply` into their own primitives.
- **Resolved subprocess-deny enforcement.** The legacy macOS profile can still emit the old process-fork/process-exec rules, but the resolved macOS pre-spawn path reports `SubprocessDeny` as unsupported because denying `process-exec*` prevents `sandbox-exec` from launching the initial payload. Linux bwrap also does not gate subprocess spawning directly — namespace isolation prevents the sandboxed process from affecting the host, but it can still fork children inside the sandbox. A future iteration may add a backend-specific mechanism for parity.


## Linux resolved-policy test runner

Darwin can compile the Linux bwrap backend but cannot execute Linux namespace tests. Use this runner on a Linux host, or start Colima/Docker locally and run it from the repository root:

```bash
colima start --arch aarch64

docker run --rm --privileged \
  -v "$PWD":/src -w /src \
  golang:1.26.1-bookworm \
  bash -lc 'apt-get update && apt-get install -y --no-install-recommends bubblewrap iproute2 ca-certificates && go test ./sandbox -run "TestBuildResolvedBwrap|TestApplyResolvedPolicyParity|TestApplyResolved_BwrapMissing|TestLoopbackForward|TestAllowLoopback" -count=1 -v'
```

`--privileged` is intentional for this reproducible runner because bwrap needs Linux namespace features that Docker Desktop commonly blocks with its default seccomp/AppArmor profile. A non-privileged Linux CI worker can run the same `apt-get ... && go test ...` command directly if unprivileged user namespaces and bubblewrap are available. If `bwrap` is absent, `ApplyResolved` returns an `EnforcementUnsupported` outcome with `ErrBackendUnavailable` instead of mutating the command.

## AllowLoopback

`Profile.AllowLoopback` is an additive escape hatch for loopback traffic when `Net == false`. When `Net == true`, the field is a no-op because the sandbox already has full network access.

```go
p := sandbox.Profile{
    ID:             "mcp-loopback",
    Net:            false,
    AllowLoopback:  true,
    Subprocess:     true,
}
```

On macOS, the SBPL backend emits explicit localhost `allow` rules before the terminal `(deny network*)`, which covers the tested `127.0.0.1` and `::1` paths under seatbelt's host-filter constraints. On Linux, the bwrap backend still uses `--unshare-net`; a small trampoline path brings `lo` UP inside the unshared namespace and then execs the real target. That enables loopback inside the sandbox namespace itself, but it does not reach a localhost listener in the parent/host namespace.

When a Linux caller needs a host-side localhost service such as a parent-bound MCP server, set `LoopbackForwardPorts` to the explicit TCP ports that should be bridged into the sandbox:

```go
p := sandbox.Profile{
    ID:                   "mcp-linux",
    Net:                  false,
    LoopbackForwardPorts: []int{4317},
    Subprocess:           true,
}
```

Under the hood, the Linux backend keeps `--unshare-net`, starts a host-side Unix-socket bridge for each forwarded port, and runs a small in-netns supervisor that binds `127.0.0.1:<port>` (and `::1:<port>` when available) inside the sandbox and relays to the host listener. Ports not listed in `LoopbackForwardPorts` remain unreachable.

## Legacy default-allow rationale

The legacy `Profile` / `Apply` path remains default-allow with selective denies for compatibility with existing callers.

The reasons differ slightly per platform but rhyme: a correct legacy default-deny posture would require enumerating an OS-version-dependent allowlist of every system path, library directory, and IPC endpoint every modern process implicitly touches — dyld caches and Mach services on macOS, glibc/musl loader paths and ld.so.conf entries on Linux. Enumerating that list correctly across distros and OS versions is a significant maintenance burden, and a partial allowlist can produce runtime failures that are hard for legacy callers to interpret.

Resolved `AccessPolicy` is the stricter path. It uses default-deny SBPL on macOS and a private bwrap namespace with explicit mounts on Linux, while still preserving the legacy API for current consumers.

## Hardening posture (audit-trace)

The Linux bwrap backend's rationale comments were authored against an internal **2026-04-10 sandbox hardening audit** (`finding 06`, gaps #1–#5). The audit document itself lives in a private repo, but the gaps it called out and the mitigations are summarised here:

- **gap #1** — read-only mounts narrowed from blanket `--ro-bind / /` to a candidate set of `/usr`, `/lib*`, `/bin`, `/sbin`, `/etc/{alternatives,ssl,ca-certificates,resolv.conf,hosts,nsswitch.conf}`. `/home`, `/root`, `/var`, `/srv`, `/opt`, and dotfiles are deliberately not bound — they can contain SSH keys, AWS creds, shell history, and other secrets the agent must not see. See `bwrapRoBindCandidates` in `sandbox/apply_linux.go`.
- **gap #2** — PID, IPC, UTS, cgroup, user namespaces always unshared so the sandboxed process cannot observe or interfere with host processes. `--unshare-user-try` degrades on hardened distros that disable unprivileged user namespaces; the rest are always available.
- **gap #3** (partial) — network namespace unshared when legacy `Profile.Net == false` or resolved `Network.Mode` is `deny`/`loopback`. Full proxy-mediated egress is out of scope for v0; see "Out".
- **loopback follow-up** — when `Profile.AllowLoopback == true` and `Profile.Net == false`, Linux still unshares the network namespace and raises only the namespace-local `lo` device before execing the target. This keeps non-loopback interfaces out of view while allowing loopback traffic inside the sandbox namespace. If `LoopbackForwardPorts` is set, only those explicit host localhost TCP ports are bridged into the sandbox.
- **gap #4** — `/tmp` replaced with a per-invocation `--tmpfs` so there is no cross-session leakage through shared `/tmp` files.
- **gap #5** (partial) — `--die-with-parent` and `--new-session` prevent orphan escape and TTY hijacking.

The macOS backend's `validateSeatbeltLiteral` was added in response to a profile-string injection vector: before the validator existed, a workspace path containing `") (allow file-write*) ;"` could turn the seatbelt profile into a no-op. The validator runs on the workspace path AND every `FS.Read`/`FS.Write`/`FS.Deny` entry before profile emit; any rejected value short-circuits `Apply` with a non-nil error.

## Repository layout

```
go-sandbox/
├── go.mod
├── LICENSE                            # MIT
├── README.md
├── sandbox/                           # main package
│   ├── doc.go
│   ├── profile.go                     # Profile, FSSpec, LoadProfile, LoadProfiles
│   ├── policy.go                      # AccessPolicy, ResolvedAccessPolicy, capability assessment
│   ├── apply_policy.go                # ApplyResolved common wrapper + outcomes
│   ├── apply_darwin.go                # SBPL backend + validateSeatbeltLiteral + cleanup
│   ├── apply_linux.go                 # bwrap backend + narrowed mounts + namespace unsharing
│   ├── apply_unsupported.go           # hard-error stub for other platforms
│   ├── apply_resolved_unsupported.go  # ApplyResolved stub for unsupported platforms
│   ├── profile_test.go
│   ├── policy_test.go
│   ├── apply_darwin_test.go
│   ├── apply_linux_test.go
│   ├── resolved_policy_integration_test.go
│   └── integration_test.go
└── examples/
    ├── mux_integration/               # load profile YAML, apply to exec.Cmd
    │   ├── main.go
    │   └── testdata/workspace-only.yaml
    └── clockwork_integration/         # programmatic Profile, apply for executor task
        └── main.go
```

## Lineage

This package is a hybrid extraction from two sibling sandbox implementations (currently in private repos), reconciled into a single public substrate:

- **Public API** (`Profile{FS, Net, AllowLoopback, LoopbackForwardPorts, Subprocess, ID}`, `LoadProfile`, `LoadProfiles`) — taken from `agent-mux`'s sandbox package (the broker-side Profile shape).
- **macOS backend + literal validator** — taken from `nanite`'s darwin sandbox impl (`validateSeatbeltLiteral`, seatbelt profile shape).
- **Linux backend** — taken from `nanite`'s linux sandbox impl (narrowed mounts, namespace unsharing, conditional `--unshare-net`, `--die-with-parent`).
- **Cleanup pattern** — taken from `nanite`'s `applyOSSandbox`. The earlier mux `Apply` leaked the temp profile file on darwin; the cleanup-function return added here closes that, and the regression is covered by tests — do not regress it.
- **Path-escape rejection** — originally a verbatim port of `nanite`'s internal `pathsafe` helper; since v0.4.1 it is `go-safefs/pathsafe`, the shared extraction that carries the dangling-symlink fix.

## License

MIT — see `LICENSE`.
