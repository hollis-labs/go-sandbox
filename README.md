# go-sandbox

`go-sandbox` is a small, standalone Go library that defines resolved process access policy and applies per-process OS-level sandboxes — macOS `sandbox-exec` (SBPL/seatbelt) on darwin, `bwrap` (bubblewrap) on linux — on top of an already-built `*exec.Cmd`.

It is the substrate library that consumers (`agent-mux`, `clockwork-manifold`, `nanite`, ...) use to wrap a CLI provider invocation in a sandbox without each consumer reinventing the seatbelt / bwrap wrapping themselves.

## Status

v0.3-in-progress — keeps the legacy `Profile` / `Apply` API and adds explicit resolved access policy contracts for shared materialization and prepared launch flows. Resolved policies can be applied on macOS through SBPL and on Linux through bubblewrap. The macOS SBPL literal validator and the Linux bwrap narrowed-mounts / namespace-unsharing posture remain non-optional and covered by tests.

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
- Internal `pathsafe.ResolveUnder` helper for bounded path resolution (not exported)
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
├── internal/
│   └── pathsafe/                      # internal — bounded path resolution
│       ├── pathsafe.go
│       └── pathsafe_test.go
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
- **`internal/pathsafe`** — verbatim port of `nanite`'s internal `pathsafe` helper; kept internal and not re-exported.

## License

MIT — see `LICENSE`.
