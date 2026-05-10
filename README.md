# go-sandbox

`go-sandbox` is a small, standalone Go library that applies per-process OS-level sandboxes — macOS `sandbox-exec` (SBPL/seatbelt) on darwin, `bwrap` (bubblewrap) on linux — on top of an already-built `*exec.Cmd`, driven by a declarative `Profile`.

It is the substrate library that consumers (`agent-mux`, `clockwork-manifold`, `nanite`, ...) use to wrap a CLI provider invocation in a sandbox without each consumer reinventing the seatbelt / bwrap wrapping themselves.

## Status

v0.2.x — extracted from two sibling sandbox impls (the agent-broker `agent-mux` and the manifest runner `nanite`) and hardened against the findings of an internal sandbox hardening audit dated 2026-04-10 (`finding 06`, gaps #1–#5; summarised under "Hardening posture" below). The macOS SBPL literal validator and the Linux bwrap narrowed-mounts / namespace-unsharing posture are non-optional and covered by tests.

## Install

```bash
go get github.com/hollis-labs/go-sandbox
```

## Usage

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

## What this library is — and isn't

**This is a lib, not a framework.**

In:

- `Profile` shape (`FS{Read,Write,Deny}` + `Net` + `AllowLoopback` + `LoopbackForwardPorts` + `Subprocess` + `ID`)
- `Apply(cmd, profile, workspace) (cleanup, err)` — hardened wrapping of an `*exec.Cmd`
- macOS SBPL backend with the **non-optional `validateSeatbeltLiteral`** (SBPL profile-string injection is a real CVE shape; the validator runs on every interpolated value before profile emit)
- Linux bwrap backend with narrowed `--ro-bind` candidate set, per-invocation `--tmpfs /tmp`, namespace unsharing (`--unshare-pid` / `--unshare-ipc` / `--unshare-uts` / `--unshare-cgroup-try` / `--unshare-user-try`), `--die-with-parent`, `--new-session`, conditional `--unshare-net`
- `LoadProfile` / `LoadProfiles` YAML loaders
- Cleanup-function return on darwin so callers can `defer cleanup()` without leaking temp profile files
- Internal `pathsafe.ResolveUnder` helper for bounded path resolution (not exported)
- `examples/mux_integration` and `examples/clockwork_integration` showing both YAML and programmatic profile shapes

Out (intentionally):

- **Network proxy subsystem.** A host-side allowlist proxy already exists in one of the source projects (`nanite`) but stays there. If more apps need allowlisted egress, extract a separate `go-egress-proxy` lib later — don't fold it into this one.
- **Default-deny posture.** Both source impls use default-allow with selective denies (see "Default-allow rationale" below). Tightening to default-deny requires a well-tested per-OS allowlist of the system paths, dyld caches, Mach services, XPC endpoints, and library directories every modern process implicitly needs. That's a separate sprint.
- **Windows.** Neither source impl supports Windows. A non-`darwin` non-`linux` `Apply` returns a hard error — no silent downgrade.
- **App vocabulary.** No FSM transitions, no executor tickets, no broker events, no plugin lifecycle. Apps translate raw `*exec.Cmd` invocations + this lib's `Apply` into their own primitives.
- **Subprocess enforcement on Linux.** macOS enforces `Profile.Subprocess` via SBPL `process-fork` / `process-exec*` denies. Linux bwrap does not gate subprocess spawning directly — namespace isolation prevents the sandboxed process from affecting the host, but it can still fork children inside the sandbox. A future iteration may add a seccomp filter for parity.

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

## Default-allow rationale

Both backends are default-allow with selective denies, not default-deny.

The reasons differ slightly per platform but rhyme: a correct default-deny posture requires enumerating an OS-version-dependent allowlist of every system path, library directory, and IPC endpoint every modern process implicitly touches — dyld caches and Mach services on macOS, glibc/musl loader paths and ld.so.conf entries on Linux. Enumerating that list correctly across distros and OS versions is a significant ongoing maintenance burden, and a partial allowlist is worse than default-allow because it produces silent runtime failures rather than visible policy gaps.

For v0.2.x we accept default-allow + targeted denies for the principal threat surfaces (sensitive FS paths, network, subprocess) and document this clearly. Tightening is its own future sprint.

## Hardening posture (audit-trace)

The Linux bwrap backend's rationale comments were authored against an internal **2026-04-10 sandbox hardening audit** (`finding 06`, gaps #1–#5). The audit document itself lives in a private repo, but the gaps it called out and the mitigations are summarised here:

- **gap #1** — read-only mounts narrowed from blanket `--ro-bind / /` to a candidate set of `/usr`, `/lib*`, `/bin`, `/sbin`, `/etc/{alternatives,ssl,ca-certificates,resolv.conf,hosts,nsswitch.conf}`. `/home`, `/root`, `/var`, `/srv`, `/opt`, and dotfiles are deliberately not bound — they can contain SSH keys, AWS creds, shell history, and other secrets the agent must not see. See `bwrapRoBindCandidates` in `sandbox/apply_linux.go`.
- **gap #2** — PID, IPC, UTS, cgroup, user namespaces always unshared so the sandboxed process cannot observe or interfere with host processes. `--unshare-user-try` degrades on hardened distros that disable unprivileged user namespaces; the rest are always available.
- **gap #3** (partial) — network namespace unshared when `Profile.Net == false`. Full proxy-mediated egress is out of scope for v0; see "Out".
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
│   ├── apply_darwin.go                # SBPL backend + validateSeatbeltLiteral + cleanup
│   ├── apply_linux.go                 # bwrap backend + narrowed mounts + namespace unsharing
│   ├── apply_unsupported.go           # hard-error stub for other platforms
│   ├── profile_test.go
│   ├── apply_darwin_test.go
│   ├── apply_linux_test.go
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
