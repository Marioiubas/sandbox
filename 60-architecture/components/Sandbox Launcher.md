---
title: "Sandbox Launcher"
aliases: ["launcher", "SandboxBackend implementations"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/isolation, topic/filesystem, control/iso, control/fs, platform/macos, platform/linux, boundary/tb2, invariant/i1, invariant/i2, invariant/i5, milestone/m0]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The launcher crate: SandboxBackend implementations (macos-seatbelt, linux-native, container, vm; remote later) that compile Cedar fs.* grants into SBPL or bwrap/Landlock/seccomp rules, probe the platform, write the CA bundle and sentinel env, and fail closed."
related: ["[[Core Trait Contracts]]", "[[Seatbelt]]", "[[bubblewrap]]", "[[Landlock]]", "[[seccomp-bpf]]", "[[Filesystem Control and Rollback]]", "[[I2 Fail-Closed Launch]]", "[[Two-Tier Isolation Design]]", "[[M0 Contained Run]]", "[[Apple Virtualization Framework]]", "[[I1 No Secrets in the Sandbox]]", "[[I5 Config Outside Writable Mounts]]", "[[I8 No Flag Disables Isolation]]", "[[Topology-Forced Egress]]", "[[Netguard Ingress]]", "[[TLS Termination and Per-Session CA]]", "[[Broker CLI and Daemon]]", "[[MCP Guard]]", "[[Broker Cedar Schema]]", "[[Firecracker]]", "[[Cloud Hypervisor]]", "[[gVisor]]", "[[Container Runtimes and Escape History]]", "[[Claude Code and sandbox-runtime]]", "[[OpenAI Codex CLI]]", "[[Conformance Probe Matrix]]", "[[L4 Product Metrics]]", "[[SandboxEscapeBench]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md", "https://github.com/anthropic-experimental/sandbox-runtime", "https://landlock.io/rust-landlock/landlock/enum.ABI.html", "https://docs.kernel.org/userspace-api/landlock.html", "https://github.com/openai/codex/issues/215", "https://github.com/apple/containerization/issues/737", "https://learn.chatgpt.com/codex/sandboxing", "https://docs.docker.com/ai/sandboxes/architecture/", "https://github.com/apple/containerization"]
milestone: M0
code: ["code/crates/launcher/src/lib.rs", "code/crates/launcher/src/fs_compile.rs", "code/crates/launcher/src/shim.rs", "code/crates/launcher/src/backends/seatbelt/sbpl.rs", "code/crates/launcher/src/backends/linux/bwrap.rs", "code/crates/launcher/src/backends/linux/inner.rs"]
---

# Sandbox Launcher

> The launcher crate: SandboxBackend implementations (macos-seatbelt, linux-native, container, vm; remote later) that compile Cedar fs.* grants into SBPL or bwrap/Landlock/seccomp rules, probe the platform, write the CA bundle and sentinel env, and fail closed.

## Responsibility

`crates/launcher` with `backends/{seatbelt,linux,container,vm}` implements `SandboxBackend` ([[Core Trait Contracts]]). Given a `SandboxSpec` from `brokerd`, it creates the process-isolation boundary (trust boundary TB2) and the network topology that makes the broker the only way out (TB3). It is the kernel-backed half of the product: the design rule is "never to rely on one primitive. Pair a hard or OS-level boundary with an inner Landlock or seccomp layer, and put the *policy* boundary (network plus credentials) in the broker" (report; [[Two-Tier Isolation Design]]).

**It must never:** launch with a required layer missing ([[I2 Fail-Closed Launch]]); copy host environment variables into the child ([[I1 No Secrets in the Sandbox]]); mount `docker.sock`, `$HOME`, or any host path outside the compiled grants; leave agent config, hooks, rc files or its own helpers writable ([[I5 Config Outside Writable Mounts]]); accept an option that removes a layer ([[I8 No Flag Disables Isolation]]); install the per-session CA into a host trust store.

## Inputs and outputs

- **Input:** `SandboxSpec { session, argv, cwd, env, fs, egress, ca_bundle }`; the spec's `fs` is compiled from Cedar `fs.read`/`fs.write` grants on `Dir`/`File` entities ([[Broker Cedar Schema]]) plus the mandatory lists below.
- **Output:** `SandboxHandle` (pid, wait and kill), a `BackendReport` from `probe()`, and filesystem-denial events forwarded to the recorder where the backend can observe them (the macOS system sandbox violation log, as srt uses; Landlock audit flags from ABI 7).

## Backends

| Backend | Tier | Milestone | Mechanism (from the record) |
|---|---|---|---|
| `macos-seatbelt` | standard | M0 | Generated SBPL via `sandbox-exec`: deny writes except the repo and tmp; deny reads of secret dirs; network only to the per-session broker localhost port; no Apple Events; no `trustd` ([[Seatbelt]]) |
| `linux-native` | standard | M0 | bubblewrap `--ro-bind / /`, repo bind, `.git/hooks` and `.git/config` read-only, agent config dirs read-only, `--unshare-user --unshare-pid --unshare-net`; seccomp (no new `AF_UNIX` after the bridge, no ptrace, bpf, raw sockets or keyctl); Landlock (FS plus TCP connect to the bridge port only); `PR_SET_NO_NEW_PRIVS` ([[bubblewrap]], [[seccomp-bpf]], [[Landlock]]) |
| `container` | packaging | phase 2 | Docker/Podman with the broker as the only egress; never the primary boundary ([[Container Runtimes and Escape History]]) |
| `vm` | hard | phase 2 | Apple Virtualization.framework per session on macOS ([[Apple Virtualization Framework]]); Cloud Hypervisor or Firecracker on Linux ([[Cloud Hypervisor]], [[Firecracker]]); gVisor Systrap in CI without KVM ([[gVisor]]); vsock-only egress |
| `remote` | gateway | phase 2 | Configures E2B, Vercel, Docker sbx egress to point at a broker gateway |

Codex's Linux pipeline confirms the standard-tier recipe in production: `--ro-bind / /`, writable roots, re-bound read-only `.git`, gitdir and `.codex`, `--unshare-user --unshare-pid --unshare-net`, `PR_SET_NO_NEW_PRIVS`, seccomp; in managed-proxy mode a TCP→UDS→TCP bridge, after which seccomp blocks new `AF_UNIX` sockets ([codex linux-sandbox](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)). srt removes the network namespace entirely and bridges through socat over Unix sockets ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).

## Filesystem compilation

**Proposal.** One resource model compiles to both platforms (research note 05, FS guard):

- **Default deny-read:** `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`, `~/.docker/config.json`, browser profiles, the keychain DB.
- **Default writable:** `${repo}`, `${tmp}` (or the CoW layer; see [[Filesystem Control and Rollback]]).
- **Mandatory deny-write (code, not config):** shell rc files, `.git/hooks`, `.git/config`, agent settings directories (`.claude/`, `.codex/`, `.cursor/`, `.vscode/`, `.idea/`), PATH directories, the broker install prefix and state directory. The report protects `.git/hooks` and `.git/config` rather than all of `.git` because hooks, `core.fsmonitor`, `core.sshCommand` and filter drivers become code execution in the user's next unsandboxed git command, while the agent still needs to commit locally.

Example compiled Seatbelt fragment (**Proposal; not compiled**; the only network rule is the form given in research note 01):

```scheme
(version 1)
(deny default)
(allow file-read*)
(deny file-read* (subpath "/Users/dev/.ssh") (subpath "/Users/dev/.aws"))
(allow file-write* (subpath "/Users/dev/src/web") (subpath "/private/tmp/broker-01J9ZK"))
(deny file-write* (subpath "/Users/dev/src/web/.git/hooks") (literal "/Users/dev/src/web/.git/config"))
(allow network-outbound (remote ip "localhost:54017"))
```

Linux path rules are literal: srt and Codex expand deny-globs into bind mounts at start, so files created after start that match a deny glob are not covered ([srt](https://github.com/anthropic-experimental/sandbox-runtime)). The linux backend therefore prefers directory-level rules plus Landlock over glob expansion.

## Environment and trust bundle

- `env` = allowlisted variables (for example `PATH`, `HOME`, `LANG`, `TERM`) + sentinels for every credential variable the agent profile expects + CA-bundle variables: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `PIP_CERT`, `CURL_CA_BUNDLE` and the npm `cafile`, all pointing at `spec.ca_bundle` (the per-session CA merged with public roots) ([[TLS Termination and Per-Session CA]]).
- Proxy variables (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`) point at the in-namespace listeners for tools that prefer explicit CONNECT; enforcement never depends on them ([[Topology-Forced Egress]]).
- The sandbox git config gets `url."https://github.com/".insteadOf "git@github.com:"` so SSH remotes become brokerable HTTPS ([[Git Smart-HTTP Adapter]]).

## Probe and launch

**Proposal.**

```rust
// linux-native probe (sketch; Proposal; not compiled)
fn probe(&self) -> anyhow::Result<BackendReport> {
    let abi = landlock_abi();                 // runtime probe; ABI 9 = Linux 7.1
    let userns = userns_allowed();            // Ubuntu 24.04+ AppArmor gate
    let bwrap = find_bwrap()?;                // pinned path, not first-on-PATH
    let seccomp = seccomp_supported();
    Ok(BackendReport { backend: "linux-native", landlock_abi: abi, userns_allowed: Some(userns), /* layers */ ..Default::default() })
}
```

`launch()` order: create the namespaces and bridge; apply seccomp and Landlock in the child pre-exec stage; verify (attempt a forbidden `connect` and a write to a deny-write path, both must fail); then `exec` the agent. Any failure kills the child and returns `Err`.

## State

Per-session only: the temp dir, the generated SBPL or bwrap argument vector, the handle. No persistent state; nothing is written outside the session temp dir and the broker state dir.

## Failure modes and fail-closed behaviour

- `bwrap` missing, userns blocked by AppArmor, seccomp unavailable, SBPL rejected: `Err` from `probe()` or `launch()`, no child ([[I2 Fail-Closed Launch]]).
- Landlock ABI below what the policy needs: required layers fail; only an org-signed bundle may mark Landlock best-effort, and the state is audited.
- Child dies during setup: session goes to `Closed` with `launch_refused`.
- On macOS, clients that ignore proxy variables simply fail, because nothing else is reachable; this "fails closed, which is acceptable for the MVP" (report).

## Security considerations

- Use a pinned `bwrap` path rather than "the first `bwrap` executable it finds on `PATH`" (Codex's behaviour, [Codex docs](https://learn.chatgpt.com/codex/sandboxing)), since PATH is attacker-influenced in some setups.
- TOCTOU: resolve and open repo paths once, then bind by file descriptor where possible; Landlock `FS_REFER` (ABI 2) controls cross-directory rename and link ([Landlock docs](https://docs.kernel.org/userspace-api/landlock.html)).
- Symlinks: never follow a symlink out of a writable root when computing binds (the DuneSlide class).
- Seatbelt: `allowAppleEvents` "removes code-execution isolation" and re-allowing `trustd` opens an exfiltration vector; both stay denied (srt). Go TLS verification needing `trustd` is a known compatibility cost.
- Seatbelt deprecation: `man sandbox-exec` on macOS 15.4 says "DEPRECATED" ([openai/codex#215](https://github.com/openai/codex/issues/215)) with no removal date; a VM fallback moves start time from <5 ms to ~800 ms in one project's measurement ([apple/containerization#737](https://github.com/apple/containerization/issues/737)). Keep the `vm` backend as the hedge ([[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]).

## Performance budget

Sandbox start ≤150 ms on native backends ([[L4 Product Metrics]]). Apple containerization VMs are "sub-second" and need macOS 26 and Apple silicon ([apple/containerization](https://github.com/apple/containerization)).

## Invariants upheld

[[I1 No Secrets in the Sandbox]] (env and deny-read), [[I2 Fail-Closed Launch]] (probe and verify), [[I5 Config Outside Writable Mounts]] (mandatory deny-write), [[I8 No Flag Disables Isolation]] (required layers from the backend, not options).

## Test plan

- Unit: SBPL and bwrap argument generation golden tests per policy fixture; mandatory deny list always present.
- Property: for random fs grants, the compiled policy never makes a mandatory deny path writable; generated SBPL parses.
- Fault injection: each required layer removed in turn ([[I2 Fail-Closed Launch]] test).
- Conformance: categories 5, 9 and 10 of [[Conformance Probe Matrix]] (raw TCP, UDP, ICMP, `docker.sock`, host localhost services, secret-path reads, symlink, hardlink and `..` traversal, rename TOCTOU); `cat ~/.ssh/id_ed25519` denied ([[M0 Contained Run]]).
- Boundary regression: SandboxEscapeBench difficulty 1–3 scenarios nested in VMs, 0 escapes ([[SandboxEscapeBench]]).
- E2E matrix: macOS 15/26, Ubuntu 22.04/24.04.

## Dependencies

`landlock` crate, `seccompiler` or libseccomp bindings, `nix`, the system `bwrap` binary, `sandbox-exec` on macOS; `hakoniwa` was the considered alternative ([[Tech Stack]]). Versions and maturity beyond `landlock` are unverified.

## How it connects

- implements:: [[Core Trait Contracts]]
- implements:: [[Two-Tier Isolation Design]]
- depends-on:: [[Seatbelt]]
- depends-on:: [[bubblewrap]]
- depends-on:: [[Landlock]]
- depends-on:: [[seccomp-bpf]]
- depends-on:: [[Filesystem Control and Rollback]]
- depends-on:: [[Apple Virtualization Framework]]
- example-of:: [[Topology-Forced Egress]]
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[SandboxEscapeBench]]
- delivered-by:: [[M0 Contained Run]]
- decided-by:: [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]
- decided-by:: [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]

## Implications for the build

- M0 ships `macos-seatbelt` and `linux-native` only; the trait already names `container` and `vm` so phase 2 adds backends without touching callers.
- The installer must handle Ubuntu's AppArmor userns restriction; `broker doctor` explains it.
- [[MCP Guard]] reuses the same backends for each MCP server principal, with a per-server spec.

## Open questions

- Landlock ABI 10 (UDP) and 11 are documented but the UDP series was still at v5 in June 2026; assume neither is in a released stable kernel ([[Open Questions and Unverified Claims]]).
- Kernel version for unprivileged overlayfs in a user namespace and APFS `clonefile` behaviour, needed for rollback mode, are unverified.
- Whether a Landlock-less kernel is supported at all (see [[I2 Fail-Closed Launch]]).
- How to confirm SBPL application from the parent on macOS.

## Sources

- https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md
- https://github.com/anthropic-experimental/sandbox-runtime
- https://landlock.io/rust-landlock/landlock/enum.ABI.html
- https://docs.kernel.org/userspace-api/landlock.html
- https://github.com/openai/codex/issues/215
- https://github.com/apple/containerization/issues/737
- https://learn.chatgpt.com/codex/sandboxing
- https://docs.docker.com/ai/sandboxes/architecture/
- https://github.com/apple/containerization
- Report: component diagram, `SandboxBackend` trait, platform table, `.git` and rollback Proposals, "Fail closed"; research notes 01 Q3, Q6, Q7 and 05 section 3.2.

## Implementation notes

- 2026-09-24: `SandboxSpec` gained `stdio` (the agent's fds, passed from the CLI), `tty_path`, `session_dir`, `shim` and `macos_keychain`; `SandboxHandle` carries the verified layer list and Linux placeholders. `CompiledFsPolicy` gained `deny_entry` (entries that may not be renamed) and `missing_protected`.
- 2026-09-24: Linux uses a private tmpfs `/tmp` and masks `$XDG_RUNTIME_DIR` (dbus, podman and other user sockets); secret directories are masked with read-only tmpfs and secret files with `/dev/null`. The Landlock read rules are an allowlist computed at start (every path except the denied subtrees), so a secret created later next to a denied path is unreadable.
- 2026-09-24: inside unprivileged Docker containers bwrap cannot mount a fresh procfs (`Can't mount proc on /newroot/proc`) because Docker masks `/proc` paths; the probe now runs bwrap with the same mounts as a launch so `broker doctor` reports this instead of `broker run` failing later. Tests ran with `--security-opt systempaths=unconfined`.

## Build log

- 2026-09-24: built `SandboxBackend` with `macos-seatbelt` and `linux-native`, the filesystem compiler, and the in-sandbox shim `broker-sandbox-shim` (`code/crates/launcher/`). Container and VM backends are phase-2 stubs that always refuse. The shim applies the inner layers (Linux: `PR_SET_NO_NEW_PRIVS`, bridge, Landlock, seccomp), verifies from inside that a canary read, protected-directory writes and direct connects fail (EPERM/EACCES/ENETUNREACH count, a refused connection from a peer does not), writes a status line to brokerd on fd 3 and only then execs the agent. Every fd above 3 is closed before exec. Tests: SBPL and bwrap golden tests, `mandatory_never_writable` property test, `i2_launch_refuses_when_any_layer_is_missing` (fault injection for every layer, `BROKER_FAULT_INJECT`, which can only cause refusals), `i2_missing_shim_refuses_launch`, conformance categories 5, 9 and 10 on macOS 26 and Linux 6.12.
- 2026-09-24: deviations recorded in [[ADR-016 macOS M0 Compatibility Exceptions]], [[ADR-017 Landlock Filesystem Layer Required]], [[ADR-018 seccomp Filter Shape for M0]] and [[ADR-019 Mandatory Deny-Write List Additions]].
