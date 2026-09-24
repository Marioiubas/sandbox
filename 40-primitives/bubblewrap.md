---
title: "bubblewrap"
aliases: ["bwrap", "Ubuntu AppArmor Userns Restriction"]
type: "primitive"
section: "primitives"
summary: "Namespace sandbox (bwrap) with --ro-bind / /, repo bind and --unshare-net so the sandbox has no network interface at all: the Linux standard tier and MCP wrapper used by srt and Codex; Ubuntu 24.04+ gates unprivileged userns via AppArmor."
tags: [sandbox/primitives, primitive, topic/isolation, topic/egress, topic/filesystem, platform/linux, platform/ci, control/iso, control/fs, control/egress, boundary/tb2, boundary/tb3, invariant/i2, invariant/i5, milestone/m0]
status: verified
confidence: high
milestone: M0
created: 2026-09-24
updated: 2026-09-24
related: ["[[seccomp-bpf]]", "[[Landlock]]", "[[Sandbox Launcher]]", "[[Two-Tier Isolation Design]]", "[[Topology-Forced Egress]]", "[[OpenAI Codex CLI]]", "[[Claude Code and sandbox-runtime]]", "[[Risk Register]]", "[[Filesystem Control and Rollback]]", "[[Threat Model Non-Goals]]", "[[Open Questions and Unverified Claims]]", "[[Git Smart-HTTP Adapter]]", "[[I2 Fail-Closed Launch]]", "[[I8 No Flag Disables Isolation]]", "[[I5 Config Outside Writable Mounts]]", "[[MCP Guard]]", "[[Tech Stack]]", "[[M0 Contained Run]]", "[[Conformance Probe Matrix]]"]
---

# bubblewrap

bubblewrap (`bwrap`) builds an unprivileged namespace sandbox: a read-only view of the host root, explicit writable binds, and, with `--unshare-net`, a network namespace that has **no interface at all**, so the only way out is a Unix socket to the broker. Anthropic's sandbox-runtime (srt) and OpenAI's Codex CLI both ship exactly this shape in 2026, which makes it the broker's Linux standard tier and the wrapper for local MCP servers. Its main platform hazard is Ubuntu 24.04+, which gates unprivileged user namespaces through AppArmor.

## Boundary and trusted computing base

- **Mechanism.** `bwrap` creates user, mount and PID namespaces (and optionally a fresh, empty network namespace), assembles a new root from bind mounts, then execs the target. Everything is enforced by the shared host kernel ([Codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)).
- **TCB.** The host kernel's namespace and mount code plus the syscalls left open by the [[seccomp-bpf]] filter. Kernel exploits are out of scope for this tier; they need the VM tier ([[Threat Model Non-Goals]]).
- **Start and overhead.** ~ms start, ~0 memory overhead (report primitive table).
- **Licence.** Believed LGPL-2.0+, **not verified** in the record ([[Open Questions and Unverified Claims]]). The broker invokes the `bwrap` binary as a separate process rather than linking it, which keeps the Apache-2.0 endpoint clean either way.

## The production recipes the record documents

### OpenAI Codex CLI (codex-rs/linux-sandbox)

Source for this list: [Codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md).

- `--ro-bind / /`, then `--bind` for each writable root.
- Protected subpaths re-bound read-only: `.git`, the resolved `gitdir:` target, and `.codex`. Missing or symlinked components are masked by mounting `/dev/null`.
- Narrower rules override broader ones (deny `/repo/a` while `/repo` and `/repo/a/b` stay writable).
- `--unshare-user --unshare-pid`, plus `--unshare-net` when network is restricted.
- `PR_SET_NO_NEW_PRIVS` plus an in-process seccomp network filter.
- Managed-proxy mode: a TCP→UDS→TCP bridge is created, then seccomp blocks new `AF_UNIX` sockets and `socketpair`, so the command cannot create other UDS channels.
- Landlock is a legacy fallback (`features.use_legacy_landlock`); WSL1 is rejected.
- Codex uses "the first `bwrap` executable it finds on `PATH`", falling back to a bundled helper, and notes AppArmor configuration may be needed on Ubuntu 24.04+ ([Codex docs](https://learn.chatgpt.com/codex/sandboxing)).

### Anthropic sandbox-runtime (srt)

Source: [srt](https://github.com/anthropic-experimental/sandbox-runtime) (Apache-2.0, "Beta Research Preview", v0.0.64 on 7 Jul 2026).

- bubblewrap applies bind-mount filesystem rules; the network namespace "is removed entirely"; traffic reaches the host HTTP and SOCKS5 proxies only "via the filesystem over Unix domain sockets" using **socat** bridges.
- A prebuilt static `apply-seccomp` blocks new `AF_UNIX` socket creation via "a nested user+PID+mount namespace"; x64 and arm64 only.
- Linux filesystem rules take **literal paths only** (no globs); dependencies are bwrap, socat and ripgrep.
- Writes are denied by default (`allowWrite`, then `denyWrite` overrides); reads are allowed by default (`denyRead`, then `allowRead` overrides); `.bashrc`, `.zshrc`, `.gitconfig`, `.vscode/`, `.idea/`, `.claude/` are always write-denied; ripgrep scans for such files to `mandatoryDenySearchDepth` (default 3).
- `enableWeakerNestedSandbox` (for running inside unprivileged Docker) "considerably weakens security".

## The broker's Linux standard-tier recipe

**Proposal** (the report's Linux-laptop row, made concrete). Flags marked † are standard bwrap options not cited in the record; confirm against `bwrap --help` for the pinned version.

```text
bwrap
  --unshare-user --unshare-pid --unshare-net        # empty netns: no interface at all
  --ro-bind / /                                     # read-only host root
  --bind  $REPO $REPO                               # writable repo (or overlay upper dir)
  --ro-bind $REPO/.git/hooks  $REPO/.git/hooks      # hooks become code in the next unsandboxed git
  --ro-bind $REPO/.git/config $REPO/.git/config     # core.fsmonitor, core.sshCommand, filters
  --ro-bind <agent config dirs> ...                 # .claude/, .codex/, .cursor/, .vscode/
  --tmpfs ~/.ssh --tmpfs ~/.aws --tmpfs ~/.config/gh   # † hide secret dirs (deny-read)
  --bind $SESSION_DIR/egress.sock /run/broker/egress.sock  # the only way out
  --proc /proc --dev /dev --new-session --die-with-parent  # †
  -- /broker-shim  <seccomp + Landlock + PR_SET_NO_NEW_PRIVS, then exec agent>
```

Layering inside the sandbox, in order: set `PR_SET_NO_NEW_PRIVS`; restrict with [[Landlock]] (filesystem plus TCP connect only to the bridge port); start the in-namespace bridge listener; then load the [[seccomp-bpf]] filter that forbids new `AF_UNIX` sockets, `ptrace`, `bpf`, raw sockets and `keyctl`; then exec the agent. This mirrors the Codex order (bridge first, then seccomp) ([Codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)).

Protect `.git/hooks` and `.git/config` rather than all of `.git`: hooks, `core.fsmonitor`, `core.sshCommand` and filter drivers become code execution in the user's next *unsandboxed* git command, while the agent still needs to commit; the broker performs the push (report Proposal; see [[Git Smart-HTTP Adapter]]).

## Sharp edges

- **Ubuntu AppArmor userns gate (alias: Ubuntu AppArmor Userns Restriction).** Ubuntu 24.04+ restricts unprivileged user namespaces via `kernel.apparmor_restrict_unprivileged_userns`; bwrap-based sandboxes fail unless the sysctl is relaxed or an AppArmor profile grants `userns` ([srt](https://github.com/anthropic-experimental/sandbox-runtime); [dfaerch/bubblewrap-on-ubuntu](https://github.com/dfaerch/bubblewrap-on-ubuntu); [microsoft/vscode#316046](https://github.com/microsoft/vscode/issues/316046)). **Proposal:** the installer ships an AppArmor profile scoped to the broker's pinned `bwrap` path rather than flipping the global sysctl, and `broker doctor` reports the state.
- **Literal paths and the deny-glob hole.** Both srt and Codex expand deny-globs into literal bind mounts with ripgrep at start; files created *after* start that match a deny glob are not covered on Linux (research-note inference). See [[Filesystem Control and Rollback]].
- **Nested inside unprivileged containers** only works with srt's weakened mode; the broker should refuse rather than weaken ([[I2 Fail-Closed Launch]], [[I8 No Flag Disables Isolation]]).
- **Kernel exploits** are not covered; that is the VM tier's job.
- **Which `bwrap`.** Taking the first `bwrap` on `PATH` (Codex) lets a writable `PATH` directory substitute the sandbox binary. **Proposal:** resolve `bwrap` to an absolute, root-owned path at install time and verify its hash before each launch ([[I5 Config Outside Writable Mounts]]).

## Verdict for the broker

**Proposal.**

- **Use it for:** the Linux laptop default; the Linux standard tier inside CI runner VMs; the per-server wrapper for local stdio MCP servers ([[MCP Guard]]).
- **Don't use it for:** kernel-exploit resistance; Ubuntu 24.04+ without the installer's AppArmor step; nesting inside unprivileged Docker in a weakened mode.
- **How we integrate it.** The `linux-native` backend of `SandboxBackend` in [[Sandbox Launcher]] (`crates/launcher/backends/linux`) invokes the pinned `bwrap` binary via `std::process::Command` with arguments generated from the compiled Cedar `fs.*` grants, plus a small in-sandbox shim that applies Landlock (`landlock` crate) and seccomp (`seccompiler` or libseccomp bindings) before exec ([[Tech Stack]]). The `hakoniwa` Rust sandbox library ([lib.rs](https://lib.rs/crates/hakoniwa)) is the considered alternative; the record prefers the proven srt/Codex pipeline. `probe()` must detect: userns availability and the AppArmor gate, `bwrap` presence and hash, Landlock ABI, and seccomp support; any failure refuses launch.

## How it connects

- part-of:: [[Two-Tier Isolation Design]] (Linux standard tier)
- depends-on:: [[seccomp-bpf]] (no new AF_UNIX after the bridge)
- depends-on:: [[Landlock]] (inner FS and TCP-port layer)
- implements:: [[Topology-Forced Egress]] (empty netns plus UDS)
- depends-on:: [[Filesystem Control and Rollback]] (bind layout, protected subpaths)
- delivered-by:: [[Sandbox Launcher]] (`linux-native` backend)
- example-of:: [[OpenAI Codex CLI]] (codex-rs linux-sandbox pipeline)
- example-of:: [[Claude Code and sandbox-runtime]] (srt bwrap plus socat)
- mitigated-by:: [[Risk Register]] (Ubuntu AppArmor gate, Linux platform variance)
- delivered-by:: [[M0 Contained Run]]

## Implications for the build

- M0 acceptance runs on Ubuntu 22.04 and 24.04; the 24.04 leg exercises the AppArmor path ([[M0 Contained Run]]).
- Tests: disable userns, remove `bwrap`, or corrupt its hash; `broker run` must exit non-zero ([[I2 Fail-Closed Launch]]). Reading `~/.ssh/id_ed25519` from inside must fail.
- Conformance categories 5, 9 and 10 exercise this backend ([[Conformance Probe Matrix]]).

## Open questions

- bubblewrap licence (believed LGPL-2.0+) is unverified ([[Open Questions and Unverified Claims]]).
- Minimum kernel for unprivileged overlayfs inside the user namespace, if the CoW rollback mode is used, is unverified.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.

## Implementation notes

- 2026-09-24: measured on Linux 6.12 (Docker Desktop, Ubuntu 24.04 userland, aarch64): bwrap 0.9 builds the sandbox; inside unprivileged containers a fresh procfs cannot be mounted unless Docker's `/proc` masks are removed (`systempaths=unconfined`).

## Build log

- 2026-09-24: the `linux-native` backend is built on bwrap ([[Sandbox Launcher]]); recipe as proposed plus `--unshare-ipc --unshare-uts --unshare-cgroup-try --cap-drop ALL`, a private tmpfs `/tmp`, a masked `$XDG_RUNTIME_DIR`, and `.git` bound onto itself. The installer AppArmor profile is `code/packaging/apparmor/broker-bwrap` (grants `userns` to `/usr/bin/bwrap` only).
- 2026-09-24: GitHub's Ubuntu 22.04 runner exposes `kernel.apparmor_restrict_unprivileged_userns` but with value 0; its AppArmor 3.x has no `abi/4.0`, so the broker profile cannot load there (and is not needed). Ubuntu 24.04 runners work with the profile. CI installs the profile only when the gate is 1.
