---
title: "Landlock"
aliases: ["Landlock LSM"]
type: "primitive"
section: "primitives"
summary: "Unprivileged, stackable LSM for filesystem paths and (ABI 4+) TCP ports; ABI 9 on Linux 7.1, UDP (ABI 10/11) not yet in a released stable kernel; the inner layer on every Linux agent and MCP process, probed at runtime."
tags: [sandbox/primitives, primitive, topic/isolation, topic/filesystem, topic/egress, platform/linux, control/iso, control/fs, boundary/tb2, invariant/i5, milestone/m0, evidence/conflict]
status: verified
confidence: medium
milestone: M0
created: 2026-09-24
updated: 2026-09-24
related: ["[[bubblewrap]]", "[[seccomp-bpf]]", "[[Sandbox Launcher]]", "[[Filesystem Control and Rollback]]", "[[Core Trait Contracts]]", "[[Topology-Forced Egress]]", "[[Open Questions and Unverified Claims]]", "[[Tech Stack]]"]
---

# Landlock

Landlock is an unprivileged, stackable Linux security module that lets any process restrict its own (and its descendants') access to filesystem paths and, from ABI 4, to TCP ports for bind and connect. ABI 9 shipped with Linux 7.1; ABI 10 (UDP) and ABI 11 are documented on kernel.org but should be assumed absent from released stable kernels. The broker applies Landlock as the inner layer on every Linux agent and MCP process, probing the ABI at runtime and degrading only in ways that keep the outer bwrap boundary intact.

## Mechanism and boundary

- A process builds a **ruleset** declaring which access rights it wants to handle, adds rules granting rights beneath specific file hierarchies (or to specific ports), then calls `landlock_restrict_self`. Everything not granted among the handled rights is denied, for the calling thread and all future children ([kernel.org Landlock docs](https://docs.kernel.org/userspace-api/landlock.html)).
- **Unprivileged and stackable.** No root or user namespace is required (unlike bwrap), so it survives the Ubuntu 24.04 AppArmor userns restriction (research-note inference). Up to **16** layers can be stacked ([kernel.org](https://docs.kernel.org/userspace-api/landlock.html)).
- **TCB.** The in-kernel LSM hooks; overhead is µs-scale (report primitive table).
- **Limitations** ([kernel.org](https://docs.kernel.org/userspace-api/landlock.html)): sandboxed threads cannot change mount topology (no mount or `pivot_root`); pipes and sockets cannot be restricted by path; `IOCTL_DEV` applies only to newly opened device files.

## ABI to kernel mapping and features

| ABI | Kernel | Adds |
|---|---|---|
| 1 | 5.13 | base filesystem access rights |
| 2 | 5.19 | `FS_REFER` (rename and link across directories) |
| 3 | 6.2 | `FS_TRUNCATE` |
| **4** | **6.7** | **`NET_BIND_TCP`, `NET_CONNECT_TCP`** (TCP port-based only) |
| 5 | 6.10 | `FS_IOCTL_DEV` |
| 6 | 6.12 | `SCOPE_ABSTRACT_UNIX_SOCKET`, `SCOPE_SIGNAL` |
| 7 | 6.15 | audit logging flags |
| 8 | 7.0 | `RESTRICT_SELF_TSYNC` (all threads) |
| 9 | 7.1 | `FS_RESOLVE_UNIX` (pathname UNIX sockets) |
| 10 | documented, unreleased | UDP bind and connect/send |
| 11 | documented, unreleased | `RESTRICT_SELF_NO_NEW_PRIVS` flag |

Kernel mapping from [rust-landlock ABI enum](https://landlock.io/rust-landlock/landlock/enum.ABI.html); feature list from [kernel.org](https://docs.kernel.org/userspace-api/landlock.html).

> [!warning] Conflict
> kernel.org describes ABI 10 (UDP) and ABI 11, but the UDP patch series was still at v5 on the LSM list in June 2026 ([LSM list](https://ratatoskr.run/linux-security-module/2026/06/17121634/t)) and rust-landlock lists only up to V9 = 7.1 ([rust-landlock](https://landlock.io/rust-landlock/landlock/enum.ABI.html)). Assume neither ABI 10 nor 11 is in a released stable kernel; they are likely 7.2/7.3-cycle work. Probe at runtime ([[Open Questions and Unverified Claims]]).

Practical consequence for the fleet (background knowledge, not in the record): Ubuntu 22.04 and 24.04 LTS ship 5.x and 6.x kernels, far below 7.x, so many machines will run an ABI below 9 and some below 4, where the TCP-port rules are missing. The exact ABI per distro kernel is not in the record, which is why the runtime probe is mandatory.

## What Landlock can and cannot express for the broker

| Need | Landlock? |
|---|---|
| Deny reads of `~/.ssh`, `~/.aws`, `~/.config/gh` | Yes: grant read only beneath allowed hierarchies (allowlist semantics) |
| Writable repo, read-only `.git/hooks` and `.git/config` | Yes, with care: rights are granted per hierarchy, so the repo root gets write and the protected files must be excluded by structuring grants (outer bwrap read-only re-binds remain the primary control) |
| Block cross-directory rename/link tricks | `FS_REFER` (ABI 2) |
| Only TCP connect to the bridge port | `NET_CONNECT_TCP` (ABI 4+) |
| Hostname-level egress policy | **No**: ports only; hostnames are the broker's job |
| Block UDP (DNS, QUIC) | **No** before ABI 10; rely on the empty netns and seccomp |
| Restrict abstract UNIX sockets to the domain | `SCOPE_ABSTRACT_UNIX_SOCKET` (ABI 6+) |
| Restrict connecting to pathname UNIX sockets | `FS_RESOLVE_UNIX` (ABI 9+) |
| Files created after start matching a deny glob | Partly: allowlist semantics avoid the deny-glob hole for reads, because nothing outside granted hierarchies is readable regardless of creation time |

The last row is the reason Landlock is valuable beyond defence in depth: srt and Codex expand deny-globs into literal bind mounts at start, so files created later are uncovered on Linux, a hole the research notes suggest closing with Landlock (research-note inference; see [[Filesystem Control and Rollback]]).

## Who ships it

- Codex CLI keeps Landlock only as a legacy fallback (`features.use_legacy_landlock`), preferring bwrap ([Codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)).
- NVIDIA OpenShell containers use seccomp and Landlock ([NVIDIA OpenShell](https://github.com/NVIDIA/openshell)); agentjail uses Landlock on Linux ([agentjail docs](https://agentjail.io/docs/concepts/sandbox/)).
- A January 2026 guide shows seccomp plus Landlock sandboxing of Rust binaries without root ([OneUptime](https://oneuptime.com/blog/post/2026-01-07-rust-sandboxing-seccomp-landlock/view)).

## Verdict for the broker

**Proposal.**

- **Use it for:** the inner layer on every Linux agent process and every MCP server process, inside bwrap; filesystem allowlists compiled from Cedar `fs.*` grants; TCP connect restricted to the bridge port when ABI ≥4.
- **Don't use it for:** hostname egress policy; UDP or DNS control before ABI 10; mount-topology enforcement; the sole boundary against kernel exploits.
- **How we integrate it.** The `landlock` crate (rust-landlock), one of the two crates the record treats as verified ([crates.io](https://crates.io/crates/landlock); [[Tech Stack]]):
  - build the ruleset with the crate's best-effort compatibility mode so rights unknown to the running kernel are dropped, but **record the effective ABI and the dropped rights** in `BackendReport` and the session audit event;
  - **fail closed** when the probe reports no Landlock at all *and* policy marks Landlock as required (org ceiling); otherwise run with bwrap + seccomp and surface the degraded state in `broker doctor`;
  - apply it in the in-sandbox shim after `PR_SET_NO_NEW_PRIVS` and before loading seccomp;
  - never rely on ABI 10/11 until a released kernel is verified on the CI matrix.

## How it connects

- depends-on:: [[bubblewrap]] (outer namespace boundary)
- depends-on:: [[seccomp-bpf]] (covers what Landlock cannot: UDP, AF_UNIX creation, ptrace)
- delivered-by:: [[Sandbox Launcher]] (`linux-native` backend, `probe()` reports the ABI)
- depends-on:: [[Core Trait Contracts]] (`BackendReport` carries the Landlock ABI)
- part-of:: [[Filesystem Control and Rollback]] (allowlist FS layer)
- part-of:: [[Topology-Forced Egress]] (TCP connect only to the bridge port)

## Implications for the build

- Add a CI matrix leg per representative kernel (at least one <6.7 and one ≥6.7) so both the port-rule and no-port-rule paths are tested.
- Conformance category 10 (filesystem) must pass with Landlock disabled too, proving bwrap alone still denies secret reads; then again with Landlock on.
- `broker doctor` prints the Landlock ABI and which rights were dropped.

## Open questions

- ABI 10/11 kernel release is unconfirmed ([[Open Questions and Unverified Claims]]).
- The effective ABI on Ubuntu 22.04/24.04 GA and HWE kernels is not in the record; measure on CI.
- `landlock` crate version pinning is to be verified at M0.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
