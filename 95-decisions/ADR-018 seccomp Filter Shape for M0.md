---
title: "ADR-018 seccomp Filter Shape for M0"
aliases: ["ADR-018"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/isolation, platform/linux, control/iso, control/egress, boundary/tb2, boundary/tb3, invariant/i2, milestone/m0]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Deny new AF_UNIX, packet and raw sockets, ptrace, bpf, keyctl, mount and namespace calls as proposed, and additionally io_uring, clone3 (ENOSYS), x32 syscalls and TIOCSTI; allow socketpair(AF_UNIX) and AF_NETLINK, which cannot reach anything outside an empty network namespace."
related: ["[[seccomp-bpf]]", "[[Sandbox Launcher]]", "[[Broker CLI and Daemon]]", "[[I2 Fail-Closed Launch]]", "[[Topology-Forced Egress]]", "[[MOC Decisions]]"]
sources: []
superseded_by:
code: ["code/crates/launcher/src/backends/linux/inner.rs"]
---

# ADR-018 seccomp Filter Shape for M0

> Keep the proposed denials, add the io_uring, clone3, x32 and TIOCSTI closures, and allow socketpair(AF_UNIX) and AF_NETLINK.

## Status

Built (2026-09-24).

## Context

The [[seccomp-bpf]] note's filter table (Proposal) denies `socket(AF_UNIX)` **and** `socketpair(AF_UNIX)` after the bridge, raw and packet sockets, `ptrace`, `bpf`, `keyctl` and mount/namespace calls, and leaves `AF_NETLINK` "to decide empirically". Three facts matter:

1. `socketpair()` returns two connected, anonymous sockets; it cannot connect to `ctl.sock`, `docker.sock` or any other named socket, which is the threat the `AF_UNIX` rule addresses. libuv (Node.js) creates child-process stdio pipes with `socketpair(AF_UNIX)`, so denying it would break Claude Code and every Node-based agent that spawns a shell.
2. Inside an empty network namespace, netlink route sockets see only the namespace's own loopback; `getifaddrs()` needs them.
3. Three well-known seccomp bypass classes are not in the table: `io_uring` can create sockets without the `socket` syscall; `clone3` passes flags in memory a filter cannot read; on x86_64 the x32 ABI uses different syscall numbers.

## Decision

The filter installed by the shim (after the bridge exists, after Landlock) returns `EPERM` for: `socket(AF_UNIX, …)`, `socket(AF_PACKET, …)`, `SOCK_RAW` on `AF_INET`/`AF_INET6`, `ptrace`, `process_vm_readv/writev`, `bpf`, `perf_event_open`, `keyctl`, `add_key`, `request_key`, `mount`, `umount2`, `pivot_root`, `unshare`, `setns`, `clone` with any namespace flag, `io_uring_setup/enter/register`, `open_by_handle_at`, `kexec_load`, module loading, `userfaultfd`, `fanotify_init`, and `ioctl(TIOCSTI|TIOCLINUX)`. `clone3` returns `ENOSYS` so libc falls back to `clone`. On x86_64 a second filter returns `ENOSYS` for any x32 syscall number. Architectures other than x86_64 and aarch64 refuse launch. `socketpair(AF_UNIX)` and `AF_NETLINK` are allowed.

**Testable as:** the shim verifies `socket(AF_UNIX)` returns `EPERM` before exec; conformance category 9 (`ctl.sock` and a host `docker.sock` stand-in unreachable, host services receive nothing).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Deny `socketpair(AF_UNIX)` as proposed | Breaks Node child processes (libuv stdio) without closing any path to a named socket |
| Deny `AF_NETLINK` | Breaks `getifaddrs()`; nothing to reach in an empty netns |
| Default-deny allowlist filter | Needs per-agent syscall profiling across the agent × OS matrix; revisit at M4 |

## Consequences

Sandboxed processes can still pass file descriptors among themselves over socketpairs. The filter is allow-by-default and must be reviewed each kernel cycle for new syscalls that open equivalent capabilities.

## Invariants affected

Upholds [[I2 Fail-Closed Launch]] (seccomp is required and verified) and the TB3 property that the sandbox can never reach `ctl.sock`.

## Relationships

- motivated-by:: [[seccomp-bpf]]

## Build log

- 2026-09-24: created and built; verified from inside the sandbox on Linux 6.12 (aarch64): `Seccomp: 2`, `socket(AF_UNIX)` = `EPERM`.
