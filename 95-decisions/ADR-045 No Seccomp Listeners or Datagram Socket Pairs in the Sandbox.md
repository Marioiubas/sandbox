---
title: "ADR-045 No Seccomp Listeners or Datagram Socket Pairs in the Sandbox"
aliases: ["ADR-045"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/sandbox, invariant/i2, milestone/m4, platform/linux]
status: built
confidence: medium
created: 2026-10-03
updated: 2026-10-03
summary: "Inside a Linux session, seccomp(SECCOMP_SET_MODE_FILTER) with NEW_LISTENER and socketpair(AF_UNIX, SOCK_DGRAM) are refused with ERRNO(EPERM) by a filter installed after the shim's own listener, which no USER_NOTIF filter can outrank: with ADR-043's deny filter returning USER_NOTIF, an agent's newer filter with its own listener would otherwise take over the deny filter's notifications (and answer CONTINUE) once brokerd's listener is gone; and a datagram socket from a pair could sendto() named host sockets the read-only root shows (journald, syslog)."
related: ["[[ADR-043 Seccomp Denials Recorded via User Notification]]", "[[ADR-018 seccomp Filter Shape for M0]]", "[[seccomp-bpf]]", "[[Sandbox Launcher]]", "[[I2 Fail-Closed Launch]]", "[[MOC Decisions]]"]
sources: ["https://man7.org/linux/man-pages/man2/seccomp.2.html", "https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html", "https://man7.org/linux/man-pages/man7/unix.7.html"]
superseded_by: 
---

# ADR-045 No Seccomp Listeners or Datagram Socket Pairs in the Sandbox

> Two refusals that no other filter can outrank: no seccomp listener of the agent's own, no datagram socket pair.

## Status

built (2026-10-03, M4). Found by an adversarial review of [[ADR-043 Seccomp Denials Recorded via User Notification]].

## Context

1. **Listener precedence.** ADR-043 turned the deny filter's match action from `ERRNO(EPERM)` into `USER_NOTIF`. The kernel runs every filter and takes the most restrictive action; between filters returning the same action the most recently installed one wins ([seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html), `seccomp_run_filters`). Before ADR-043 an agent's own `USER_NOTIF` filter lost to our `ERRNO`; after it, an agent's newer `USER_NOTIF` filter with its own listener would win the tie, and its supervisor could answer `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, running a syscall the deny filter refuses. The kernel's one-listener-per-filter-chain rule (`EBUSY`) prevents this only while brokerd's listener is open; teardown, a transient error in the serving loop or a crash of brokerd closes it.
2. **Datagram socket pairs.** [[ADR-018 seccomp Filter Shape for M0]] refuses every new `AF_UNIX` socket but allows `socketpair(AF_UNIX, …)` (Node's `child_process`). A connected `AF_UNIX` datagram socket can still `sendto()` a named address ([unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html)), and the Linux sandbox shows the host root read-only, so named datagram sockets such as journald's (`/run/systemd/journal/socket`, `dev-log`) are reachable: at least log injection into the host journal. Stream pairs cannot connect elsewhere (already connected).

## Decision

A third filter, `fixed_filter()` in `code/crates/launcher/src/backends/linux/inner/seccomp.rs`, returns `ERRNO(EPERM)` for:

- `seccomp(SECCOMP_SET_MODE_FILTER, flags & SECCOMP_FILTER_FLAG_NEW_LISTENER)`: no process in the sandbox creates a listener;
- `socketpair(AF_UNIX, type & 0xf == SOCK_DGRAM)`.

It is installed after the deny filter (whichever form went in), because the shim itself needs `NEW_LISTENER` for ADR-043's listener; installing it is a `seccomp()` call, which the deny filter does not notify. `ERRNO` outranks `USER_NOTIF`, so neither our notify filter nor anything the agent installs later can override these refusals, and the agent can never hold a listener whether or not brokerd's is open.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep brokerd's listener open until every sandboxed process is gone | Narrows the window but still depends on brokerd's health (a crash reopens it); the refusal does not. |
| Revert ADR-043 to `ERRNO` | Gives up recording refused syscalls; the refusal above closes the gap without that. |
| Refuse all `socketpair` | Breaks Node's `child_process` (ADR-018); stream pairs cannot reach named sockets. |
| Mask `/run` in the bwrap mount | Would hide the sockets known today but not others under the read-only root; the refusal covers every path. |

## Consequences

- Tools inside the sandbox cannot use seccomp user notification (container runtimes, some sandboxers) or `AF_UNIX` datagram socket pairs; both now fail with EPERM. Neither is used by the coding agents in scope.
- An agent can still stack its own `ERRNO` filter to keep its refused calls off the record (silencing, not bypass; ADR-043).

## Invariants affected

Strengthens I2 (a layer no longer depends on brokerd staying up). Weakens none: both are narrowings.

## Tests

`inner::seccomp::tests::controls_keep_their_action` (the precedence interpreter: both refusals are `ERRNO(EPERM)` in every filter set, served or not; `seccomp(SET_MODE_FILTER, 0)` and `SOCK_SEQPACKET` pairs stay allowed; upper register bits ignored), `inner::notify::tests::*` (real kernel on the Linux CI runners, with the fixed filter installed after the listener).

## Relationships

- decided-by:: adversarial review (2026-10-03)
- narrows:: [[ADR-018 seccomp Filter Shape for M0]]
- extends:: [[ADR-043 Seccomp Denials Recorded via User Notification]]
