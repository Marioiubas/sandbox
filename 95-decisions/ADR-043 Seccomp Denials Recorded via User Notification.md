---
title: "ADR-043 Seccomp Denials Recorded via User Notification"
aliases: ["ADR-043"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/audit, topic/isolation, platform/linux, control/iso, boundary/tb2, invariant/i2, invariant/i9, milestone/m4]
status: built
confidence: medium
created: 2026-10-01
updated: 2026-10-03
summary: "On Linux the seccomp deny filter of ADR-018 returns SECCOMP_RET_USER_NOTIF (the same program, only the match return patched); the shim hands the listener to brokerd over an inherited socketpair end and closes both before exec; brokerd answers every notification -EPERM, never CONTINUE, and writes an attributed `kernel.denied` row (layer `seccomp`, syscall, plain register arguments). With the listener closed the kernel answers ENOSYS, so the shim's check fails and the launch is refused. Old kernels keep the EPERM filter, unrecorded."
related: ["[[ADR-041 Kernel Denials on the Audit Record]]", "[[ADR-018 seccomp Filter Shape for M0]]", "[[seccomp-bpf]]", "[[Sandbox Launcher]]", "[[I2 Fail-Closed Launch]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[Audit Recorder and Event Schema]]", "[[Open Questions and Unverified Claims]]", "[[MOC Decisions]]", "[[ADR-045 No Seccomp Listeners or Datagram Socket Pairs in the Sandbox]]"]
sources: ["https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html", "https://man7.org/linux/man-pages/man2/seccomp.2.html", "https://docs.kernel.org/userspace-api/seccomp_filter.html", "https://github.com/torvalds/linux/blob/master/kernel/seccomp.c"]
superseded_by: 
code: ["code/crates/launcher/src/backends/linux/inner/seccomp.rs", "code/crates/launcher/src/backends/linux/inner/notify.rs", "code/crates/launcher/src/backends/linux/inner/syscalls.rs", "code/crates/launcher/src/backends/linux/inner.rs", "code/crates/launcher/src/shim.rs", "code/crates/launcher/src/backends/mod.rs", "code/crates/brokerd/src/kernel_denials/seccomp.rs", "code/tests/conformance/tests/m4_kernel_denials.rs"]
---

# ADR-043 Seccomp Denials Recorded via User Notification

> The syscalls the Linux seccomp layer refuses reach brokerd as user notifications; brokerd always answers EPERM and puts each one on the session's audit chain. Enforcement never waits on the record and never depends on brokerd reading the caller's memory.

## Status

built (2026-10-01, M4), Linux only. macOS is unchanged ([[ADR-041 Kernel Denials on the Audit Record]]).

## Context

[[ADR-041 Kernel Denials on the Audit Record]] put macOS kernel denials on the session's record and left Linux as a residual: Landlock records and `SECCOMP_RET_LOG` / `SECCOMP_FILTER_FLAG_LOG` go to the kernel audit subsystem, which an unprivileged daemon cannot read. `SECCOMP_RET_USER_NOTIF` is the one unprivileged channel for seccomp: a filter installed with `SECCOMP_FILTER_FLAG_NEW_LISTENER` returns a listener descriptor (created `O_CLOEXEC`), and a process holding it receives each matching syscall's number and register arguments with `SECCOMP_IOCTL_NOTIF_RECV` and answers with `SECCOMP_IOCTL_NOTIF_SEND` ([seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html), Linux 5.0). Four kernel facts shape the design ([kernel/seccomp.c](https://github.com/torvalds/linux/blob/master/kernel/seccomp.c), [seccomp_filter.rst](https://docs.kernel.org/userspace-api/seccomp_filter.html)):

1. When the listener is closed, pending and later notified syscalls fail with `ENOSYS`; the kernel never runs them.
2. When filters stack, the most restrictive action wins (KILL > TRAP > ERRNO > USER_NOTIF > TRACE > LOG > ALLOW): an ERRNO rule for the same syscall would silence the notification.
3. One listener per filter chain: a second `NEW_LISTENER` on the chain fails with `EBUSY`.
4. `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (Linux 5.19) stops ordinary signals from interrupting a call whose notification the supervisor has received.

A supervisor that reads pointer arguments and then lets the call continue is open to time-of-check/time-of-use races ([seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html), "Caveats"). This design never lets a call continue and never reads through a pointer.

## Decision

1. **Same filter, different return.** The deny filter of [[ADR-018 seccomp Filter Shape for M0]] (new `AF_UNIX`, `AF_PACKET` and raw sockets, namespace flags on `clone`, `TIOCSTI`/`TIOCLINUX`, and 23 syscalls refused by number) is compiled once with `ERRNO(EPERM)`; the notify program is that program with every `RET ERRNO(EPERM)` instruction changed to `RET USER_NOTIF` and nothing else (`seccomp::to_user_notif`). All of its rules move, because every one is decided by the syscall number or plain register arguments (a filter cannot read through pointers). Kept as they are: `clone3` and x32 syscall numbers return `ENOSYS`, the architecture check kills, everything else is allowed.
2. **Never both.** When the kernel gives a listener the EPERM form is not installed (fact 2); when it does not (Linux < 5.0, or another listener already on the chain: `EBUSY`), the EPERM form goes in instead, byte for byte ADR-018's filter, and the optional layer `seccomp_notify` says the denials are not recorded. The required `seccomp` layer is unchanged either way.
3. **Order in the shim:** `PR_SET_NO_NEW_PRIVS` → bridge → Landlock → the `clone3` and x32 filters → the deny filter **last**, with `NEW_LISTENER` (and `WAIT_KILLABLE_RECV`, retried without it on `EINVAL`). Order changes no verdict (fact 2 is order-independent); it matters because a notified syscall by the shim while it still holds the listener would wait for itself, so the shim's next calls are only `sendmsg`, `close` and `fcntl`.
4. **The listener never reaches the agent.** The launcher opens a `socketpair(AF_UNIX)` per launch; the sandbox's end becomes the shim's fd 4 (like the status pipe on fd 3, every other descriptor is closed), connected before seccomp exists and with no name in any filesystem, so nothing inside the sandbox can reach brokerd's end. The shim sends the listener with `SCM_RIGHTS`, closes it and fd 4, and refuses the launch unless `fcntl(F_GETFD)` fails with `EBADF` for both, checked again just before exec. The bridge, forked before the listener exists, closes its copies of fds 3 and 4.
5. **brokerd takes exactly one descriptor** (one message, one tag byte, one `SCM_RIGHTS` descriptor, received `MSG_CMSG_CLOEXEC`; anything else is closed), checks it is a seccomp listener (`NOTIF_ID_VALID` for an unknown id answers `ENOENT`; where `/proc` is mounted, its `/proc/self/fd` link reads `anon_inode:seccomp notify`), then closes its end of the pair. Anything else is closed unserved, which fails the launch (point 8).
6. **Answers.** One thread per session handles one notification at a time: it zeroes the request buffer (sized from `SECCOMP_GET_NOTIF_SIZES`, never smaller than libc's `#[repr(C)]` structs, whose sizes 64/80/24 are asserted at compile time), receives, reads the caller's `comm` (advisory; `NOTIF_ID_VALID` afterwards proves it was that caller), answers `error = -EPERM, val = 0, flags = 0`, and only then queues the record. There is no code path that sends `SECCOMP_USER_NOTIF_FLAG_CONTINUE` or a success value. The answer is constant, so it depends on nothing the sandbox controls.
7. **Rows.** `kernel.denied`, reason `sandbox_denied`, detail `layer = "seccomp"`, `syscall`, `nr`, named plain arguments (for example `domain`, `type`, `protocol` for `socket`; `flags` for `clone` and `unshare`; `request` and `target_pid` for `ptrace`; 32-bit arguments masked to 32 bits), `process` and `pid` (host PID namespace); attributed with `AuditEvent::new(EventKind::KernelDenied).attributed_as(&attribution)` like every row of the session; deduplicated per process name, syscall and arguments (per pid for the shim's name `broker-sandbox-`, whose own check is flagged `launch_check`), at most 500 per session then one `suppressed` row, as on macOS. A full queue (4096) loses a record, never an answer.
8. **Fail closed.** The shim's existing check (`socket(AF_UNIX)` must fail with `EPERM`) is now a round trip through brokerd. If brokerd does not take the listener, the check gets `ENOSYS` and the launch is refused; if brokerd does not answer, the shim waits and `spawn_with_status` refuses the launch after 15 s; if the listener cannot be sent, the shim refuses at once. When the session ends (or brokerd stops serving, or dies) the listener closes and anything still running gets `ENOSYS` (fact 1). Fault `BROKER_FAULT_INJECT=seccomp_notify` makes brokerd close the listener unserved, to test this end to end.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| `SECCOMP_RET_LOG` or `SECCOMP_FILTER_FLAG_LOG` | Records go to the kernel audit subsystem; reading them needs audit enabled and `CAP_AUDIT_READ`, auditd or `CAP_SYSLOG`, which an unprivileged brokerd does not have ([[ADR-041 Kernel Denials on the Audit Record]]). `RET_LOG` would also allow the call. |
| `SECCOMP_RET_TRACE` with brokerd as ptracer | Takes the one tracer slot (the agent's debuggers and `strace` stop working), needs ptrace rights over the sandbox, and lets the tracer change the syscall: a far larger, racier surface than a constant answer. |
| `SECCOMP_RET_TRAP` (SIGSYS to the caller) | The report would come from inside the sandbox, from a process brokerd cannot trust. |
| Keep the EPERM filter and add a notify filter for the same rules | ERRNO outranks USER_NOTIF (fact 2): nothing would ever be notified. |
| A per-session listening socket in the session directory | The shim could reach it only if it were bound into the sandbox, and a name inside the sandbox is reachable by any process there that can still create a Unix socket (the bridge runs without seccomp). The inherited socketpair has no name at all, only ever one peer, and brokerd's end lives outside every mount. |
| Let brokerd decide per call (for example by the `connect` path) and `CONTINUE` | Pointer arguments can change between brokerd's read and the kernel's (TOCTOU, seccomp_unotify(2)); this ADR records, it does not widen. |
| Notify only some of ADR-018's rules | Each rule is decided by register values and is safe to notify; splitting them would leave two filters to keep in step for no gain. |

## Consequences

- Linux sessions now have a row for each distinct refused syscall, including routine noise (glibc's nscd lookup tries `socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK)` on every `getpw*`), filterable by `detail.syscall`. As on macOS, the cap and dedupe mean absence of rows proves nothing.
- **A hung brokerd blocks the agent** in a refused syscall until brokerd answers or the task is killed (with `WAIT_KILLABLE_RECV`, ordinary signals no longer interrupt it once brokerd has received the notification). A dead brokerd closes the listener (`ENOSYS`), and bwrap's `--die-with-parent` ends the sandbox anyway.
- **An agent can silence, not bypass, the record**: it may stack its own filter returning ERRNO, TRAP or KILL (or USER_NOTIF without a listener, which yields `ENOSYS`) for a syscall; those outrank or tie ours, so the call fails without a notification. Nothing it can install (ALLOW, LOG, TRACE) outranks USER_NOTIF, and it cannot add a listener of its own to the chain (fact 3).
- Each refused syscall costs a round trip to brokerd (two ioctls and a `/proc` read) instead of an in-kernel return.
- The errno while brokerd serves is EPERM, as before; after the listener is closed it is `ENOSYS`.
- `kernel.denied` rows stay out of OCSF export, learn mode, shadow mode and the harness's broker-deny counts ([[ADR-041 Kernel Denials on the Audit Record]]).
- **Residual:** Landlock and mount denials on Linux are still enforced but not on the broker's chain (Landlock ABI 7 sends the agent's to the host's audit log, ADR-041).

## Invariants affected

- [[I2 Fail-Closed Launch]]: upheld. The `seccomp` layer stays required and verified from inside; the verification now also proves brokerd serves the listener (EPERM), and a listener that cannot be sent, is not taken or is not answered refuses the launch (exit 125). No syscall the filter refuses can run with brokerd absent: the kernel answers `ENOSYS`. Kernels without user notification keep ADR-018's filter, which is not a regression.
- [[I9 Hash-Chained Audit Outside the Sandbox]]: strengthened. Seccomp denials are now decisions on the session's hash-chained record, attributed to user, groups, agent, agent hash, task and sandbox.
- I1 and I5: the channel carries one descriptor and no data, and has no filesystem name. I8: no flag changes any of this. Weakens none.

## Tests

- Filter construction, by a classic-BPF interpreter under the kernel's precedence rule: `launcher::backends::linux::inner::seccomp::tests::{notify_filter_differs_from_the_eperm_filter_only_in_its_match_action, no_syscall_becomes_allowed_with_or_without_brokerd, every_listed_syscall_is_refused, controls_keep_their_action, refusals_are_unchanged_for_any_registers}` (every syscall `denied_syscalls()` lists and every argument rule: EPERM served, ENOSYS unserved, EPERM with the fallback; over all syscall numbers 0..=470 and an argument grid, and a property test over random registers, the new sets refuse exactly what ADR-018's refused).
- Real kernel, forked children: `inner::notify::tests::{this_kernel_can_notify, unserved_listener_fails_every_refused_syscall_with_enosys, served_listener_answers_eperm_records_each_and_fails_closed_after, a_second_listener_falls_back_to_eperm_which_outranks_notify}`.
- `inner::syscalls::tests::{every_denied_syscall_has_a_name, describe_is_total}` (property test), `shim::tests::{fd_closed_tells_open_from_closed, older_specs_decode_without_the_notify_flag}`.
- brokerd: `kernel_denials::seccomp::tests::{rows_are_attributed_deduplicated_and_flag_the_shim, rows_are_capped_with_one_note, drain_records_until_the_feed_ends}`.
- End to end: `m4_kernel_denials::seccomp_denials_are_on_the_sessions_record` (`socket(AF_UNIX)`, `socket(AF_PACKET)`, `unshare(CLONE_NEWUSER)` and `ptrace` inside a session fail with EPERM and appear as attributed `seccomp` rows; the shim's check is on the record, flagged; `assert_attributed`, chain verifies) and `m4_kernel_denials::an_unserved_seccomp_listener_refuses_the_launch` (exit 125, `ENOSYS` in the refusal, no `session.ready`). Existing: `i2_launch_refuses_when_any_layer_is_missing`, `m0_categories` 5 and 9.

## Relationships

- decided-by:: M4 build
- extends:: [[ADR-041 Kernel Denials on the Audit Record]]
- refines:: [[ADR-018 seccomp Filter Shape for M0]]
- motivated-by:: [[I9 Hash-Chained Audit Outside the Sandbox]]

## Build log

- 2026-10-01: created and built (branch `seccomp-notify`, draft PR #1). Code: `code/crates/launcher/src/backends/linux/inner/{seccomp,notify,syscalls}.rs` (the inline `seccomp` module of `inner.rs` moved to its own file), `shim.rs` (`NOTIFY_FD`, `fd_closed`, `LinuxShim.seccomp_notify`), `backends/mod.rs` (`spawn_with_status` places the channel at fd 4), `lib.rs` (`SeccompDenial`, `SeccompFeed`, `SeccompStop`, `SandboxHandle.seccomp`), `inner/bridge.rs` (closes fds 3 and 4); `code/crates/brokerd/src/kernel_denials/seccomp.rs` and `Collector::attach_seccomp`; probes `packet-socket` and `unshare-user` in `conformance-probe`. CI run 36912922849: all tests above passed on ubuntu-22.04 (Linux 6.8) and ubuntu-24.04 (6.17) on the first run, which also confirmed facts 1 to 3 of the Context on both kernels (`inner::notify::tests`); the lint job failed on one clippy lint in the new conformance test, fixed in the next commit.
- 2026-10-01: rebased on main, where `broker doctor` had meanwhile learned to say whether kernel denials are recorded (ADR-041): on Linux it now says seccomp refusals are recorded when the `seccomp_notify` layer is available, Landlock and mount refusals not (`code/crates/broker-cli/src/cmd/doctor.rs`, test `m4_doctor`).
- 2026-10-03: **review finding, closed by [[ADR-045 No Seccomp Listeners or Datagram Socket Pairs in the Sandbox]]**: with the deny filter at `USER_NOTIF`, an agent's newer `USER_NOTIF` filter with its own listener would win the tie once brokerd's listener closes (the one-listener rule holds only while it is open). Agents can no longer create listeners at all.
