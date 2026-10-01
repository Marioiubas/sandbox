---
title: "ADR-041 Kernel Denials on the Audit Record"
aliases: ["ADR-041"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/audit, invariant/i9, milestone/m4]
status: built
confidence: medium
created: 2026-09-30
updated: 2026-10-01
summary: "On macOS every Seatbelt deny rule carries the tag `broker:<session>`; brokerd streams the kernel's own reports (pid 0, Sandbox.kext) from the unified log and writes one attributed `kernel.denied` row (reason `sandbox_denied`) per process, operation and target, capped at 500 per session; the shim's launch checks are recorded and flagged. A record, not a control. Linux Landlock and seccomp denials remain unrecorded (residual)."
related: ["[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[Sandbox Launcher]]", "[[Audit Recorder and Event Schema]]", "[[Conformance Probe Matrix]]", "[[ADR-028 M2 Plan Items Built Differently or Deferred]]", "[[ADR-023 OCSF and OTLP Export as Built]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
code: ["code/crates/brokerd/src/kernel_denials.rs", "code/crates/launcher/src/backends/seatbelt/sbpl.rs", "code/tests/conformance/tests/m4_kernel_denials.rs"]
---

# ADR-041 Kernel Denials on the Audit Record

> The kernel enforces a filesystem or network denial whether or not anyone records it; this puts the record on the session's audit chain.

## Status

built (2026-09-30, M4), macOS only.

## Context

[[I9 Hash-Chained Audit Outside the Sandbox|I9]] lists "filesystem denial reported by the backend" among the decisions to log, and probe rule 3 of the [[Conformance Probe Matrix]] requires every deny to have an audit row with a reason. Category 10 denials (and direct connects refused by Seatbelt) had no row at all. [[ADR-028 M2 Plan Items Built Differently or Deferred]] item 3 said kernel denials "already surface as `fs.denied`"; that event kind was never emitted (correction).

## Decision

1. Every deny rule in the generated SBPL carries `(with message "broker:<session>")`; the kernel appends the tag to its report (verified empirically on macOS 26 / Darwin 25.5).
2. At launch brokerd starts `/usr/bin/log stream --style ndjson` with a predicate for `processID == 0`, `processImagePath == "/kernel"`, `senderImagePath` = the Sandbox.kext binary and the session tag, and checks the same fields again per line. **Found while building:** a user process whose binary is named `Sandbox` logs with `sender == "Sandbox"`, so the first predicate accepted forged reports; the kernel-only check rejects them (unit test `only_the_kernels_reports_are_taken`).
3. Each new (process name, operation, target) becomes one `kernel.denied` row, reason `sandbox_denied`, attributed like every row (session, end user, groups, agent, sandbox); at most 500 per session, then one `suppressed` row. The shim's launch checks are recorded too and flagged `launch_check` (advisory: a process can take any name), deduplicated per pid so they never hide the agent's own attempt.
4. Rows are after the fact, not write-ahead: the kernel already refused. The launch waits (at most 2 s, about 10 ms measured) for `log stream` to print its header, so the agent's first denials are not lost to a stream that is not yet live; the test requires the shim's checks, the first thing a session does, to be on the record. A collector that cannot start records nothing and never fails a launch; the collector stops 2 s after teardown.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Skip every row from a process named `broker-sandbox-shim` | Any process can take that name and hide its denials. |
| Dedupe by operation and target only | The shim's port-443 check would hide the agent's own direct connect. |
| Linux: Landlock audit records (Linux 6.15+) or `SECCOMP_FILTER_FLAG_LOG` | They go to the kernel audit subsystem, which needs audit enabled and `CAP_AUDIT_READ`, auditd or `CAP_SYSLOG` to read; an unprivileged daemon cannot (verified from primary sources 2026-10-01, see [[Open Questions and Unverified Claims]]). seccomp `SECCOMP_RET_USER_NOTIF` is the one unprivileged channel (fails closed with `ENOSYS` if brokerd goes away); not built. |

## Consequences

- macOS sessions now have a row for kernel-refused reads, writes and connects, including routine noise (for example `mach-lookup com.apple.diagnosticd`), filterable by `detail.operation`.
- The kernel rate-limits and coalesces reports ("N duplicate reports"), and a flood of distinct denials can reach the cap; absence of rows proves nothing.
- `kernel.denied` rows are not exported to OCSF ([[ADR-023 OCSF and OTLP Export as Built]] maps request decisions only); a File System Activity mapping is not built. Learn mode, shadow mode and the conformance harness's broker-deny counts read request decisions only, so these rows never become policy or count as broker denials.
- **Residual:** Linux Landlock, seccomp and mount denials are enforced but not recorded on the broker's chain.
- **Linux, host record (2026-10-01):** from Landlock ABI 7 (Linux 6.15) the launcher sets `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`, so on a host with audit enabled the agent's Landlock denials after exec reach the host's own audit log (the kernel's default logs only before exec). That is the administrator's record, not the broker's: brokerd cannot read it unprivileged. Nothing changes on a host with audit off. The `landlock_fs` layer detail says `host audit after exec on|off`. Test: `m4_kernel_denials::landlock_denials_reach_the_host_audit_log` (CI, ubuntu-24.04 with auditd: a TCP connect to a loopback port other than the bridge, refused by Landlock alone, appears as a `blockers=net.connect_tcp` record). Verified on CI run 36909489407 (GitHub ubuntu-24.04 runner, Linux 6.17, ABI 7, auditd: `enabled 1`, record found).

## Invariants affected

Strengthens I9. Weakens none.

## Tests

`brokerd::kernel_denials::tests::*` (parse, attribution, dedupe, cap, kernel-only, property test that `parse` is total) and `m4_kernel_denials::kernel_denials_are_on_the_sessions_record` (a hook write and a direct `nc` connect inside a session become attributed agent rows separate from the shim's flagged checks, which are also present; the hook file does not exist; the chain verifies). The conformance harness's `deny_reasons` counts broker decisions only: the first CI run (36713218963, macOS 15 and 26) failed `i6_bypass_corpus_end_to_end` with 833 deny rows for 70 probes, the kernel rows of 70 short sessions.

## Relationships

- decided-by:: M4 build
- extends:: [[I9 Hash-Chained Audit Outside the Sandbox]]

## Build log

- 2026-10-01: `broker doctor` says what is recorded on this host: on macOS kernel denials are recorded on each session's audit log (best effort, capped); on Linux they are enforced but not recorded on the broker's log, and from Landlock ABI 7 reach the host's audit log when the host has audit enabled (`m4_doctor`).
