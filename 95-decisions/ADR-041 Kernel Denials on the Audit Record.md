---
title: "ADR-041 Kernel Denials on the Audit Record"
aliases: ["ADR-041"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/audit, invariant/i9, milestone/m4]
status: built
confidence: medium
created: 2026-09-30
updated: 2026-09-30
summary: "On macOS every Seatbelt deny rule carries the tag `broker:<session>`; brokerd streams the kernel's own reports (pid 0, Sandbox.kext) from the unified log and writes one attributed `kernel.denied` row (reason `sandbox_denied`) per process, operation and target, capped at 500 per session; the shim's launch checks are recorded and flagged. A record, not a control. Linux Landlock and seccomp denials remain unrecorded (residual)."
related: ["[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[Sandbox Launcher]]", "[[Audit Recorder and Event Schema]]", "[[Conformance Probe Matrix]]", "[[ADR-028 M2 Plan Items Built Differently or Deferred]]", "[[MOC Decisions]]"]
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
4. Rows are after the fact, not write-ahead: the kernel already refused. A collector that cannot start records nothing and never fails a launch; the collector stops 2 s after teardown.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Skip every row from a process named `broker-sandbox-shim` | Any process can take that name and hide its denials. |
| Dedupe by operation and target only | The shim's port-443 check would hide the agent's own direct connect. |
| Linux: Landlock audit records (Linux 6.15+) or `SECCOMP_RET_LOG` | They go to the kernel audit subsystem, which an unprivileged daemon cannot read; unverified details are in [[Open Questions and Unverified Claims]]. |

## Consequences

- macOS sessions now have a row for kernel-refused reads, writes and connects, including routine noise (for example `mach-lookup com.apple.diagnosticd`), filterable by `detail.operation`.
- The kernel rate-limits and coalesces reports ("N duplicate reports"), and a flood of distinct denials can reach the cap; absence of rows proves nothing.
- **Residual:** Linux Landlock, seccomp and mount denials are enforced but not recorded.

## Invariants affected

Strengthens I9. Weakens none.

## Tests

`brokerd::kernel_denials::tests::*` (parse, attribution, dedupe, cap, kernel-only, property test that `parse` is total) and `m4_kernel_denials::kernel_denials_are_on_the_sessions_record` (a hook write and a direct `nc` connect inside a session become attributed agent rows; the hook file does not exist; the chain verifies).

## Relationships

- decided-by:: M4 build
- extends:: [[I9 Hash-Chained Audit Outside the Sandbox]]
