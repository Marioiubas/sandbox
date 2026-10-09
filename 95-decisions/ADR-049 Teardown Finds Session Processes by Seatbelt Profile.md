---
title: "ADR-049 Teardown Finds Session Processes by Seatbelt Profile"
aliases: ["ADR-049"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/sandbox, invariant/i9, invariant/i2, milestone/m4]
status: built
confidence: medium
created: 2026-10-09
updated: 2026-10-09
summary: "On macOS a sandboxed process can leave the session's process group with `setsid()` and outlive the session. Teardown now finds the session's processes two ways: by the session's own Seatbelt profile (a per-session marker only that profile may read, checked with `sandbox_check`) and by ancestry. It stops them all before it kills any, so nothing of the session runs after `session.stop` is on the record."
related: ["[[Broker CLI and Daemon]]", "[[Sandbox Launcher]]", "[[Seatbelt]]", "[[Request and Session Lifecycle]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[I2 Fail-Closed Launch]]", "[[Trust Boundaries]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
---

# ADR-049 Teardown Finds Session Processes by Seatbelt Profile

> When a session ends, every process that ran under its sandbox ends with it, whether or not it stayed in the sandbox's process group.

## Status

built (2026-10-09, M4). Found by the host-side review of 2026-10-09; its test failed before the change and passes after it.

## Context

The supervisor in [[Broker CLI and Daemon]] kills the session tree when the agent exits or the CLI goes away. It did so with `kill(-pid)` on the process group the sandbox leads. Nothing stops a sandboxed process from calling `setsid()`: the reviewer checked with `sandbox-exec` and a deny-default profile that Seatbelt does not mediate it. Such a process outlived its session on macOS:

- it still held the user's terminal (fds 0 to 2) and write access to the repository and agent state;
- it kept running after `session.stop` was on the record and the kernel-denial collector had stopped.

On Linux the sandbox is a PID namespace whose init takes every member with it (`--unshare-pid --die-with-parent`). Seatbelt has no such container. Ancestry alone is not enough either: after a double fork whose middle process exits, the survivor is reparented to launchd.

## Decision

- **Marker:** the Seatbelt backend writes an empty `sandbox.mark` into the session directory, which no sandbox can write and every profile denies reading. The session's profile ends with `(allow file-read-data (literal <marker>))`.
- **Fingerprint (`seatbelt::in_session_sandbox`):** a process belongs to the session if all three hold. `sandbox_check(pid, NULL, 0)` reports it sandboxed; `sandbox_check(pid, "file-read-data", PATH | NO_REPORT, marker)` allows the read; and the same check on the session's canary, in the same directory, denies it.
  - Only this profile tells the two files apart. Another session denies both. A permissive profile allows both.
  - The sandbox is inherited and cannot be left, so the check holds after `setsid()`, a double fork or reparenting.
  - `NO_REPORT` keeps the check off the denial log.
  - Verified on macOS 26.5: for another process, `sandbox_check` returns 0 (allowed) or 1 (denied) for an existing path, and 1 for a path that does not exist.
- **Teardown (`launcher::reap::kill_session`):**
  1. SIGSTOP the group.
  2. Repeat until a round finds no new process, at most 32 rounds:
     - list every process of the user;
     - take those in the group or matching the fingerprint, plus every descendant of one, by parent pid;
     - SIGSTOP the new ones. A stopped process cannot fork.
  3. SIGKILL the group and every stopped process.

  The daemon uses this at teardown, when the CLI goes away, and when the audit log fails at launch. Members are matched by process-group id rather than by the root's pid: a group id cannot be reused while a member lives, but the reaped root's pid can.
- **Linux:** unchanged (`kill(-pid)`; the PID namespace does the rest).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Deny `setsid` in the profile | Seatbelt has no operation for it (reviewer's check). |
| Ancestry only | A double fork reparents the survivor to launchd before teardown sees it. |
| A marker inherited through the environment or an open descriptor | The process can clear its environment or close the descriptor. |
| Sandboxed and writable `TMPDIR` as the fingerprint | The session can rename or delete its own `TMPDIR`; the marker sits where no sandbox can write. |
| Audit sessions or coalitions | Creating one needs privilege or an entitlement the daemon does not have. |

## Consequences

- `session.stop` is written only after every process of the session has been stopped and killed.
- **Residual:** `sandbox_check` is not in the public SDK headers (Chromium and WebKit use it). If its behaviour changes, the fingerprint matches nothing and teardown falls back to group plus ancestry. `reap::tests` asserts the fingerprint on a real Seatbelt process, so CI on macOS would notice.
- **Residual (low):** a member could exit and its pid be reused by another of the user's processes between the scan and the signal, which takes microseconds.
- **Residual (low):** a process tree that forks faster than 32 rounds can stop it could leave a survivor.

## Invariants affected

Upholds I9 (nothing of a session acts after its record is closed) and TB2 ([[Trust Boundaries]]). Weakens none. The profile gains one read rule, for an empty file that holds nothing.

## Tests

- `launcher::reap::tests::a_daemonised_process_of_the_session_is_killed_and_no_other` (macOS, real Seatbelt). A daemonised process under the session's profile is killed; one under another session's profile and one outside any sandbox are not. Without the fingerprint the test fails.
- `launcher::backends::seatbelt::sbpl::tests::marker_is_a_literal_read_allow`
- the reviewer's `brokerd::session::running::review_tests::review_teardown_kills_sandboxed_processes_that_left_the_group` (failed before)
- end to end on macOS and Linux: `m4_teardown::a_daemonised_process_does_not_outlive_its_session`. With teardown run without the fingerprint, this test fails.

## Relationships

- decided-by:: host-side review (2026-10-09)
- motivated-by:: [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]

## Build log

- 2026-10-09: built. Code:
  - `code/crates/launcher/src/reap.rs`
  - `code/crates/launcher/src/backends/seatbelt/mod.rs` (`in_session_sandbox`, the marker)
  - `code/crates/launcher/src/backends/seatbelt/sbpl.rs` (`SbplInputs::marker`)
  - `code/crates/brokerd/src/session/running.rs` (`Running::kill_all`)
  - `code/crates/brokerd/src/server.rs`
  - `code/crates/brokerd/src/session/launch.rs`

  Tests as above.
