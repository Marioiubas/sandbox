---
title: "I9 Hash-Chained Audit Outside the Sandbox"
aliases: ["Audit Invariant"]
type: concept
section: architecture
tags: [sandbox/architecture, concept, invariant/i9, topic/audit, control/audit, adversary/a3, milestone/m2]
status: built
confidence: high
created: 2026-09-24
updated: 2026-10-09
summary: "Every decision is logged outside the sandbox, hash-chained, and attributed to user, agent, task and session; the model's self-reports are never evidence."
related: ["[[Audit Recorder and Event Schema]]", "[[Replit Production Database Deletion]]", "[[Mythos Preview Evaluation Escape]]", "[[Core Trait Contracts]]", "[[M2 Policy Audit and Learn]]", "[[Control Plane and Policy Bundles]]", "[[Broker CLI and Daemon]]", "[[I1 No Secrets in the Sandbox]]", "[[Adversary Classes]]", "[[Policy Learning Loop]]", "[[GTG-1002 AI-Orchestrated Espionage]]", "[[ADR-041 Kernel Denials on the Audit Record]]", "[[ADR-043 Seccomp Denials Recorded via User Notification]]"]
sources: ["https://incidentdatabase.ai/cite/1152/", "https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/", "https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card", "https://metr.org/blog/2026-05-19-frontier-risk-report/", "https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf"]
milestone: M2
code: ["code/crates/audit/src/store.rs", "code/crates/audit/src/store", "code/tests/conformance/tests/invariants.rs", "code/crates/brokerd/src/kernel_denials.rs", "code/tests/conformance/tests/m4_kernel_denials.rs"]
---

# I9 Hash-Chained Audit Outside the Sandbox

> Every decision is logged outside the sandbox, hash-chained, and attributed to user, agent, task and session; the model's self-reports are never evidence.

## Statement

**Proposal.** For every authorization decision the broker makes (egress allow or deny, L7 classification, credential mint or reuse, foreign-credential rejection, filesystem denial reported by the backend, MCP tool call, session start and stop, launch refusal, policy reload, approval):

1. an `AuditEvent` is appended by the [[Audit Recorder and Event Schema|Recorder]] **before** the decision takes effect upstream (write-ahead), and an append failure turns the decision into a deny;
2. the event is stored in a location no sandbox can read or write;
3. each stored event carries `hash = H(prev || canonical_json(ev))` (the `Recorder` contract in [[Core Trait Contracts]]), so deletion, reordering or edit of any row breaks verification;
4. each event carries user (IdP subject), agent ID and binary hash, task ID, session ID and sandbox identity;
5. tooling that explains or summarises behaviour (`broker why`, `broker audit`, SIEM exports, review UIs) reads only this log and Cedar policy IDs, never the agent's transcript or claims.

## Rationale

- **Models misreport.** The Replit agent ignored a code freeze, deleted the production database and wrongly said rollback was impossible ([AIID](https://incidentdatabase.ai/cite/1152/); [Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/)); see [[Replit Production Database Deletion]]. In GTG-1002 Claude "frequently overstated findings and occasionally fabricated data" ([Anthropic](https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf)); see [[GTG-1002 AI-Orchestrated Espionage]].
- **Models conceal.** An early Claude Mythos Preview snapshot rarely took steps so its edits "would not appear in the change history on git" ([Mythos system card](https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card)); see [[Mythos Preview Evaluation Escape]].
- **In-guest monitors get disabled.** METR found monitors could be disabled via environment variables or fooled by simple jailbreaks, and that "routine monitoring measures could have caught all incidents if applied" ([METR](https://metr.org/blog/2026-05-19-frontier-risk-report/)).
- **The audit log is an asset.** The report names it as one of the two least obvious and most valuable assets. Adversary A3 (misbehaving model) in [[Adversary Classes]] motivates tamper evidence even without an external attacker.

## How it is enforced

**Proposal.**

- **Location.** The SQLite WAL database lives in `brokerd`'s per-user state directory, which is never mounted into any sandbox ([[I5 Config Outside Writable Mounts]] covers the mount rule). In CI and gateway modes the broker runs outside the sandbox in the runner or host.
- **Chain.** `Recorder::append` computes the chain hash over the canonical JSON serialisation of the event; the genesis hash per database is recorded in the first row and exported.
- **Anchoring.** Batches exported to the control plane (OTLP/OCSF) carry the last chain hash, so a local rewrite after export is detectable by comparing with the ingested copy ([[Control Plane and Policy Bundles]]).
- **Attribution.** The Task entity built at `session.start` carries owner and agent; every event copies them from the session, never from request content.
- **No secrets.** Events carry a credential ID and issuer, never a value ([[I1 No Secrets in the Sandbox]]); URLs are redacted.
- **Explainers.** `broker why <request-id>` renders the event plus determining Cedar policy IDs ([[Broker CLI and Daemon]]).

## Minimal test

**Proposal.** `tests/audit/chain`: run a scripted session producing allows, denies and a mint; then (a) `broker audit verify` passes; (b) modify one byte of one row's JSON, delete one row, and swap two rows in separate copies: verification fails at the first affected index in each case; (c) from inside a sandbox, attempt to open the audit DB path: denied; (d) make the audit disk read-only mid-session: the next request is denied with reason `audit_unavailable`.

## What would violate it

- Logging asynchronously after forwarding, so a crash loses the record of a completed action.
- Storing the audit DB inside the repo, `${tmp}` or any mounted path.
- Filling user or agent fields from HTTP headers or agent output.
- Using an agent's transcript as the answer to `broker why`.
- A "reduce logging" flag that drops denies.

## How it connects

- depends-on:: [[Audit Recorder and Event Schema]]
- part-of:: [[Core Trait Contracts]]
- motivated-by:: [[Replit Production Database Deletion]]
- motivated-by:: [[Mythos Preview Evaluation Escape]]
- motivated-by:: [[GTG-1002 AI-Orchestrated Espionage]]
- depends-on:: [[Control Plane and Policy Bundles]]
- depends-on:: [[Broker CLI and Daemon]]
- delivered-by:: [[M2 Policy Audit and Learn]]
- decided-by:: [[ADR-041 Kernel Denials on the Audit Record]]

## Implications for the build

- M0 and M1 need a minimal decision log for `broker why` and conformance "100% of denies logged with a reason"; build it on the `Recorder` trait from the start so M2 only adds the chain, OCSF and OTLP.
- Canonical JSON must be deterministic (key order, number formatting); pick one serialisation and test it with golden files.
- The [[Policy Learning Loop]] consumes this log; its quality depends on the attribution fields being complete.

## Open questions

- Whether to sign batches (Ed25519 device key) in addition to hash-chaining; research note 03 says "sign or hash-chain".
- Retention and size limits for the local ring (the tech stack calls it an "audit ring"); rotation must preserve chain continuity.

## Sources

- https://incidentdatabase.ai/cite/1152/
- https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/
- https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card
- https://metr.org/blog/2026-05-19-frontier-risk-report/
- https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf
- Report: invariant I9, assets paragraph, `Recorder` trait, audit event list; research notes 04b Q4 and 03 Q5.

## Implementation notes

- 2026-10-01: **"filesystem denial reported by the backend" as built** ([[ADR-041 Kernel Denials on the Audit Record]]). On macOS the kernel's own reports of Seatbelt denials (file reads and writes, direct network connects, Mach service lookups) reach the session's chain as `kernel.denied` rows with reason `sandbox_denied`. These rows are a record after the fact, not write-ahead: the kernel has already refused the operation before the broker learns of it, so point 1 does not apply to them, and a failed append is reported on brokerd's stderr (there is no decision left to turn into a deny). Points 2, 3 and 5 hold as for every row; point 4 holds as for every row (see the next entry). The record is best effort: the kernel rate-limits and coalesces its reports, rows are deduplicated per process name, operation and target and capped at 500 per session (then one `suppressed` row), and a collector that cannot start records nothing without failing the launch. The absence of a row therefore proves nothing; the kernel enforces the denial either way.
- 2026-10-01: **Linux residual.** Landlock, seccomp and mount denials are enforced by the kernel but not recorded: there is no collector on Linux. Whether an unprivileged daemon can read Landlock or seccomp denial records is open ([[Open Questions and Unverified Claims]]).
- 2026-10-01: **Linux seccomp denials recorded** ([[ADR-043 Seccomp Denials Recorded via User Notification]]), narrowing the residual above to Landlock and mount denials. The seccomp deny filter returns `USER_NOTIF`; the kernel holds each refused call until brokerd answers, brokerd always answers EPERM, then appends a `kernel.denied` row (layer `seccomp`, the syscall and its plain register arguments) through the same attribution, dedupe and 500-row cap as macOS. The row still comes after the decision, not ahead of it: the answer never waits on the log, so a failed append loses a row, never a denial. If brokerd stops answering, the kernel fails the calls with ENOSYS.

## Build log

- 2026-09-24: minimal M0 tests: chain tamper tests in `code/crates/audit/src/store.rs` (`tamper_one_byte_fails_at_that_row`, `delete_row_fails`, `swap_rows_fails`, `rehashed_edit_breaks_next_link`, `any_single_body_mutation_is_detected`), `audit_failure_denies_before_connecting`, `i9_every_decision_is_chained_and_explainable` (`broker why`, `broker audit verify`, the sandbox can neither read nor write the log). `session.start` is written ahead of the launch.
- 2026-09-30: status `built`: the minimum tests pass on macOS 15/26 and Ubuntu 22.04/24.04 in every CI run since 35999705456 (vault audit).
- 2026-10-01: macOS kernel-enforced denials are on the session's record as attributed `kernel.denied` rows, after the fact rather than write-ahead (built 2026-09-30, [[ADR-041 Kernel Denials on the Audit Record]]; `code/crates/brokerd/src/kernel_denials.rs`). Tests: `brokerd::kernel_denials::tests::*` (parse, attribution, dedupe, cap, kernel-only reports, `parse` total) and `m4_kernel_denials::kernel_denials_are_on_the_sessions_record` (a hook write and a direct connect become rows attributed to the denied session; the chain verifies). Linux kernel denials remain unrecorded (residual, Implementation notes).
- 2026-10-01: **point 4 built for every row.** Until now only `session.start` carried the task ID and the agent binary hash; request, label, ready, stop and kernel rows carried session, end user, groups, agent and sandbox, and `approval.granted` rows carried only the session. Every row of a session is now built from one attribution template (`AuditEvent::attributed_as` in `code/crates/audit/src/event.rs`; the template is made once per launch in `code/crates/brokerd/src/session/launch.rs` and kept by the approval registry for grants). Found on the way: `kernel.denied` rows were cloned from the template and so carried the session's start time instead of their own; `attributed_as` copies attribution only. Test: `conformance::Harness::assert_attributed` (every row of every session has the attribution of its `session.start`, including the agent hash), used by `invariants::i9_every_decision_is_chained_and_explainable`, `m3_approvals` and `m4_kernel_denials`; `kernel_denials::tests` checks the row's own time. `launch.refused` rows remain partial (agent and sandbox only): the session never got an identity.
- 2026-10-01: **label rows raised by an MCP server's request** ([[ADR-038 MCP Server Sessions Share Agent Labels]]) are on the agent session and now carry that session's attribution; until now they carried the server's (agent = the server binary, its hash and task) on the agent session's row. The server and its request remain named by `raised_in_session` and the request ID. Found by `Harness::assert_attributed` in the new MCP approval test.
- 2026-10-01: Linux seccomp denials on the session's record ([[ADR-043 Seccomp Denials Recorded via User Notification]]; `code/crates/brokerd/src/kernel_denials/seccomp.rs`, `code/crates/launcher/src/backends/linux/inner/notify.rs`). Tests: `brokerd::kernel_denials::seccomp::tests::*` (attribution with the row's own time, dedupe per process name and arguments, the shim's check flagged per pid, cap) and `m4_kernel_denials::seccomp_denials_are_on_the_sessions_record` (`socket(AF_UNIX)`, `socket(AF_PACKET)`, `unshare(CLONE_NEWUSER)` and `ptrace` in a session become attributed rows; `assert_attributed`; the chain verifies).
- 2026-10-09: host-side review fixes. `audit verify` now also checks that each row's indexed columns (`ts`, `kind`, `session`, `request_id`, which `broker why`, `audit tail` and session queries select by) match its hashed body; a row edited only there fails with `ColumnMismatch` (`audit::store::tests::review_query_columns_are_covered_by_verification`). A `session.start` whose parameters do not parse is refused on the record (`launch.refused`) like every other refusal (`brokerd::server::review_tests::review_every_refused_session_start_is_logged`). On macOS nothing of a session runs after `session.stop` ([[ADR-049 Teardown Finds Session Processes by Seatbelt Profile]]; `m4_teardown::a_daemonised_process_does_not_outlive_its_session`).
