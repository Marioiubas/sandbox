---
title: "I9 Hash-Chained Audit Outside the Sandbox"
aliases: ["Audit Invariant"]
type: concept
section: architecture
tags: [sandbox/architecture, concept, invariant/i9, topic/audit, control/audit, adversary/a3, milestone/m2]
status: proposal
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Every decision is logged outside the sandbox, hash-chained, and attributed to user, agent, task and session; the model's self-reports are never evidence."
related: ["[[Audit Recorder and Event Schema]]", "[[Replit Production Database Deletion]]", "[[Mythos Preview Evaluation Escape]]", "[[Core Trait Contracts]]", "[[M2 Policy Audit and Learn]]", "[[Control Plane and Policy Bundles]]", "[[Broker CLI and Daemon]]", "[[I1 No Secrets in the Sandbox]]", "[[Adversary Classes]]", "[[Policy Learning Loop]]", "[[GTG-1002 AI-Orchestrated Espionage]]"]
sources: ["https://incidentdatabase.ai/cite/1152/", "https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/", "https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card", "https://metr.org/blog/2026-05-19-frontier-risk-report/", "https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf"]
milestone: M2
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
