---
title: "Audit Recorder and Event Schema"
aliases: ["Recorder", "Audit Event Schema", "OCSF Mapping", "audit crate"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/audit, topic/identity, control/audit, adversary/a3, invariant/i9, invariant/i1, milestone/m2, evidence/unverified, evidence/conflict]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-25
summary: "The audit crate: SQLite WAL hash-chained decision log (each hash covers the previous hash concatenated with the canonical JSON event) and the per-request OTel/OCSF event carrying user, agent and binary hash, task, session, method, redacted URL, adapter verb, Cedar decision with policy IDs and mode, credential ID (never value), status, bytes and chain hash."
related: ["[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[Core Trait Contracts]]", "[[M2 Policy Audit and Learn]]", "[[Control Plane and Policy Bundles]]", "[[AWS STS Session Policies]]", "[[Open Questions and Unverified Claims]]", "[[Gap Analysis]]", "[[Policy Learning Loop]]", "[[Broker CLI and Daemon]]", "[[Policy Engine and Entity Builder]]", "[[Credential Injector and Issuers]]", "[[Request and Session Lifecycle]]", "[[I1 No Secrets in the Sandbox]]", "[[Replit Production Database Deletion]]", "[[Mythos Preview Evaluation Escape]]", "[[Policy Miner Safeguards]]", "[[M3 CI Identity and MCP]]", "[[Agent Identity Brokers]]", "[[L1 Conformance Suite]]", "[[Tech Stack]]", "[[Repository Layout]]"]
sources: ["https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html", "https://incidentdatabase.ai/cite/1152/", "https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card", "https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/", "https://docs.aembit.io/get-started/use-cases/ai-agents/", "https://tailscale.com/docs/aperture/what-is-aperture"]
milestone: M2
code: ["code/crates/audit/src/store.rs", "code/crates/audit/src/event.rs", "code/crates/audit/src/reason.rs", "code/crates/audit/src/canonical.rs", "code/crates/audit/src/ocsf.rs", "code/crates/audit/src/otlp.rs", "code/crates/broker-cli/src/cmd/export.rs", "code/crates/audit/src/reason/explain.rs"]
---

# Audit Recorder and Event Schema

> The audit crate: SQLite WAL hash-chained decision log (each hash covers the previous hash concatenated with the canonical JSON event) and the per-request OTel/OCSF event carrying user, agent and binary hash, task, session, method, redacted URL, adapter verb, Cedar decision with policy IDs and mode, credential ID (never value), status, bytes and chain hash.

## Responsibility

`crates/audit` ([[Repository Layout]]: "SQLite hash chain, OCSF mapping, OTLP exporter"). It implements the `Recorder` trait ([[Core Trait Contracts]]) and is the single writer of the evidence that [[I9 Hash-Chained Audit Outside the Sandbox]] requires. Every crate that decides calls it; `broker why`, `broker audit`, the learning plane and the SIEM export read only from it.

The audit log is one of the two assets the report calls least obvious and most valuable, because "the model's self-reports cannot be trusted": the Replit agent wrongly claimed rollback was impossible ([AI Incident Database](https://incidentdatabase.ai/cite/1152/)), and an early Claude Mythos Preview snapshot rarely took steps to keep its edits out of git history ([Mythos system card](https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card)). See [[Replit Production Database Deletion]] and [[Mythos Preview Evaluation Escape]].

"One audit schema across agents (OTel plus OCSF), attributed to Okta or Entra identities" is one of the six gaps the report says nobody owns ([[Gap Analysis]]). A CSA note recommends SIEM capture of tool-call sequences ([CSA Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/)).

**It must never:** store a secret value, sentinel value, request body or prompt; accept identity fields from request content or agent output; return from `append` before the event is durable; live anywhere a sandbox can read or write; drop denies under load.

## Inputs and outputs

- **Inputs:** `AuditEvent`s from `brokerd` (session lifecycle, approvals, reloads), netguard (admission and denies), l7 (decisions, outcomes), creds (mint, reuse, foreign rejection), mcpguard (launch, manifest change, calls), launcher (launch refusal, filesystem denials the backend reports).
- **Outputs:** the chain hash to the caller; query results for `audit.query` and `decision.explain`; OTLP spans or logs and OCSF JSON batches to the control plane or a SIEM sink; trace tuples for [[Policy Learning Loop]].

## Event schema

The report's field list (**Proposal**): each event is one OTel span or log record carrying

- `enduser.id` (IdP subject), agent ID and binary hash, task ID, session ID and sandbox identity;
- `http.request.method` and a redacted `url.full`;
- the adapter verb (`git.push refs/heads/agent/x`);
- the Cedar decision, determining policy IDs and mode (enforce or audit);
- the credential ID and issuer (never the value);
- upstream status and bytes;
- the chain hash.

Concrete form (**Proposal; not compiled**; values illustrative):

```json
{
  "v": 1, "seq": 4182, "ts": "2026-09-24T10:15:02.113Z", "kind": "request.decision",
  "enduser": { "id": "okta|00u1abc", "groups": ["eng"] },
  "agent": { "id": "claude-code", "binary_sha256": "5e1f…" },
  "task": "task-01J9…", "session": "01J9ZK3M5V7X", "sandbox": "linux-native",
  "http": { "method": "POST", "url_redacted": "https://github.com/acme/web.git/git-receive-pack" },
  "verb": "git.push refs/heads/agent/fix-123",
  "decision": { "result": "allow", "policy_ids": ["push-agent-branches"], "mode": "enforce",
                "labels": { "untrusted_input": false, "sensitive_read": true, "external_effect": true },
                "bundle": "acme-2026-09-24.3" },
  "credential": { "id": "github_app:acme#7", "issuer": "github_app", "action": "mint" },
  "upstream": { "status": 200, "bytes_out": 18234, "bytes_in": 512 },
  "reason": null,
  "prev": "a91c…", "hash": "3be0…"
}
```

Event kinds (**Proposal**): `session.start`, `session.stop`, `session_aborted`, `launch_refused`, `request.decision`, `request.outcome`, `credential.mint`, `credential.reuse`, `foreign_credential`, `fs.denied`, `mcp.launch`, `mcp.manifest_changed`, `mcp.call_tool`, `approval`, `policy.reload`.

## Interface

`Recorder` is verbatim from the report (**Proposal; not compiled**):

```rust
/// Append-only, hash-chained decision log.
pub trait Recorder: Send + Sync {
    fn append(&self, ev: &AuditEvent) -> anyhow::Result<ChainHash>; // hash = H(prev || canonical_json(ev))
}
```

Supporting API and storage (**Proposal; not compiled**):

```rust
pub struct AuditEvent { /* fields above except seq, prev, hash, which the recorder assigns */ }
pub fn canonical_json(ev: &AuditEvent) -> Vec<u8>;              // deterministic key order and numbers
pub fn verify(db: &Path) -> Result<(), VerifyError>;             // first bad seq
pub trait Exporter { fn export(&self, batch: &[StoredEvent], anchor: ChainHash) -> anyhow::Result<()>; }
```

```sql
CREATE TABLE meta   (format_version INTEGER, hash_alg TEXT, genesis BLOB);
CREATE TABLE events (seq INTEGER PRIMARY KEY, ts TEXT, kind TEXT, session TEXT,
                     body BLOB NOT NULL,          -- canonical JSON
                     prev BLOB NOT NULL, hash BLOB NOT NULL);
CREATE INDEX events_session ON events(session);
```

Config (**Proposal**, org or user scope):

```toml
[audit]
retention = "30d"
export = ["otlp", "ocsf"]
sinks = ["splunk_hec", "s3"]        # sink set from research note 05; connectors are ee/
redact_query = true
```

## Internal design

**Proposal.**

1. **Write-ahead.** The L7 pipeline appends the decision before forwarding and the outcome after the response; an `Err` from `append` turns the decision into a deny with reason `audit_unavailable` ([[Request and Session Lifecycle]]).
2. **Chain.** `hash = H(prev || canonical_json(ev))`, with `H` and the canonical form fixed by `format_version` (SHA-256 and an RFC 8785-style canonical JSON are proposals; the record does not name them). Genesis hash in `meta`.
3. **Durability and throughput.** SQLite WAL with full synchronous commits and group commit: concurrent appends within a short window share one commit, and each caller returns only after its commit.
4. **Redaction.** `url_redacted` keeps scheme, canonical host and path; query values are replaced; any substring matching a live sentinel or issued secret is replaced (defence in depth; the redaction must never be the only barrier).
5. **Identity.** Copied from the session's Task entity, never from the request. In CI and after [[M3 CI Identity and MCP]], `enduser.id` and groups come from the IdP or runner OIDC.
6. **Export.** Batches go out as OTLP and OCSF JSON with the last chain hash as an anchor, so a local rewrite after export is detectable against the ingested copy ([[Control Plane and Policy Bundles]]). Research note 05 lists Splunk HEC, Microsoft Sentinel, Datadog, S3 and webhooks as sinks, with retention and tamper evidence as SOC 2 evidence.
7. **Correlation with providers.** Minted AWS sessions carry `SourceIdentity`, which persists across chaining and is visible in CloudTrail ([AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)); the broker writes the same value into its event, giving a join key between broker and CloudTrail logs ([[AWS STS Session Policies]]).
8. **Rotation.** Segments rotate by size or age; each new segment's genesis is the previous segment's last hash.

## OCSF and OTel mapping

> [!warning] Conflict and unverified
> The report maps events to "OCSF HTTP or API Activity records" and warns that "the exact OCSF class IDs and the current OTel GenAI conventions were not verified in the record and must be checked before implementation". Research note 03 suggests HTTP Activity, Authorization/Authentication events and API Activity, with example IDs (HTTP Activity 4002, API Activity 6003) marked unverified; research note 05 names "Network Activity" and "API Activity". **Proposal:** implement the mapping as data (one table from event kind to OCSF class and fields), verify class names and IDs against the published OCSF schema in M2, and record the result in [[Open Questions and Unverified Claims]].

**Implementation notes (2026-09-24, M2):** verified against the published OCSF 1.9.0 schema: Network Activity is 4001 and HTTP Activity 4002 (category 4), API Activity 6003 (category 6, additionally requiring `actor`, `api`, `src_endpoint`). As built, L4 admissions map to Network Activity, terminated requests to HTTP Activity and git operations to API Activity; allow/deny uses the `security_control` profile; broker fields go in `unmapped.broker`; each event carries its chain hash and sequence as the anchor. Export is a pull from the verified chain by `broker audit export` (NDJSON, HEC-style or OTLP/HTTP JSON), not live spans via the OTel SDK ([[ADR-023 OCSF and OTLP Export as Built]]). OTel GenAI conventions are not used.

Market reference points for audit content: Aembit logs user, agent, resource, policy and call count ([Aembit docs](https://docs.aembit.io/get-started/use-cases/ai-agents/)); Tailscale Aperture logs full request and response bodies with SIEM export ([Tailscale](https://tailscale.com/docs/aperture/what-is-aperture)). This design logs metadata, not bodies ([[Agent Identity Brokers]]).

## State

The SQLite database and its segments in `brokerd`'s per-user state directory, never mounted into any sandbox; an in-memory `prev` hash and pending-commit queue.

## Failure modes and fail-closed behaviour

- Disk full, read-only filesystem, corruption detected at open: every new request is denied (`audit_unavailable`); sessions cannot start.
- Crash mid-append: WAL recovery; `verify` at startup; a broken tail is reported and new appends start a segment whose genesis records the break.
- Exporter failure: local log continues; export retries with backoff; the backlog is visible in `broker doctor`.

## Security considerations

- The chain gives tamper evidence, not tamper resistance, against a local attacker with the user's privileges; export anchoring and optional batch signing (research note 03: "sign or hash-chain") raise the bar.
- Audit data is sensitive (hosts, repos, verbs); exports go over mTLS and follow tenant retention.
- The learning plane must not learn from requests that carried foreign credentials; the event marks them ([[Policy Miner Safeguards]]).

## Performance budget

**Proposal:** append p99 ≤1 ms on SSD with group commit, inside the ≤5 ms warm p50 request budget; measure on reference machines. Export is asynchronous and off the request path.

## Invariants upheld

[[I9 Hash-Chained Audit Outside the Sandbox]] (chain, location, write-ahead, attribution), [[I1 No Secrets in the Sandbox]] (credential IDs, never values).

## Test plan

- **Tamper** (`tests/audit/chain`): modify a byte, delete a row, swap rows; `broker audit verify` fails at the first affected index.
- **Golden:** canonical JSON for fixed events is byte-stable across builds and platforms.
- **Property:** for random event sequences, `verify` passes; any single mutation fails it.
- **Crash:** kill `brokerd` during appends; after restart, every forwarded request has a durable decision event.
- **Secret scan:** run the M1 canary scenario and grep the database and exports for canary values and sentinels: none.
- **Conformance:** "100% of denies logged with a reason" ([[L1 Conformance Suite]]).
- **E2E** ([[M2 Policy Audit and Learn]]): events validate against the OCSF schema and reach a test SIEM sink.

## Crates

`audit`; `rusqlite` (WAL), `sha2`, `serde_json`, `opentelemetry` + `opentelemetry-otlp` ([[Tech Stack]]). Versions unverified.

## Delivering milestone

[[M2 Policy Audit and Learn]]: chain, verify, OTLP, OCSF, `broker audit tail`. M0 and M1 ship a minimal recorder on the same trait for `broker why` and deny logging.

## How it connects

- implements:: [[I9 Hash-Chained Audit Outside the Sandbox]]
- implements:: [[Core Trait Contracts]]
- motivated-by:: [[Gap Analysis]]
- depends-on:: [[AWS STS Session Policies]]
- part-of:: [[Request and Session Lifecycle]]
- mitigates:: [[Replit Production Database Deletion]]
- mitigates:: [[Mythos Preview Evaluation Escape]]
- contrasts-with:: [[Agent Identity Brokers]]
- evaluated-by:: [[L1 Conformance Suite]]
- delivered-by:: [[M2 Policy Audit and Learn]]

Exports feed [[Control Plane and Policy Bundles]]; traces feed [[Policy Learning Loop]]; open items are tracked in [[Open Questions and Unverified Claims]].

## Implications for the build

- Build the recorder on the trait in M0 so later milestones add the chain and exporters without touching callers.
- Freeze `format_version` 1 before the first design partner; any change to hash or canonical form bumps it and keeps a verifier for old segments.
- `broker why` renders events plus policy IDs, never agent transcripts.

## Open questions

- ~~OCSF class names and IDs~~ (verified, [[ADR-023 OCSF and OTLP Export as Built]]); OTel GenAI semantic conventions (not used yet).
- Batch signing with a device key in addition to chaining.
- Local retention defaults and ring size (the tech stack calls it an "audit ring").

## Sources

- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- https://incidentdatabase.ai/cite/1152/
- https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card
- https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/
- https://docs.aembit.io/get-started/use-cases/ai-agents/
- https://tailscale.com/docs/aperture/what-is-aperture
- Report: `Recorder` trait, audit-event list and OCSF/OTel caveat, request-life step 5, tech-stack telemetry and local-state rows, assets paragraph, "The gap to own"; research notes 03 Q5 and 05 §3.3.

## Build log

- 2026-09-24: M0 slice built in `code/crates/audit/`: `Recorder` trait, `SqliteRecorder` (WAL, `synchronous=FULL`, busy timeout), hash `SHA-256(prev || canonical_json(event + seq))` with a random per-database genesis in `meta`, `verify` returning the first bad sequence number, `open` refusing a broken chain, read-only readers for `broker why` and `broker audit`. Canonical JSON: sorted keys, no whitespace, floats rejected. The enumerated deny `Reason` (36 codes with stage, trust boundary and explanation) lives here and is shared by every deciding crate. Tests: tamper one byte, delete, swap, re-hash an edited row (breaks the next link), property test over random single-byte mutations, `audit_failure_denies_before_connecting`, `i9_every_decision_is_chained_and_explainable`. Truncating the tail is only detectable against an exported anchor (tested and documented).
- 2026-09-24: not built (M2): OCSF and OTLP export, anchoring, rotation. Added event kind `session.ready`.
- 2026-09-24 (M2): OCSF 1.9.0 mapping and validation (`ocsf.rs`), OTLP/HTTP JSON logs body (`otlp.rs`), `broker audit export --format ocsf|hec|otlp [--to URL] [--token REF] [--from-seq N]` exporting only the verified prefix (`SqliteRecorder::range`), chain hash and sequence in every event as the anchor ([[ADR-023 OCSF and OTLP Export as Built]]). Tests: `ocsf::tests::classes_map_and_validate`, `otlp::tests::wraps_each_event`, `m2_ocsf::c4_events_validate_and_reach_the_sinks`. Still not built: segment rotation, batch signing, live streaming.
- 2026-09-24 (M2): `audit.query` on the control socket (filters on session, kind, decision, reason, canonical host, sequence; validated at the boundary, unknown keys refused) and `broker audit query`. Status `built` for the M2 scope (chain, verify, OCSF, OTLP, tail, query); segment rotation, batch signing and live streaming remain open. Tests: `audit_query::tests::filters_are_validated_not_ignored`, `m2_ocsf::audit_query_filters_through_the_daemon`.
- 2026-09-24 (M3): event kind `session.label` (label, cause, request ID); L7 decision rows carry `labels`; reasons `github_route_unknown`, `github_graphql_unsupported`, `github_verb_not_allowed`, `github_repo_not_allowed`.
- 2026-09-25 (M3): MCP rows (`layer: mcp`: connect, each call, refusals, revocations with a tool diff) and reasons `mcp_server_unknown`, `mcp_manifest_unapproved`, `mcp_manifest_changed`, `mcp_tool_unknown`, `mcp_tool_not_allowed`, `mcp_method_not_allowed`, `mcp_malformed`, `mcp_launch_failed`.
- 2026-09-25: `reason.rs` reached 500 lines with the M3 reasons; `Reason::explain` (the `broker why` text) moved to `reason/explain.rs`, no behaviour change.
- 2026-09-25 (M3): `enduser` is the verified identity token's `sub` for CI sessions; `session.start` carries `identity` (issuer, subject, claims); the token is never logged ([[ADR-031 CI Identity as Built]]).
- 2026-09-25 (M3): reasons `s3_route_unknown` and `s3_prefix_not_allowed`; allow rows for S3 carry `credential_kind: aws_sts` with `credential_origin` `mint` then `reuse` ([[ADR-032 AWS STS and S3 Adapter as Built]]).
- 2026-09-25 (M3): reason `public_sink_after_untrusted_input` ([[ADR-033 Public-Sink Rule as Built]]).
- 2026-09-25 (M3): `enduser_groups` on every row of a `broker login` session (omitted when empty, so older rows hash as before); OCSF `actor.user.groups` ([[ADR-034 Device Login as Built]]).
- 2026-09-25: not yet built: group commit (point 3 of the design). Each append is its own synchronous commit under a mutex, called from async tasks; on the Linux CI runner the latency harness suggests this dominates new-connection latency. Measuring before building it.
