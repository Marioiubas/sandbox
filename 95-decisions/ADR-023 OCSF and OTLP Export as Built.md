---
title: "ADR-023 OCSF and OTLP Export as Built"
aliases: ["ADR-023"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/audit, invariant/i9, invariant/i1, milestone/m2]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Decisions export as OCSF 1.9.0 events (Network Activity 4001 for L4, HTTP Activity 4002 for terminated requests, API Activity 6003 for git) from the verified chain by `broker audit export`, as NDJSON, Splunk HEC-style batches or an OTLP/HTTP JSON logs request built without the opentelemetry SDK."
related: ["[[Audit Recorder and Event Schema]]", "[[M2 Policy Audit and Learn]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[I1 No Secrets in the Sandbox]]", "[[Open Questions and Unverified Claims]]", "[[Tech Stack]]", "[[MOC Decisions]]"]
sources: ["https://schema.ocsf.io/1.9.0/classes/network_activity", "https://schema.ocsf.io/1.9.0/classes/http_activity", "https://schema.ocsf.io/1.9.0/classes/api_activity", "https://opentelemetry.io/docs/specs/otlp/", "https://opentelemetry.io/docs/specs/otel/logs/data-model/"]
superseded_by: 
---

# ADR-023 OCSF and OTLP Export as Built

> Export is a pull from the verified hash chain (`broker audit export`), each decision mapped to one OCSF 1.9.0 event and delivered as NDJSON, HEC-style batches or an OTLP/HTTP JSON logs request; brokerd does not stream telemetry and the opentelemetry SDK is not a dependency.

## Status

built (2026-09-24, M2 step 3).

## Context

[[Audit Recorder and Event Schema]] proposed "one span or log record per decision via `opentelemetry-otlp`" and a mapping to "OCSF HTTP or API Activity records", with the class IDs unverified ([[Open Questions and Unverified Claims]]). M2 acceptance C4 requires that 100% of emitted events validate against OCSF and reach a test SIEM sink.

Verified from the published schema browser on 2026-09-24 (OCSF 1.9.0): Network Activity is class 4001 in category 4 (activity 1 Open, 5 Refuse); HTTP Activity is 4002 in category 4 with activity IDs by method (CONNECT 1, DELETE 2, GET 3, HEAD 4, OPTIONS 5, POST 6, PUT 7, TRACE 8, PATCH 9, Other 99); API Activity is 6003 in category 6 (1 Create, 2 Read, 3 Update, 4 Delete, 99 Other) and additionally requires `actor`, `api` and `src_endpoint`. `type_uid = class_uid * 100 + activity_id`. The `security_control` profile carries `action_id` (1 Allowed, 2 Denied) and `disposition_id` (1 Allowed, 2 Blocked). `metadata.product` and `metadata.version` are required ([network_activity](https://schema.ocsf.io/1.9.0/classes/network_activity), [http_activity](https://schema.ocsf.io/1.9.0/classes/http_activity), [api_activity](https://schema.ocsf.io/1.9.0/classes/api_activity)).

## Decision

1. **Mapping as data** (`code/crates/audit/src/ocsf.rs`): only `request.decision` rows are exported. An L4 admission becomes Network Activity (Open when allowed, Refuse when denied); a terminated HTTP request becomes HTTP Activity with the activity ID of its method and `http_request.url` (host, path, port; never query strings or headers); a git operation becomes API Activity (`git.push` → Update, fetch and advertise → Read) with `api.service.name = "git"`, `actor.user.name` = the end user, `src_endpoint.name` = the sandbox identity. Allow/deny is `action_id`/`disposition_id`/`status_id`; the deny reason code is `status_detail` and its explanation `message`; determining policy IDs are `policy`.
2. **Chain anchor in every event.** `metadata.uid` is the row's chain hash and `metadata.sequence` its sequence number, so the last event of a batch anchors the batch and a local rewrite after export is detectable against the ingested copy ([[I9 Hash-Chained Audit Outside the Sandbox]]). Broker-specific fields (session, request ID, enduser, agent, mode, policy IDs, reason, verb, credential ID, would-deny) go in `unmapped.broker`. No field holds a secret: the source rows hold none ([[I1 No Secrets in the Sandbox]]).
3. **Pull, from the verified prefix only.** `broker audit export` verifies the chain first, then exports rows `from_seq < seq <= verified count`; rows appended meanwhile wait for the next export. `--from-seq` resumes. Every event is validated against the captured 1.9.0 subset (required attributes, category, activity and action/disposition enums, `type_uid`, metadata version) before anything leaves; one invalid event aborts the export.
4. **Formats:** `ocsf` (NDJSON to stdout), `hec` (Splunk HEC-style `{"time","source","sourcetype":"ocsf:<class>","event"}` lines), `otlp` (one OTLP/HTTP JSON `ExportLogsServiceRequest`, one log record per event with the OCSF JSON as body, severity INFO/WARN, `timeUnixNano` as a string per the protobuf-JSON mapping) ([OTLP spec](https://opentelemetry.io/docs/specs/otlp/), [logs data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)).
5. **Delivery** (`--to`): HTTPS with verified certificates (webpki roots plus the user policy's `[tls] extra_roots`); plain HTTP only when every resolved address is loopback. The sink token is a secret reference (`--token env:…`, `keychain:…`, `file:…`), read by the CLI and sent as `Authorization: Splunk <token>` (hec) or `Bearer <token>`; it is never accepted as a literal argument.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| `opentelemetry` + `opentelemetry-otlp` SDK in brokerd, streaming spans live | Adds an async exporter, batching and (for gRPC) tonic/prost to the daemon on the request path; a failing collector would need its own fail-open/closed story. The chain is already the durable source of truth, and a pull export from the verified prefix gives exactly-once-per-sequence semantics with an anchor. The OTLP JSON body is ~40 lines. Revisit for live streaming in the control plane ([[Control Plane and Policy Bundles]]). |
| Map everything to HTTP Activity | L4 admissions have no HTTP request; Network Activity is the class for connection open/refuse. |
| Authorization class for denies | The allow/deny outcome is expressed by the `security_control` profile on the activity itself, which keeps allow and deny in one class per surface. |
| Put broker fields at top level | Unknown top-level attributes fail strict OCSF validation; `unmapped` is the schema's place for them. |
| Accept the sink token on the command line | Leaks into shell history and `ps`; secret references are how every other credential is read. |

## Consequences

- SIEM delivery is batch (cron or CI job running `broker audit export --from-seq`), not live. A live exporter is M3+ control-plane work.
- The validator checks a captured subset of 1.9.0 (not the full JSON schema with every object's types); the fixture test is `m2_ocsf::c4_events_validate_and_reach_the_sinks`. A full-schema validation against the OCSF validator service is left for [[M4 Harden and Ship]].
- The HEC and OTLP bodies were checked against local fakes, not a live Splunk or OpenTelemetry Collector.
- OTel GenAI/agent semantic conventions are not used (the OCSF body is the payload); that part of the open question stays open.

## Invariants affected

Upholds I9 (export from the verified prefix only; chain hash in each event) and I1 (no secret in any exported field; sink token by reference only). Weakens none.

## Relationships

- decided-by:: M2 build
- supersedes::
- motivated-by:: [[Audit Recorder and Event Schema]], [[M2 Policy Audit and Learn]] C4

## Build log

- 2026-09-24: created and built. Code: `code/crates/audit/src/ocsf.rs`, `code/crates/audit/src/otlp.rs`, `code/crates/audit/src/store.rs` (`range`), `code/crates/broker-cli/src/cmd/export.rs`. Tests: `ocsf::tests::classes_map_and_validate`, `otlp::tests::wraps_each_event`, `m2_ocsf::c4_events_validate_and_reach_the_sinks` (100% of decisions validate; HEC sink receives every event with the token from `env:`; OTLP collector receives one record per decision; plain HTTP to a non-loopback sink refused; `--from-seq` resumes).
