---
title: "ADR-038 MCP Server Sessions Share Agent Labels"
aliases: ["ADR-038"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/mcp, topic/ifc, topic/policy, invariant/i9, milestone/m3]
status: built
confidence: medium
created: 2026-09-26
updated: 2026-09-26
summary: "A pinned MCP server's session is started for one agent session and carries that session's raise-only labels, never fresh ones: what the server's egress reads or writes raises the agent's labels, and the server's own requests are judged with them (Rule of Two, public-sink rule). Starting a server requires the agent session's labels, so there is no fallback path. Label rows go on the agent session and name the server session and request that raised them. Closes the toxic flow through an MCP server."
related: ["[[ADR-030 MCP Guard as Built]]", "[[ADR-040 Label Sources Beyond the Adapters]]", "[[Trifecta Session Labels]]", "[[MCP Guard]]", "[[GitHub MCP Toxic Flow]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[ADR-037 Step-Up Approvals as Built]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[M3 CI Identity and MCP]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
code: ["code/crates/brokerd/src/labels.rs", "code/crates/brokerd/src/session/assemble.rs", "code/crates/brokerd/src/session/mcp_launch.rs", "code/crates/brokerd/src/mcp/mod.rs", "code/crates/brokerd/src/approvals.rs", "code/tests/conformance/tests/m3_label_gaps_mcp.rs"]
---

# ADR-038 MCP Server Sessions Share Agent Labels

> An MCP server acts for one agent session, so it reads, writes and is judged with that session's labels.

## Status

built (2026-09-26, M3). Amends [[ADR-030 MCP Guard as Built]] items 3 (the server's session had labels of its own) and 5 (the relay's `tools.write` / `tools.untrusted` lists were the only way MCP use reached the agent's labels).

## Context

[[ADR-030 MCP Guard as Built]] starts each pinned server as its own sandboxed session with its own policy. That policy was compiled fresh, so its labels were fresh too (`EgressPolicy::compile_with` starts with empty labels; only a shadow candidate shared them). The relay raised `external_effect` and `untrusted_input` in the agent's session from the operator's `tools.write` and `tools.untrusted` lists, and never `sensitive_read`. A security review on 2026-09-26 proved three gaps with a failing test (`m3_label_gaps_mcp`):

1. **Toxic flow through a server:** the agent reads a public issue (`untrusted_input`), a GitHub MCP tool reads a private issue (the broker labelled `sensitive_read`, but in the server's session), and the agent opens a pull request on the public repository. The agent's session never held `sensitive_read`, so the Rule of Two did not fire. This is the [[GitHub MCP Toxic Flow]] the M3 acceptance names.
2. **Unlisted write tools:** a tool that writes but is missing from `tools.write` is not a write to the relay, and the server's own egress write was judged against the server's fresh labels, so it passed whatever the agent had read.
3. **What the server reads counts only if the operator says so:** a server reading public issue bodies raised `untrusted_input` only when its tool was listed in `tools.untrusted`.

Labels are per session by design ([[ADR-010 Session-Level Trifecta Labels in the MVP]]). A server is started per connection and serves exactly one agent session (ADR-030, no pooling), so everything it reads flows only into that agent session: the information-flow boundary is the agent session, not the server's sandbox.

## Decision

1. **One set of labels per agent session.** A pinned server's session is started for the agent session whose connection asked for it and carries that session's labels: the same raise-only object, not a copy. What the server's egress shows the broker (a private repository read, public issue bodies, an S3 read, a high-risk credential, a credentialed read or a host marked sensitive ([[ADR-040 Label Sources Beyond the Adapters]]), a write) raises the agent session's labels through the same code as the agent's own requests, before the server's request is forwarded. The server's own requests are judged with those labels, so the Rule of Two and the public-sink rule ([[ADR-033 Public-Sink Rule as Built]]) apply to the server's writes whether or not the tool is in `tools.write`.
2. **No fresh labels, by construction.** `Daemon::start_mcp_server` takes the agent session's `LabelOwner` (its session ID and labels) as a required argument, and session assembly has two kinds: `Agent` (labels of its own) and `McpServer(owner)` (the owner's labels). There is no way to assemble a server session with labels of its own, and so no silent fallback to fresh ones. The only caller is the relay, which runs in the agent session's own pipeline and takes the owner from that session's context. A server session never reaches servers itself (its context has no `mcp`), so owners do not chain.
3. **The relay lists keep their meaning.** `tools.write` and `tools.untrusted` still raise labels at the call, for what the server's egress cannot show (a tool that writes locally, or content from a source no adapter classifies), and `tools.write` still selects the `rule-of-two-mcp` check on the call itself.
4. **Audit (I9).** A `session.label` row is written on the session whose labels changed: the agent session. Its `request_id` is the request that raised the label, and when that request was made in the server's session the row carries `raised_in_session` (the server's session ID). `broker why <request>` therefore shows the server's decision row and the agent session's label row together, and the agent session's rows include every label its servers raised. The server's `session.start` row carries `labels_session` (the agent session); the agent's `mcp.connect` row already names `server_session`. Decision rows in the server's session carry the shared `labels` snapshot they were judged with.
5. **Approvals** ([[ADR-037 Step-Up Approvals as Built]]). A write held in the server's session leaves its pending approval in that session and is granted only into it. The pending approval records `labels_session`, and `broker approvals` reads its provenance from that session's label rows, marking those raised in another session.
6. **Several agent sessions, one server name.** Each connection starts its own server session bound to the connecting agent session. Two agent sessions using the same server name get two server sessions, each with its own agent's labels; nothing crosses between agent sessions.
7. **A server outliving its agent session.** Teardown kills the agent's process group; the stub's connection closes and the relay tears the server session down after outstanding calls, bounded by the 20 s drain window. Until then the server keeps the agent session's final labels (raise-only, so only as strict or stricter), and its label rows name the ended agent session.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Merge the server's labels into the agent's after each `tools/call` | A window between the server's read and the merge; the server's own writes still judged with its own labels; two sets of state to keep in step. |
| Seed the server's labels from the agent's at launch | A snapshot: labels raised later on either side would not flow, and the server's writes would be judged with stale labels. |
| Treat every MCP call as raising all three labels when the agent session is unknown | There is no such case once the owner is a required argument; removing the path at compile time is stronger than a runtime default, and a blanket default would make every write after any MCP use need approval (approval fatigue, [[Fatigue-Resistant Approval Interfaces]]). |
| One shared server session per server name | Would mix labels of different agent sessions or switch them per request; ADR-030 already starts one server per connection. |
| Write the label rows on the server's session | The agent session's audit view and its approval provenance would miss the reads that make its writes need approval. |

## Consequences

- The toxic flow through an MCP server is held at the public write, and an unlisted write tool is held in the server's session with the reason `rule_of_two` and a pending approval.
- More label creep: any private read a server makes now counts toward the agent session's Rule of Two. That is the intended narrowing; keep tasks (and so sessions) small ([[Trifecta Session Labels]]).
- A record-mode agent session's servers still run in enforce mode (as before, ADR-030), now with the agent's labels: a learning run through an MCP server can be held where the agent's own requests would only be recorded. Residual; a server session inheriting its agent's mode is not built.
- An agent session's approvals do not carry to its servers' sessions, nor the reverse (each session's approvals are its own): only narrows.
- Pending approvals for a server's held writes live as long as the server session, which is the agent's MCP connection.
- Labels are read when a call is authorized. A `tools/call` the agent sends before an earlier call's result arrives is judged with the labels as they stand then; it cannot carry that result, and the server's own egress for it is judged again, with the labels as they stand when it happens.

## Invariants affected

Upholds I9: every label raise is a chained row on the session whose labels changed, naming the request and session that raised it. Labels stay raise-only; sharing them with the server can only add denials. Upholds I1 and I5 unchanged (the server still gets sentinels and its definition still comes only from user or org policy). Weakens none.

## Tests

- `m3_label_gaps_mcp::a_private_read_through_an_mcp_server_is_a_sensitive_read_of_the_agent_session` (the failing test from the review; the public PR is now held: `200 MCP 403`).
- `m3_label_gaps_mcp::an_unlisted_write_tool_is_judged_with_the_agent_sessions_labels` (with `tools.write = []` the relay allows the call, the server's comment is denied `rule_of_two` in the server's session and never reaches the API; the `sensitive_read` row is on the agent session with `raised_in_session` and the server's allowed request; the server's `session.start` names `labels_session`; the audit chain verifies).
- `m3_label_gaps_mcp::labels_raised_through_a_server_stay_with_its_agent_session` (a second agent session using the same server name is not affected).
- `brokerd::labels::tests::a_server_session_raises_the_agent_sessions_labels_on_its_record`, `server_sessions_of_different_agents_do_not_share_labels`; `brokerd::approvals::tests::a_held_server_request_names_the_session_whose_labels_held_it`; `policy::cedar::github_tests::a_policy_sharing_labels_is_judged_with_them`.
- `m3_mcp::d3_d4_pinned_server_is_approved_confined_and_revoked_on_change` still passes.

## Relationships

- decided-by:: M3 security review (label gaps)
- amends:: [[ADR-030 MCP Guard as Built]]
- motivated-by:: [[GitHub MCP Toxic Flow]], [[Trifecta Session Labels]]

## Build log

- 2026-09-26: created and built. Code: `code/crates/brokerd/src/labels.rs` (`LabelOwner`, `PipelineCtx::raise_label` / `label_event`), `code/crates/brokerd/src/pipeline.rs` (`labels_session`), `code/crates/brokerd/src/session/{assemble,launch,mcp_launch}.rs` (`SessionKind::McpServer(owner)`), `code/crates/brokerd/src/mcp/{mod,relay}.rs`, `code/crates/brokerd/src/l7_pipeline/{github,approval}.rs` and the admission-time label in `code/crates/brokerd/src/pipeline.rs` (all through `raise_label`), `code/crates/brokerd/src/approvals.rs` and `code/crates/broker-cli/src/cmd/approve.rs` (provenance from `labels_session`), `code/docs/policy-reference.md`. Tests as listed above.
