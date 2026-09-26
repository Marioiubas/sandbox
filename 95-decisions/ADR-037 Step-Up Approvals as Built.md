---
title: "ADR-037 Step-Up Approvals as Built"
aliases: ["ADR-037"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/approval, topic/policy, boundary/tb1, invariant/i8, invariant/i9, milestone/m3]
status: built
confidence: medium
created: 2026-09-26
updated: 2026-09-26
summary: "A request denied only for want of a human approval (`needs_approval`, `rule_of_two`, `public_sink_after_untrusted_input`) leaves a pending approval naming the exact actions (the authority diff); `broker approvals` shows it with the provenance of the session's labels from the audit log, and `broker approve <id>` grants it once (or `--for-session`) through the control socket, which no sandbox can reach. Approved actions see `context.session.approved` only for themselves; single-use approvals are consumed by the allowed request; everything is logged (`approval.requested`, `approval.granted`, `approvals_used`)."
related: ["[[Fatigue-Resistant Approval Interfaces]]", "[[Broker CLI and Daemon]]", "[[Trifecta Session Labels]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[ADR-033 Public-Sink Rule as Built]]", "[[ADR-036 Git Fetch Visibility by Anonymous Probe]]", "[[I8 No Flag Disables Isolation]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
---

# ADR-037 Step-Up Approvals as Built

> An approval names one exact action, is given by the human on the host, and is shown with ground truth rather than the agent's account.

## Status

built (2026-09-26, M3). The MCP tool path (`rule-of-two-mcp`) is not covered yet.

## Context

The default policy's approval-conditional forbids (`publish-needs-approval`, `rule-of-two`, `rule-of-two-verbs`, the merge rule, the opt-in public-sink rule) all end in `unless { context.session.approved }`, but nothing ever set `approved`: every such decision was a permanent deny. With [[ADR-036 Git Fetch Visibility by Anonymous Probe]] the Rule of Two fires in a common flow (clone a private repository, read a public issue, push), so the missing approval path turned a checkpoint into a dead end. The design is specified as a Proposal in [[Broker CLI and Daemon]] (`needs_approval` with an `authority_diff`, approvals by the human via the CLI) and [[Fatigue-Resistant Approval Interfaces]] (render the authority diff and the provenance of the request from structured data, never the model's prose; prompt only for approval-gated verbs).

## Decision

1. **What is approved**: an *approval key* naming one exact action: `git.push <repo> <ref> force=<bool>` (a force push is never the same approval as a fast-forward), `github <verb> <repo|host>`, `http <METHOD> <host[:port]><path>`, `<s3 op> <host>/<bucket>/<key>` (`policy::approvals::approval_key`). Approvals live in the session's policy (`EgressPolicy::approvals`) and die with the session.
2. **Decision**: each Cedar request sets `context.session.approved` for its own action only when its key is approved; every other rule still applies (the approval lifts approval-conditional forbids, nothing else).
3. **Pending**: when a request is denied with an approval reason, the broker decides again as if the blocked actions were approved; only if that allows the request does it record a pending approval (`apr-…`, random, per session, deduplicated, at most 32 per session, 30-minute expiry) and log `approval.requested` (reason, authority diff, labels) before answering. If the event cannot be logged, there is no approval (I9). The denial tells the agent to ask the user to run `broker approve <id>` outside the sandbox.
4. **Review and grant** (host only): `broker approvals [--json]` lists each pending approval with its authority diff, the denied request, and the requests that raised the session's labels (from `session.label` audit events). `broker approve <id>` prints the same, asks for confirmation on a terminal (`--yes` for scripts; without a terminal and without `--yes` it refuses), and grants once, or for the rest of the session with `--for-session`. `approval.granted` (approval, scope, approver, diff) is logged before the grant takes effect.
5. **Use**: an allowed request that relies on approvals lists them in its decision row (`approvals_used`); single-use approvals are consumed once that row is written.
6. **Reach**: approvals go through the daemon's control socket, which no sandbox can reach, so an agent cannot approve its own request (tested).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| A session-wide `approved` flag | One approval would lift every approval-gated rule for the session. |
| Approve by prose ("allow the PR?") | Fatigue research: prompts must show the authority diff and provenance from structured data. |
| Approvals that outlive the session | Session state and labels reset per session; a stored approval would apply to a context nobody reviewed. |
| Prompt inside the agent's terminal | The agent's terminal is agent-controlled output; the approval must come from the host. |

## Consequences

- Approval-gated decisions are recoverable: the user reviews and approves; the agent retries.
- `--yes` skips only the confirmation of one reviewed approval; it cannot approve anything unnamed, and no flag disables the check ([[I8 No Flag Disables Isolation]]).
- **Not built**: approvals for MCP tool calls (`rule-of-two-mcp`), notifications (Slack/Teams, phase 2), approval telemetry for the fatigue study, and `grant.request` on the control API.

## Invariants affected

Upholds I8 and I9; the control socket's unreachability from the sandbox is what keeps TB1 intact. Weakens none: an approval lifts only rules written as approval-conditional.

## Tests

`policy::approvals::tests::*`, `policy::cedar::github_tests::a_human_approval_lifts_exactly_one_action_once`, `brokerd::approvals::tests::*`, and `m3_approvals::a_held_write_is_approved_on_the_host_once_and_never_from_inside` (the agent's own `broker approve` from inside the sandbox fails; a non-terminal approve without `--yes` refuses; the approved retry passes once and the next PR is held again; one allowed row lists `approvals_used`; only the approved PR reached the upstream; audit chain verifies).
