---
title: "ADR-039 Model API Is Not a Rule-of-Two Sink"
aliases: ["ADR-039"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, topic/credentials, invariant/i4, invariant/i7, milestone/m3]
status: built
confidence: medium
created: 2026-09-26
updated: 2026-09-26
summary: "A profile, user or org grant may mark its host `model_api = true` (the agent's own model provider API); HTTP requests to it carry `context.model_api` and the Rule-of-Two forbid skips them, so an agent does not lose its model once a session holds both labels. Repository policy cannot set it (I4), only plain HTTP grants can, and the shipped agent profiles mark their model APIs."
related: ["[[Trifecta Session Labels]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[ADR-036 Git Fetch Visibility by Anonymous Probe]]", "[[ADR-037 Step-Up Approvals as Built]]", "[[I4 Repo Policy Only Narrows]]", "[[I7 Reject Foreign Credentials]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
---

# ADR-039 Model API Is Not a Rule-of-Two Sink

> The agent's own model is where everything it reads already goes; sending there is not an exfiltration channel the Rule of Two can close.

## Status

built (2026-09-26, M3).

## Context

A review found that once a session holds both `untrusted_input` and `sensitive_read`, the agent's own calls to its model API (`POST api.anthropic.com/v1/messages` on a terminated grant with a brokered credential) are `http.write` requests, so the `rule-of-two` forbid refuses them and the agent loses its model mid-session. [[ADR-036 Git Fetch Visibility by Anonymous Probe]] made "both labels" common (clone a private repository, read a public issue), so this turned a safety rule into an outage.

The model provider already receives everything the agent reads; with [[I7 Reject Foreign Credentials]] the only credential that reaches it is the user's own (brokered), so data sent there lands in the user's own account, not an attacker's. Requiring approval for every model call would teach users to approve everything ([[Fatigue-Resistant Approval Interfaces]]).

## Decision

1. `model_api = true` on an `[[egress]]` entry marks the host as the agent's model provider API. It is accepted in profile, user and org policy; a repository layer that sets it is a compile error (it would widen, [[I4 Repo Policy Only Narrows]]); only plain HTTP grants may set it.
2. An HTTP action on a host whose admitting grants all carry `model_api` has `context.model_api = true` (schema `HttpCtx.model_api`), and the `rule-of-two` forbid in `code/policies/default.cedar` skips it. Every other rule (methods, paths, credential binding, foreign credentials, the task-expiry forbid) still applies.
3. The shipped profiles mark `api.anthropic.com` (claude-code, claude-code-apikey), `api.openai.com` (codex), `generativelanguage.googleapis.com` (gemini-cli) and `api2.cursor.sh` (cursor-agent).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Exempt hosts with a brokered credential | Would exempt every credentialed API, including ones an attacker can read (issue trackers, chat). |
| Require approval for model calls after both labels | Every model turn would prompt; approval fatigue makes the prompt meaningless. |
| Let repository policy mark model APIs | A repository could declare a paste site its "model"; only narrowing layers are allowed there. |

## Consequences

- Sessions keep their model after both labels are live; writes elsewhere still need approval.
- **Residual:** an injected agent can still put private data into the user's own model-provider account (its logs, files or batches); that account is the user's, and model-provider data handling is outside this product's boundary ([[Threat Model Non-Goals]]).

## Invariants affected

Upholds I4 (repository policy cannot set it) and I7 (only the user's brokered credential reaches the model API). Narrows nothing and widens only the Rule of Two for hosts the user's own profile names.

## Tests

`policy::cedar::github_tests::the_model_api_is_not_a_write_destination_for_the_rule_of_two` (with both labels live: `POST` to the model API passes, `POST` elsewhere is held; a GitHub grant and a repository layer cannot set `model_api`); `brokerd` profile tests compile the marked profiles.
