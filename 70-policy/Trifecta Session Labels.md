---
title: "Trifecta Session Labels"
aliases: ["Trifecta Context", "Sequence Rules", "Invariant Guardrails", "Session Taint"]
type: concept
section: policy
tags: [sandbox/policy, concept, topic/ifc, topic/policy, control/hitl, control/task-tok, milestone/m3, evidence/conflict]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-25
summary: "How the broker computes untrusted_input, sensitive_read and external_effect from systems of record, enforces Rule of Two as a Cedar forbid, optionally forbids public-sink writes whenever untrusted_input is set, limits label creep with one session per task, and exposes sequence rules (Invariant's '->') as automaton context."
related: ["[[Lethal Trifecta]]", "[[Agents Rule of Two]]", "[[Example Cedar Policies]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[Information Flow Control]]", "[[Policy Engine and Entity Builder]]", "[[GitHub MCP Toxic Flow]]", "[[Credential Broker as Label Authority]]", "[[M3 CI Identity and MCP]]", "[[Provenance-Aware Cedar]]", "[[Supabase MCP Token Leak]]", "[[Broker Cedar Schema]]", "[[GitLost GitHub Agentic Workflows Leak]]", "[[CaMeL]]", "[[FIDES]]", "[[Cedar]]", "[[GitHub API Adapter]]", "[[MCP Guard]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/", "https://ai.meta.com/blog/practical-ai-agent-security/", "https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/", "https://invariantlabs.ai/blog/mcp-github-vulnerability", "https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html", "https://generalanalysis.com/blog/supabase-mcp-blog", "https://github.com/invariantlabs-ai/invariant", "https://arxiv.org/html/2609.14003", "https://arxiv.org/abs/2608.30041", "https://arxiv.org/html/2505.23643", "https://arxiv.org/html/2602.03117v1", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/"]
---

# Trifecta Session Labels

> How the broker computes untrusted_input, sensitive_read and external_effect from systems of record, enforces Rule of Two as a Cedar forbid, optionally forbids public-sink writes whenever untrusted_input is set, limits label creep with one session per task, and exposes sequence rules (Invariant's '->') as automaton context.

## Summary

The lethal trifecta is private data, untrusted content and external communication in one session ([Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)). Meta's "Agents Rule of Two" restates it as a per-session invariant: satisfy at most two of [A] untrustworthy inputs, [B] sensitive systems or private data, [C] state change or external communication ([Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/)). Cedar cannot express information flow, so it can only check labels it is given ([[Cedar]]). This note specifies how the broker, the only component that sees every system of record, computes three session-level booleans and hands them to Cedar as `context.session.trifecta`. The MVP choice of session-level rather than per-value labels is [[ADR-010 Session-Level Trifecta Labels in the MVP]].

## Details

### Label definitions

**Proposal:** Labels are set only by the broker, from facts it observes in protocol traffic or from credential metadata. They are never set by the model, the agent, or content inside the sandbox.

| Label | Flips to true when | Evidence source the broker controls |
|---|---|---|
| `sensitive_read` | The session reads a private repo, or uses a credential whose `risk` is high | Repo `visibility` from the GitHub API responses the broker proxies ([[GitHub API Adapter]]); `Credential.risk` from issuer config |
| `untrusted_input` | The session fetches content anyone can write: public-repo issues and PRs, arbitrary web pages, ticket bodies from designated sources | Adapter classification of the response (public repo + issue/PR/comment endpoints; hosts not on a trusted-content list) |
| `external_effect` | Any write-class action: `http.write`, `git.push`, `pkg.publish`, write-class MCP tools | The action being authorized |

Labels are **sticky** for the session: once true, they stay true until the session ends. This is the coarse, monotone form: "taint narrows the grant set". SkillGuard's evaluated version restricts future capabilities once untrusted data enters state, with no extra inference, and eliminated attacks on 3 of 4 AgentDojo suites ([arXiv 2608.30041](https://arxiv.org/abs/2608.30041)).

The principle is FlowSeal's: **labels come from systems, not the model** ([arXiv 2609.14003](https://arxiv.org/html/2609.14003)). FIDES showed labels work but left open who annotates them ([arXiv 2505.23643](https://arxiv.org/html/2505.23643)). Credential and repo metadata close that gap; the research version is [[Credential Broker as Label Authority]].

**Proposal (from the incidents research note):** also label each *grant* at issue time as A, B or C. A session that would hold all three at once then triggers supervision or a context reset *before* any request is made, not only at the write.

### Enforcement in Cedar

The Rule of Two forbid (**Proposal; not compiled**, verbatim from the report):

```cedar
forbid (principal, action in [Broker::Action::"http.write", Broker::Action::"git.push"], resource)
when { context.session.trifecta.untrusted_input && context.session.trifecta.sensitive_read }
unless { context.session.approved };
```

When A and B are both live, any C needs out-of-band approval. This would have stopped the GitHub MCP toxic flow and GitLost at the public-write step ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability); [The Hacker News](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)). In the Supabase MCP case, a support-ticket injection copied `integration_tokens` back into the ticket thread ([General Analysis](https://generalanalysis.com/blog/supabase-mcp-blog)). **Proposal:** treat writes to externally readable sinks, such as ticket threads and public comments, as `external_effect`.

> [!warning] Conflict
> Meta calls [A]+[C] without [B] "lower risk" (changed from "safe"). Willison and the design-patterns paper say it is still dangerous, because injection can still drive state changes ([simonwillison.net](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)). **Proposal:** offer an org-policy forbid on public-sink writes whenever `untrusted_input` is set, regardless of `sensitive_read` (sketch in [[Example Cedar Policies]]). Do not treat "no private data" as sufficient for autonomous state change on untrusted input.

### Label creep and task sizing

A session-level label inherits information-flow control's classic label-creep problem: after one public-issue read, everything the session does is tainted. **Proposal:** keep tasks small. Start a fresh session per task rather than carrying one long-lived taint, so `broker run` defaults to one session per invocation. Label creep is also why per-value labels are the research direction ([[Provenance-Aware Cedar]], [[Information Flow Control]]).

This is a utility trade. On dynamic tasks, capability systems lose most of their utility: AgentDyn found CaMeL at zero utility on open-ended tasks ([arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)). Session labels are coarser than CaMeL's per-value tracking ([[CaMeL]]) but deterministic and cheap, which is the argument in [[ADR-010 Session-Level Trifecta Labels in the MVP]].

### Sequence rules as automaton context

Invariant's guardrail language has a `->` operator that matches ordered tool-call sequences, such as `get_inbox` followed by `send_email` to an external address. Its standard library includes ML detectors such as `prompt_injection()` with configurable thresholds, and it is Apache-2.0 ([GitHub](https://github.com/invariantlabs-ai/invariant)). Cedar has no temporal operator.

**Proposal:** Implement sequences as a small deterministic automaton in `brokerd`, one per session. Each authorized request advances it, and its state is exposed as extra context booleans (for example `context.session.seen.inbox_read`). Each per-call decision then stays a stateless, SymCC-analyzable Cedar request. ML detectors are **not** imported as label sources. They may emit alerts, and under [[I3 Probabilistic Components Only Narrow]] they may only ever set a label to true, never clear one.

### Worked example

A CI job fixes a bug reported in a public issue on the private repo `acme/web`:

1. `GET /repos/acme/web` → the response says `visibility: private` → `sensitive_read = true`.
2. `GET /repos/acme/web/issues/42` → issue text on a public-writable surface → `untrusted_input = true`. **Proposal:** for a private repo, only issues from outside collaborators count; the adapter decides from author association if the API response carries it (not in the record; verify).
3. `git.push refs/heads/agent/fix-42` → `external_effect` on a write → the Rule of Two forbid fires → the broker pauses and asks for approval, showing the authority diff ([[Fatigue-Resistant Approval Interfaces]]).
4. On approval, `session.approved = true` for that request only, and the push proceeds.

## Evidence

- Trifecta and Rule of Two: [Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/); [Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/).
- AgentCore Policy authorizes calls on inputs and identity, but its docs describe no data-flow control; adding provenance and trifecta context is listed as the improvement ([AWS](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)).

## How it connects

- implements:: [[Agents Rule of Two]]
- motivated-by:: [[Lethal Trifecta]]
- motivated-by:: [[GitHub MCP Toxic Flow]]
- mitigates:: [[GitLost GitHub Agentic Workflows Leak]]
- mitigates:: [[Supabase MCP Token Leak]]
- decided-by:: [[ADR-010 Session-Level Trifecta Labels in the MVP]]
- part-of:: [[Policy Engine and Entity Builder]]
- depends-on:: [[Broker Cedar Schema]]
- example-of:: [[Information Flow Control]]
- contrasts-with:: [[CaMeL]]
- contrasts-with:: [[FIDES]]
- delivered-by:: [[M3 CI Identity and MCP]]
- Research extensions: [[Provenance-Aware Cedar]], [[Credential Broker as Label Authority]]
- Used by: [[Example Cedar Policies]], [[MCP Guard]]

## Implications for the build

- Labels live in `brokerd` session state, outside the sandbox, and are written to the audit row of every decision.
- Adapters must classify responses, not just requests: the private/public signal comes from response bodies. Budget for response parsing on the GitHub adapter.
- Labels are monotone within a session; add a property test that no code path clears one.
- The M3 acceptance test "a replay of the GitHub MCP toxic flow is stopped at the public write" is the primary regression test for this note.

## Open questions

- Which content sources count as `untrusted_input` by default beyond public issues, PRs and arbitrary web pages? Package READMEs? Dependency source?
- Does GitHub's API expose author association on issues and comments reliably enough to label them? Not in the record.
- How should labels propagate to sub-agents and map-reduce workers ([[Revocable Sub-Agent Delegation]])?

## Sources

- [Willison: lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/); [Willison: Nov 2025](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- [Meta AI: Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/)
- [Invariant Labs: GitHub MCP](https://invariantlabs.ai/blog/mcp-github-vulnerability); [Invariant guardrails](https://github.com/invariantlabs-ai/invariant)
- [The Hacker News: GitLost](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)
- [General Analysis: Supabase MCP](https://generalanalysis.com/blog/supabase-mcp-blog)
- [FlowSeal](https://arxiv.org/html/2609.14003); [SkillGuard](https://arxiv.org/abs/2608.30041); [FIDES](https://arxiv.org/html/2505.23643); [AgentDyn](https://arxiv.org/html/2602.03117v1)
- [AWS Security Blog: AgentCore Policy](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)

## Build log

- 2026-09-24 (M3): built for GitHub API facts ([[ADR-029 GitHub API Adapter and Session Labels as Built]]): raise-only labels (property test), raised before forwarding, shared with a shadow candidate, on every L7 decision row and as `session.label` events; `risk = "high"` credentials raise `sensitive_read`; the Rule-of-Two forbid is now live. Not built: web pages as untrusted input, the public-sink org option, author-association filtering, sequence automata, step-up approval; git clones of private repositories do not raise `sensitive_read` yet. Tests: `m3_github::d5_toxic_flow_is_stopped_at_the_public_write`, `a_public_issue_then_a_pr_on_that_public_repo_is_allowed`.
- 2026-09-25 (M3): the optional org rule is built: `[trifecta] deny_public_sinks_after_untrusted_input = true` denies writes to repositories not known to be private, pushes, gists and package publishes once `untrusted_input` is live ([[ADR-033 Public-Sink Rule as Built]]). S3 reads raise `sensitive_read` and S3 writes `external_effect` ([[ADR-032 AWS STS and S3 Adapter as Built]]).
