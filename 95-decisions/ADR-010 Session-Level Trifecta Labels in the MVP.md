---
title: "ADR-010 Session-Level Trifecta Labels in the MVP"
aliases: ["ADR-010"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/ifc, topic/policy, control/task-tok, control/hitl, invariant/i3, milestone/m3]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-25
summary: "Ship session-level trifecta labels sourced from systems of record in the MVP; defer CaMeL-style interpreters and FIDES planners."
related: ["[[Trifecta Session Labels]]", "[[CaMeL]]", "[[FIDES]]", "[[AgentDyn]]", "[[Information Flow Control]]", "[[Provenance-Aware Cedar]]", "[[Credential Broker as Label Authority]]", "[[Lethal Trifecta]]", "[[Agents Rule of Two]]", "[[GitHub MCP Toxic Flow]]", "[[GitLost GitHub Agentic Workflows Leak]]", "[[Cedar]]", "[[I3 Probabilistic Components Only Narrow]]", "[[Threat Model Non-Goals]]", "[[M3 CI Identity and MCP]]", "[[L3 Real-Work Utility]]", "[[Broker Cedar Schema]]", "[[Example Cedar Policies]]", "[[GitHub API Adapter]]", "[[Policy Engine and Entity Builder]]", "[[MOC Decisions]]"]
sources: ["https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/", "https://ai.meta.com/blog/practical-ai-agent-security/", "https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/", "https://invariantlabs.ai/blog/mcp-github-vulnerability", "https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html", "https://arxiv.org/html/2503.18813", "https://arxiv.org/html/2505.23643", "https://arxiv.org/html/2602.03117v1", "https://arxiv.org/html/2601.09923v1", "https://arxiv.org/html/2609.14003", "https://arxiv.org/abs/2608.30041", "https://arxiv.org/abs/2502.08966", "https://arxiv.org/html/2510.09023"]
superseded_by:
---

# ADR-010 Session-Level Trifecta Labels in the MVP

> Ship session-level trifecta labels sourced from systems of record in the MVP; defer CaMeL-style interpreters and FIDES planners.

## Status

Proposed (2026-09-24). Delivered by [[M3 CI Identity and MCP]] ("trifecta context"), whose acceptance criterion is that a replay of the GitHub MCP toxic flow is stopped at the public write.

## Context

The recurring incident shape is the **lethal trifecta**: private data, untrusted content and external communication in one session ([Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)). Meta's "Rule of Two" restates it as a per-session invariant ([Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/)). In the GitHub MCP toxic flow, a public issue drove an agent holding an all-repo PAT to read private repos and leak them through a public PR ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)). In "GitLost", a public issue made an org-read agent post a private README, and the output scanner was bypassed by prefixing "Additionally," ([The Hacker News](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)). Both leaks used an allowed host, so domain allowlists alone do not stop them.

Full information-flow control would. The research record, though, shows what it costs on realistic tasks:

- **[[CaMeL]]** solves 77% of AgentDojo tasks against 84% undefended and cut attacks on GPT-4o to zero, at 2.7–2.8x tokens ([arXiv 2503.18813](https://arxiv.org/html/2503.18813)). On [[AgentDyn]]'s open-ended tasks it scores **zero utility** because its static plan is too rigid ([arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)).
- **[[FIDES]]** cut successful injections from 21/152 to 3/152 with policies, but task completion fell to 41–59% against up to 98.8% for the basic planner. Its labels must be annotated or inferred, and it notes over-conservative label propagation ([arXiv 2505.23643](https://arxiv.org/html/2505.23643)). Its iterative variant cost 29.6x tokens in the computer-use adaptation ([arXiv 2601.09923](https://arxiv.org/html/2601.09923v1)).
- **AgentDyn** (60 open-ended tasks, 560 injection cases, 7.1 average steps against AgentDojo's 3.49) concludes that "almost all existing defenses are either not secure enough or suffer from significant over-defense" ([arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)).
- **Where labels come from matters.** RTBAS decides label propagation with an LM judge, which is probabilistic ([arXiv 2502.08966](https://arxiv.org/abs/2502.08966)). FlowSeal derives provenance labels from systems of record and reaches 0–3.3% leakage at 72.4% benign utility ([arXiv 2609.14003](https://arxiv.org/html/2609.14003)). SkillGuard restricts future capabilities once untrusted data enters state, with no extra inference, and eliminated attacks on 3 of 4 AgentDojo suites ([arXiv 2608.30041](https://arxiv.org/abs/2608.30041)). Model-based defenses were broken adaptively at 71–100% ([arXiv 2510.09023](https://arxiv.org/html/2510.09023)).

A structural constraint applies as well. The broker wraps unmodified vendor agents. It sees requests, not the agent's plan or its individual values. **Proposal (inference):** a per-value interpreter or planner cannot be imposed on Claude Code or Codex from outside; the broker can only label what crosses its own boundary. Cedar also cannot express information-flow properties in stateless request authorization; it checks only the labels it is given ([[Cedar]]; [[Information Flow Control]]).

## Decision

**Proposal.** The MVP ships three boolean session labels, computed only by the broker from systems of record, and enforced in [[Cedar]] ([[Trifecta Session Labels]]):

| Label | Flips to true when |
|---|---|
| `sensitive_read` | the session reads a private repository (the broker knows repo visibility from the API it proxies) or uses a high-risk credential |
| `untrusted_input` | the session fetches content anyone can write: public-repo issues and PRs, arbitrary web pages, ticket bodies from designated sources |
| `external_effect` | any write-class action |

1. Labels only ever flip from false to true within a session. They are never set by the model, a classifier or an LLM judge.
2. The default policy forbids `http.write` and `git.push` when `untrusted_input && sensitive_read`, unless the session holds an out-of-band approval (the Rule of Two forbid in [[Example Cedar Policies]]).
3. An org policy may additionally forbid writes to public sinks whenever `untrusted_input` is set. This answers Willison's point that "[A]+[C] without [B]" is still dangerous ([simonwillison.net](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)).
4. Sequence rules (Invariant's `->`) become a small automaton in the broker, exposed as context attributes, so each per-call decision stays analyzable.
5. One `broker run` invocation is one session. Label flips and the requests that caused them are audit events.
6. **Not in the MVP:** a CaMeL-style interpreter, a FIDES planner, per-value or per-argument labels, and any LLM-decided label.

**Testable as:** the M3 GitHub MCP toxic-flow replay is denied at the public write with a reason naming both labels; a session that reads a public issue in a public repo and then opens a PR on that same repo is allowed.

## Alternatives considered

| Alternative | Pros | Cons | Why rejected |
|---|---|---|---|
| **CaMeL-style interpreter** | Per-value provenance; attacks on GPT-4o to zero on AgentDojo | Needs control of the agent loop; zero utility on open-ended AgentDyn tasks; 2.7–2.8x tokens | Incompatible with wrapping unmodified agents; utility collapse on the tasks our users run |
| **FIDES planner** | Confidentiality × integrity labels; selective hiding | Annotation burden; completion 41–59%; label creep | Same integration problem; annotation is what the broker can replace |
| **No labels (domain and verb rules only)** | Simplest | GitHub MCP and GitLost leaks used allowed hosts | Misses the dominant incident shape |
| **LLM-judged labels** | Finer grain | Probabilistic; adaptive attacks break model-based judgements | Violates [[I3 Probabilistic Components Only Narrow]] |
| **Per-argument provenance in Cedar now** | Precise; analyzable | Unsolved research problem; no paper in the record combines IFC with a verified engine | Deferred to [[Provenance-Aware Cedar]] |

## Consequences

- **Easier:** the Rule of Two becomes an enforced, SymCC-checkable rule instead of advice, with no model in the decision path and near-zero runtime cost.
- **Harder:** session-level labels inherit IFC's classic **label creep**. After one public-issue read, the whole session is tainted. The mitigation is small tasks: a fresh session per task rather than one long-lived taint.
- **Riskier:** false denies on legitimate "read issue, touch private code, push" workflows. Each one costs an approval, and users approve 93% of permission prompts (report, approval-fatigue paragraph), so approvals must show an authority diff.
- **Not covered:** misuse inside granted scope, text-only manipulation, and exfiltration through channels the broker does not see ([[Threat Model Non-Goals]]).
- The label definitions (what counts as a high-risk credential or a designated ticket source) become policy the org must maintain.

## Revisit triggers

- L3 or L2 runs show the trifecta forbid blocking more than the proposed ≤2% of tasks through a necessary action ([[L3 Real-Work Utility]]).
- Agent vendors expose a stable plan or tool-call hook that lets the broker see values, not just requests.
- [[Provenance-Aware Cedar]] or [[Credential Broker as Label Authority]] produce a schema and monitor that keep utility on AgentDyn.
- An incident in which the three labels were correct and the leak still happened.

## Invariants and components affected

- **Upholds [[I3 Probabilistic Components Only Narrow]]:** labels are deterministic, and nothing probabilistic can clear one.
- **Upholds I9:** label flips and approvals are logged outside the sandbox.
- **Weakens nothing.** Approvals relax only the trifecta forbid for one session, and only out of band.
- Components: [[Trifecta Session Labels]], [[Policy Engine and Entity Builder]] (session context), [[GitHub API Adapter]] (visibility lookups), [[Broker Cedar Schema]] (`Trifecta` type).

## How it connects

- motivated-by:: [[Lethal Trifecta]]
- motivated-by:: [[Agents Rule of Two]]
- motivated-by:: [[AgentDyn]]
- mitigates:: [[GitHub MCP Toxic Flow]]
- mitigates:: [[GitLost GitHub Agentic Workflows Leak]]
- depends-on:: [[Trifecta Session Labels]]
- depends-on:: [[Cedar]]
- contrasts-with:: [[CaMeL]]
- contrasts-with:: [[FIDES]]
- example-of:: [[Information Flow Control]] (coarse, session-level)
- implements:: [[I3 Probabilistic Components Only Narrow]]
- contrasts-with:: [[Provenance-Aware Cedar]] (the per-value research direction that may supersede this ADR)
- depends-on:: [[Credential Broker as Label Authority]] (the principle this ADR applies at session grain)
- evaluated-by:: [[L3 Real-Work Utility]]
- delivered-by:: [[M3 CI Identity and MCP]]
- part-of:: [[MOC Decisions]]

## Implications for the build

- Put the label computation in the entity builder, fed by adapter facts (repo visibility, host class), never by request bodies the agent controls.
- Store the source request ID of each flip, so `broker why` can say "denied because request 812 read private repo X and request 790 fetched public issue Y".
- Default `broker run` to one session per invocation, and warn when a session's age or request count suggests label creep.
- Add the toxic-flow and GitLost replays to the L1 and L2 fixtures.

## Open questions

- Should labels cover MCP tool results (an issue read through a wrapped GitHub MCP server) in M3, or only direct HTTP? The record defines labels at the broker boundary, which includes relayed MCP traffic.
- Which credentials count as "high-risk" by default? Not specified in the record.
- The FlowSeal date conflicts (the fetched page said September 2024; the arXiv ID implies September 2026); treat the date as unverified.

## Sources

- [Simon Willison: the lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [Meta AI: practical AI agent security](https://ai.meta.com/blog/practical-ai-agent-security/)
- [Simon Willison: new prompt injection papers](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- [Invariant Labs: GitHub MCP vulnerability](https://invariantlabs.ai/blog/mcp-github-vulnerability)
- [The Hacker News: GitLost](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)
- [CaMeL, arXiv 2503.18813](https://arxiv.org/html/2503.18813)
- [FIDES, arXiv 2505.23643](https://arxiv.org/html/2505.23643)
- [AgentDyn, arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)
- [CaMeLs Can Use Computers Too, arXiv 2601.09923](https://arxiv.org/html/2601.09923v1)
- [FlowSeal, arXiv 2609.14003](https://arxiv.org/html/2609.14003)
- [SkillGuard, arXiv 2608.30041](https://arxiv.org/abs/2608.30041)
- [RTBAS, arXiv 2502.08966](https://arxiv.org/abs/2502.08966)
- [The Attacker Moves Second, arXiv 2510.09023](https://arxiv.org/html/2510.09023)
- Report: decisions row "IFC depth in MVP" and the label-creep paragraph; research note 02 Q2, Q5 and Q6.

## Build log

- 2026-09-25: item 3 (the optional public-sink rule) is built as [[ADR-033 Public-Sink Rule as Built]].
