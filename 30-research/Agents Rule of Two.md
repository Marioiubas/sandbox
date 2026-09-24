---
title: "Agents Rule of Two"
aliases: ["Rule of Two"]
type: concept
section: research
tags: [sandbox/research, concept, topic/ifc, topic/policy, topic/approval, control/hitl, evidence/conflict]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Meta's per-session rule: satisfy at most two of [A] untrusted input, [B] sensitive access, [C] state change or external communication; and Willison's critique that [A]+[C] without [B] is still dangerous."
related: ["[[Lethal Trifecta]]", "[[Trifecta Session Labels]]", "[[Example Cedar Policies]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[GitLost GitHub Agentic Workflows Leak]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[GitHub MCP Toxic Flow]]", "[[Design Patterns for Securing LLM Agents]]", "[[Information Flow Control]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://ai.meta.com/blog/practical-ai-agent-security/", "https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/", "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/", "https://arxiv.org/html/2506.08837", "https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html", "https://anthropic.com/engineering/claude-code-auto-mode", "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/"]
---

# Agents Rule of Two

Meta's "Agents Rule of Two" says that within one session an agent should satisfy no more than two of three properties: [A] it processes untrustworthy inputs, [B] it accesses sensitive systems or private data, [C] it changes state or communicates externally ([Meta AI, 31 Oct 2025](https://ai.meta.com/blog/practical-ai-agent-security/)). It is a per-session restatement of the [[Lethal Trifecta]] that adds state change to the third leg. The broker enforces it as a Cedar rule over session labels, and adds the stricter reading Willison argues for.

## The rule, as published

From Meta's post ([Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/)):

- [A] processes untrustworthy inputs; [B] accesses sensitive systems or private data; [C] changes state or communicates externally.
- "Agents must satisfy no more than two ... within a session."
- If all three are needed, the agent "should not be permitted to operate autonomously and at a minimum requires supervision".
- The rule is "a supplement — and not a substitute — for common security principles such as least-privilege".

The last point matters for this product: the Rule of Two sits on top of task-scoped credentials and deny-by-default egress; it does not replace them.

## The disagreement: is [A]+[C] safe?

> [!warning] Conflict
> Meta changed its wording for the [A]+[C] combination from "safe" to "lower risk". Willison argues that [A]+[C] without [B] is still dangerous, because an injection can drive a state change even when no private data is involved ([simonwillison.net, 2 Nov 2025](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)). The [[Design Patterns for Securing LLM Agents]] paper agrees in substance: most patterns stop control-flow hijack but still allow manipulation of data parameters ([arXiv 2506.08837](https://arxiv.org/html/2506.08837)). Tracked in [[Open Questions and Unverified Claims]].

The research resolution (research note 02, Q6): the product should **not** treat "no private data" as sufficient to allow autonomous state change on untrusted input. An agent that read a public issue and then pushes code, opens a PR or publishes a package is [A]+[C], and it is exactly the shape of supply-chain and CI incidents.

## Why a heuristic is not enough

As written, the Rule of Two relies on the agent designer to classify their own system. Nothing checks it at runtime, and a session's properties change as it runs: a coding agent starts with [B] (the private repo) and [C] (git push), and acquires [A] the moment it fetches a public issue. [[GitLost GitHub Agentic Workflows Leak]] shows the failure: a public issue made an org-read agent post a private README, and an output scanner was bypassed by prefixing "Additionally," ([The Hacker News](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)). Output classifiers do not replace scoping. [[GitHub MCP Toxic Flow]] is the same shape.

## How the broker enforces it

**Proposal.** The broker maintains three session labels ([[Trifecta Session Labels]]) mapped to the rule's letters:

| Rule of Two | Session label | Flipped by (broker-observed) |
|---|---|---|
| [A] untrusted input | `untrusted_input` | Fetching content anyone can write: public-repo issues and PRs, arbitrary web pages, designated ticket sources |
| [B] sensitive access | `sensitive_read` | Reading a private repo (visibility from the forge API) or using a high-risk credential |
| [C] state change / external comms | `external_effect` | Any write-class action |

The org rule from the report ([[Example Cedar Policies]]; Proposal, not compiled): once `untrusted_input` and `sensitive_read` are both live, `http.write` and `git.push` need out-of-band approval. The report adds that org policy can **additionally** forbid public-sink writes whenever `untrusted_input` is set, which answers Willison's [A]+[C] critique.

"Requires supervision" becomes an approval prompt, which brings in fatigue. Users approve 93% of Claude Code permission prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)), and OWASP lists "Overwhelming HITL" as threat T10 ([OWASP](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)). The gate must therefore fire rarely and show an authority diff, not prose ([[Fatigue-Resistant Approval Interfaces]]).

## Adopt / Improve / Add

- **Adopt:** The three-property taxonomy as the schema of session labels, and "all three means supervision" as the default org rule.
- **Improve:** **Proposal:** labels computed by the broker from systems of record, updated live as the session runs, and exposed to Cedar, so the rule is enforced and analyzable rather than self-assessed at design time.
- **Add:** **Proposal:** a stricter optional org rule for [A]+[C] on public sinks (per Willison), and a context-reset path: instead of approving, the user can start a fresh session without the tainted input, which also limits label creep ([[ADR-010 Session-Level Trifecta Labels in the MVP]]).

## How it connects

- part-of:: [[Lethal Trifecta]]
- mitigated-by:: [[Trifecta Session Labels]]
- decided-by:: [[ADR-010 Session-Level Trifecta Labels in the MVP]]
- depends-on:: [[Fatigue-Resistant Approval Interfaces]]
- contrasts-with:: [[Design Patterns for Securing LLM Agents]]

The rule is coarse [[Information Flow Control]]; its policy text lives in [[Example Cedar Policies]]. Incidents it would stop: [[GitLost GitHub Agentic Workflows Leak]], [[GitHub MCP Toxic Flow]].

## Implications for the build

- Ship the Rule-of-Two forbid in the default org ceiling; make the [A]+[C]-public-sink rule a documented, recommended org option.
- The approval path must show which labels are live and which grant the write would use; approvals are logged with the label state.
- Tests: a session that reads a public issue and a private repo and then attempts `git.push` must be denied without approval (M3 GitHub MCP replay).

## Open questions

- Whether [A]+[C] should be denied by default rather than as an org option: product decision, needs an ADR once design-partner data exists.
- No user study of approval fatigue for agent capability prompts exists in the record.

## Sources

- [Meta AI, Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/)
- [Willison, new prompt injection papers (2 Nov 2025)](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/); [Willison, lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [Design Patterns, arXiv 2506.08837](https://arxiv.org/html/2506.08837)
- [The Hacker News, GitLost](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)
- [Anthropic, auto mode](https://anthropic.com/engineering/claude-code-auto-mode); [OWASP Agentic AI threats](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
