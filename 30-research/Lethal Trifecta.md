---
title: "Lethal Trifecta"
aliases: ["Trifecta"]
type: concept
section: research
tags: [sandbox/research, concept, topic/ifc, topic/egress, topic/policy, control/egress, control/task-tok, adversary/a1]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Private data plus untrusted content plus external communication in one session equals exfiltration (Willison, Jun 2025); the shape behind most incidents."
related: ["[[Agents Rule of Two]]", "[[Trifecta Session Labels]]", "[[GitHub MCP Toxic Flow]]", "[[Supabase MCP Token Leak]]", "[[EchoLeak M365 Copilot Exfiltration]]", "[[Information Flow Control]]", "[[Example Cedar Policies]]", "[[Problem Statement]]", "[[GitLost GitHub Agentic Workflows Leak]]", "[[Claude Code DNS Exfiltration CVE-2025-55284]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[Broker Cedar Schema]]", "[[The Attacker Moves Second]]"]
sources: ["https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/", "https://ai.meta.com/blog/practical-ai-agent-security/", "https://invariantlabs.ai/blog/mcp-github-vulnerability", "https://generalanalysis.com/blog/supabase-mcp-blog", "https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/", "https://arxiv.org/html/2509.10540v1", "https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html", "https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/"]
---

# Lethal Trifecta

Simon Willison's lethal trifecta says that an agent session which combines **access to private data**, **exposure to untrusted content** and **the ability to communicate externally** can be made to exfiltrate that data, because "LLMs follow instructions in content" ([Simon Willison, 16 Jun 2025](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)). It is the most common shape in the 2025–2026 incident record. This design turns it from advice into a per-session rule that the broker enforces.

## The claim

Willison's argument, 16 June 2025 ([simonwillison.net](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)):

- The three legs: private data, untrusted content, external communication.
- Guardrail vendors' "95%" detection rates are "very much a failing grade" in web application security.
- The recommendation is to "avoid that lethal trifecta combination entirely".
- Affected products named include Microsoft 365 Copilot, the GitHub MCP server, GitLab Duo, ChatGPT/Operator, Bard/NotebookLM/AI Studio, Amazon Q, the Claude iOS app, Slack AI, Grok and Le Chat.

Meta's "Agents Rule of Two" (31 Oct 2025) restates it as a per-session invariant: satisfy at most two of [A] untrustworthy inputs, [B] sensitive access, [C] state change or external communication ([Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/)). The two framings differ on whether [A]+[C] alone is safe; see [[Agents Rule of Two]].

## The incident record fits the shape

| Incident | Private data | Untrusted content | External channel |
|---|---|---|---|
| [[GitHub MCP Toxic Flow]] (May 2025) | Private repos via an all-repo PAT | Malicious issue in a public repo | PR on the public repo ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)) |
| [[Supabase MCP Token Leak]] (Jul 2025) | `integration_tokens` table, readable because `service_role` bypasses RLS | Attacker-submitted support ticket | The public support-message thread ([General Analysis](https://generalanalysis.com/blog/supabase-mcp-blog); [Willison](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/)) |
| [[EchoLeak M365 Copilot Exfiltration]] (disclosed Jun 2025) | M365 tenant data | Zero-click email | Reference-style markdown image to a CSP-allowed endpoint ([arXiv 2509.10540](https://arxiv.org/html/2509.10540v1)) |
| [[GitLost GitHub Agentic Workflows Leak]] (Jul 2026) | Private README via org-read agent | Public issue | Posted output; scanner bypassed by prefixing "Additionally," ([The Hacker News](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)) |
| [[Claude Code DNS Exfiltration CVE-2025-55284]] (2025) | `.env` secrets | Injected instructions | DNS queries from auto-approved `dig`/`nslookup` ([Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)) |

Two observations drive the design. First, the external channel is often **in scope**: a PR on github.com, a ticket reply, a DNS query. Domain allowlists do not break the trifecta; semantic rules and scoped credentials do. Invariant itself called the GitHub case "a fundamental architectural issue that must be addressed at the agent system level", recommending one repository per session ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)). Second, the private-data leg is almost always a **broad standing credential**, which task-scoped minting removes. The [[Problem Statement]] builds on this pattern.

## From heuristic to enforced invariant

The research inference: the trifecta and the Rule of Two are coarse, session-level versions of [[Information Flow Control]], and the broker can make them precise because it sees every system of record.

**Proposal.** The broker computes three session labels ([[Trifecta Session Labels]]):

- `sensitive_read` flips when the session reads a private repo (the broker knows visibility from the API it proxies) or uses a high-risk credential.
- `untrusted_input` flips when the session fetches content anyone can write: public-repo issues and PRs, arbitrary web pages, ticket bodies from designated sources.
- `external_effect` is any write-class action.

Then a Cedar rule (from the report; Proposal, not compiled) gates the third leg ([[Example Cedar Policies]], [[Broker Cedar Schema]]):

```cedar
forbid (principal, action in [Broker::Action::"http.write", Broker::Action::"git.push"], resource)
when { context.session.trifecta.untrusted_input && context.session.trifecta.sensitive_read }
unless { context.session.approved };
```

Per the report, this would have stopped the GitHub MCP and GitLost flows at the public-write step.

## Adopt / Improve / Add

- **Adopt:** The trifecta as the organising threat shape for policy defaults and for the M3 acceptance test (replay of the GitHub MCP toxic flow must stop at the public write).
- **Improve:** **Proposal:** compute the legs from broker-observed facts (repo visibility, credential risk, source of fetched content), never from a model's judgement, so the labels are deterministic.
- **Add:** **Proposal:** org policy may additionally forbid public-sink writes whenever `untrusted_input` alone is set, covering Willison's [A]+[C] critique. Label creep is handled by small tasks, one session per task.

## How it connects

- mitigated-by:: [[Trifecta Session Labels]]
- part-of:: [[Information Flow Control]]
- contrasts-with:: [[Agents Rule of Two]]
- decided-by:: [[ADR-010 Session-Level Trifecta Labels in the MVP]]

Incidents that are examples of this shape: [[GitHub MCP Toxic Flow]], [[Supabase MCP Token Leak]], [[EchoLeak M365 Copilot Exfiltration]], [[GitLost GitHub Agentic Workflows Leak]], [[Claude Code DNS Exfiltration CVE-2025-55284]]. [[The Attacker Moves Second]] explains why detecting the injection is not an alternative.

## Implications for the build

- The trifecta labels are session state in the broker, exposed to Cedar as `context.session.trifecta`; only the broker writes them.
- Every host adapter must classify its responses: which ones mark `untrusted_input` (public issue bodies, web pages) and which reads mark `sensitive_read` (private repo contents).
- Writes to externally readable sinks (issue comments, PRs on public repos, ticket replies) count as external effects even on allowed hosts.
- DNS is an external channel: the sandbox gets no UDP/53, and the broker resolves.

## Open questions

- How to label content from sources that are partly trusted (org-internal issues writable by many employees)? Not in the record; start conservative.
- Measured false-approval and prompt rates for the trifecta gate on real sessions: no data yet ([[Agents Rule of Two]] covers the approval-fatigue side).

## Sources

- [Willison, The lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/); [Willison on Supabase MCP](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/)
- [Meta AI, Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/)
- [Invariant Labs, GitHub MCP](https://invariantlabs.ai/blog/mcp-github-vulnerability); [General Analysis, Supabase MCP](https://generalanalysis.com/blog/supabase-mcp-blog)
- [EchoLeak, arXiv 2509.10540](https://arxiv.org/html/2509.10540v1); [The Hacker News, GitLost](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html); [Embrace The Red, DNS exfiltration](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)
