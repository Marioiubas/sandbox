---
title: "MiniScope"
aliases: ["Tool-Graph Least Privilege"]
type: paper
section: research
tags: [sandbox/research, paper, topic/policy, topic/learning, topic/mcp, topic/approval, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Least-privilege framework that reconstructs permission hierarchies from tool-call relationships with mobile-style prompts and no LLM in the loop (1-6% latency); basis for tool-graph-derived incremental MCP grants."
related: ["[[MCP Guard]]", "[[MCP Authorization Spec]]", "[[Policy Learning Loop]]", "[[Trace-Mined Least Privilege]]", "[[AgentSpec]]", "[[Conseca]]", "[[Progent]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[AgentDyn]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://arxiv.org/abs/2512.11147", "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices", "https://modelcontextprotocol.io/specification/latest/basic/authorization", "https://arxiv.org/html/2602.03117v1"]
---

# MiniScope

MiniScope computes least privilege for tool-calling agents **without an LLM in the security loop**. It reconstructs a permission hierarchy from the relationships among tool calls and pairs it with a mobile-app-style permission model, so the agent starts with little authority and the user grants more incrementally. It reports 1–6% latency overhead and fewer unnecessary grants than LLM-based baselines. The broker uses the idea for MCP: derive grants per tool from the tool graph and extend them incrementally, which fits MCP's own progressive-scope guidance.

## Citation

- Zhu, Tseng, Vernik, Huang, Patil, Fang, Popa. "MiniScope: A Least Privilege Framework for Tool-Calling Agents" (title as summarised in the record). arXiv 2512.11147, Dec 2025 ([arXiv](https://arxiv.org/abs/2512.11147)).
- Code availability: not stated.

## Mechanism

From the abstract ([arXiv](https://arxiv.org/abs/2512.11147)):

- **Permission hierarchy from tool relationships.** Tools are related: reading a calendar event is a precondition of editing it; listing messages precedes reading one. MiniScope reconstructs a hierarchy of permissions from these relationships among tool calls.
- **Mobile-style permission model.** Like an app asking for "access to contacts" the first time it needs it, the agent is granted permissions incrementally as the task reaches them.
- **No manual policy and no LLM in the security loop.** The hierarchy and the grant decisions are computed, not generated.

Illustrative shape (not MiniScope's representation):

```text
tool graph:  calendar.list → calendar.read(id) → calendar.update(id)
             mail.list     → mail.read(id)     → mail.send(to)
grant state: {calendar.list, calendar.read}          # task so far
next call:   calendar.update(id=42)  → prompt: "allow editing calendar events?"
             mail.send(...)          → prompt: different subtree, separate grant
```

## Threat model and assumptions

The research record extracted the abstract only, so the threat model below is partly inferred and should be checked against the paper.

- **Problem addressed:** over-privileged tool-calling agents that hold every permission their tools could use, so any hijack or mistake has a large blast radius ([arXiv](https://arxiv.org/abs/2512.11147)).
- **Trusted:** the tool definitions and call relationships from which the hierarchy is reconstructed, and the user answering permission prompts.
- **Implied assumption:** tool definitions are honest. A malicious or rug-pulled tool description could distort the reconstructed hierarchy, which is why this product pins manifests before deriving anything from them.
- **Adaptive attacks:** none in the record.
- **Design choice worth copying:** keeping the model out of the security loop entirely, which removes the policy-author attack surface that [[Progent]], [[Conseca]] and [[AgentSpec]] all carry.

## Evidence

- **1–6% latency overhead** ([arXiv](https://arxiv.org/abs/2512.11147)).
- **Fewer unnecessary grants** than LLM-based baselines ([arXiv](https://arxiv.org/abs/2512.11147)).
- Evaluated on a **synthetic dataset built from ten real-world applications** ([arXiv](https://arxiv.org/abs/2512.11147)).

## Counter-evidence and weaknesses

- Synthetic dataset; no AgentDojo, [[AgentDyn]] or adaptive-attack results in the record.
- Reconstruction presumes the tool-dependency structure is knowable from tool definitions and call relationships; an MCP server whose tools are coarse (one `execute` tool) defeats it.
- **No IFC.** A granted permission can still be used with attacker-chosen data.
- Prompts still reach the user; a mobile-style prompt stream is exactly where approval fatigue sets in ([[Fatigue-Resistant Approval Interfaces]]).

## Where the probabilistic part lives

Nowhere in the security loop, per the abstract. It is the main non-LLM least-privilege inference approach in the record (research note 02, Q4), alongside SkillGuard's inference-free confinement.

## Relation to MCP's own guidance

The MCP security best practices already mandate progressive least-privilege scopes: a minimal initial scope, incremental elevation through `WWW-Authenticate scope=` challenges, and no wildcard or omnibus scopes ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)). The authorization spec signals runtime step-up with a 403 and `WWW-Authenticate: Bearer error="insufficient_scope"` ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)). MiniScope supplies the missing piece: *which* scope subtree to grant next, derived from the tool graph rather than from the server's own scope list. See [[MCP Authorization Spec]].

## Where it fits among policy sources

The record's policy-synthesis systems differ mainly in who writes the policy: an LLM from the task ([[Progent]], [[Conseca]], [[AgentSpec]]), a verified analyzer over LLM output (AgentCore), or no model at all (MiniScope, SkillGuard). The research resolution is that an LLM may author, but a deterministic analyzer must bound the result against a static ceiling. MiniScope is the strongest evidence that useful least privilege can be derived structurally, and it is the closest prior work to trace mining, although it infers from the static tool graph rather than from recorded runs.

## Adopt / Improve / Add

- **Adopt:** **Proposal:** tool-graph-derived incremental grants for MCP tools. When the [[MCP Guard]] pins a server's `tools/list`, it also derives a read → write hierarchy over the tools; the session starts with the read subtree the task profile needs, and write-class tools are granted per subtree on step-up.
- **Improve:** **Proposal:** combine the static graph with recorded traces: the [[Policy Learning Loop]] observes which tools a repo's tasks actually use and pre-grants those, so prompts appear only for genuinely new behaviour ([[Trace-Mined Least Privilege]]). Treat an `insufficient_scope` challenge from a remote MCP server as the same step-up hook: pause, show the authority diff, re-authorise with the union of scopes.
- **Add:** **Proposal:** SymCC proof that each incremental grant is within the org ceiling, and trifecta labels so a write-class tool on a public sink is not grantable by a single click once `untrusted_input` is live.

## How it connects

- contrasts-with:: [[Conseca]]
- contrasts-with:: [[AgentSpec]]
- contrasts-with:: [[Progent]]

It supplies the missing half of the [[MCP Authorization Spec]]'s progressive-scope guidance. Design notes grounded here: [[MCP Guard]] (per-tool authorization), [[Policy Learning Loop]] and [[Trace-Mined Least Privilege]] (grants from observed structure rather than generation).

## Implications for the build

- M3: the MCP guard's pinned manifest record should include a derived tool hierarchy, and `tools/call` authorization should check the tool against the session's granted subtree.
- Classify every pinned tool as read, write or execute at pin time; a description change re-runs classification and revokes derived grants.
- Measure prompts per session for MCP-heavy tasks as part of L4.

## Open questions

- Code availability is unverified ([[Open Questions and Unverified Claims]]).
- How well tool-graph inference works on real MCP servers with coarse or badly described tools: not measured anywhere in the record.

## Sources

- [MiniScope, arXiv 2512.11147](https://arxiv.org/abs/2512.11147)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices); [MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- [AgentDyn](https://arxiv.org/html/2602.03117v1)
