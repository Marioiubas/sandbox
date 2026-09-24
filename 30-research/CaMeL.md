---
title: "CaMeL"
aliases: ["CaMeLs for Computer Use", "Branch Steering"]
type: paper
section: research
tags: [sandbox/research, paper, topic/ifc, topic/policy, topic/evaluation, evidence/conflict]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Google DeepMind/ETH design where a privileged LLM writes code from the trusted query, an interpreter tracks readers and provenance, and Python policies gate tool calls: 77% vs 84% AgentDojo utility, zero on AgentDyn open-ended tasks; plus CaMeLs for computer use and Branch Steering."
related: ["[[Design Patterns for Securing LLM Agents]]", "[[Information Flow Control]]", "[[Object Capabilities]]", "[[AgentDyn]]", "[[Branch-Steering Resistance]]", "[[Dynamic Tasks Without Control-Flow Hijack]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[Threat Model Non-Goals]]", "[[Provenance-Aware Cedar]]", "[[L2 Injection Benchmarks]]", "[[FIDES]]", "[[DRIFT]]", "[[The Attacker Moves Second]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[Cedar]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://arxiv.org/abs/2503.18813", "https://arxiv.org/html/2503.18813", "https://github.com/google-research/camel-prompt-injection", "https://simonwillison.net/2025/Apr/11/camel/", "https://arxiv.org/html/2602.03117v1", "https://arxiv.org/html/2506.12104v2", "https://arxiv.org/abs/2505.22852", "https://arxiv.org/abs/2601.09923", "https://arxiv.org/html/2601.09923v1", "https://arxiv.org/abs/2606.26479"]
---

# CaMeL

CaMeL is the reference "secure by design" defense against prompt injection. A privileged LLM turns the trusted user query into a program; a custom interpreter runs it, tagging every value with who may read it and where it came from; and security policies are checked at each tool call. It holds up well on AgentDojo (77% of tasks versus 84% undefended, attacks against GPT-4o reduced to zero), but scores **zero utility** on AgentDyn's open-ended tasks. The broker adopts its labels and its checkpoint at the tool boundary, not its interpreter.

## Citation

- Debenedetti, Shumailov, Fan, Hayes, Carlini, Fabian, Kern, Shi, Terzis, Tramèr (Google DeepMind, Google, ETH Zürich). "Defeating Prompt Injections by Design". arXiv 2503.18813, v1 24 Mar 2025, v2 24 Jun 2025 ([arXiv](https://arxiv.org/abs/2503.18813)).
- Code: [google-research/camel-prompt-injection](https://github.com/google-research/camel-prompt-injection).
- Follow-ups: "Operationalizing CaMeL: Strengthening LLM Defenses for Enterprise Deployment", arXiv 2505.22852 (content not read) ([arXiv](https://arxiv.org/abs/2505.22852)); "CaMeLs Can Use Computers Too", arXiv 2601.09923, Jan 2026 (below).

## Mechanism

From the paper ([arXiv HTML](https://arxiv.org/html/2503.18813)):

1. **Privileged LLM (P-LLM)** writes code in a Python subset from the **trusted user query only**. It never sees tool outputs.
2. **Custom interpreter** executes the program. Control flow is fixed by the program, so untrusted data cannot add or reorder tool calls.
3. **Quarantined LLM (Q-LLM)**, with no tools, parses untrusted data into structured outputs.
4. **Capabilities** (really [[Information Flow Control]] labels): every value carries *readers* (who may see it) and *provenance* (user literal, tool X, CaMeL transformation). Labels propagate through computation.
5. **Security policies**, written as Python functions per tool, are checked at each tool call against the arguments' labels.

```text
query (trusted) ──P-LLM──► program
program ──interpreter──► tool calls
            │   each value v : (data, readers, provenance)
            ▼
   policy(tool, args, labels) → allow | deny     # e.g. send_email.to must not be
                                                #   derived from untrusted content
untrusted text ──Q-LLM (no tools, schema-bound)──► structured values (labelled untrusted)
```

**STRICT mode** adds conditional tests as dependencies of assigned variables, so a branch taken on untrusted data taints what it assigns (control-dependency tainting).

### Threat model and non-goals

The user query is trusted. Out of scope: text-to-text attacks with no data-flow consequence (for example misrepresenting an email's content), phishing links shown to users, and fully autonomous operation with no human in the loop ([arXiv HTML](https://arxiv.org/html/2503.18813)). The report carries the first as a product non-goal ([[Threat Model Non-Goals]]).

## Evidence

- Solves **77%** of AgentDojo tasks with provable security versus **84%** for the undefended system, roughly a 7-point utility cost ([arXiv](https://arxiv.org/abs/2503.18813)).
- Successful attacks against GPT-4o fell to **0** (from 233 undefended), with a couple of "non-goal" attacks remaining in travel and banking. The Travel suite suffered due to under-documented tool return formats ([arXiv HTML](https://arxiv.org/html/2503.18813)).
- Median token overhead **2.82x input / 2.73x output** versus native tool calling ([arXiv HTML](https://arxiv.org/html/2503.18813)).
- Willison: "the first credible prompt injection mitigation I've seen that doesn't just throw more AI at the problem", with concerns about policy burden and approval fatigue ([simonwillison.net](https://simonwillison.net/2025/Apr/11/camel/)).

## Counter-evidence

> [!warning] Conflict
> Utility numbers are model- and benchmark-specific. The authors report 77% versus 84% on AgentDojo; DRIFT's GPT-4o-mini comparison measured CaMeL at **37.71%** benign utility and 32.25% utility under attack ([DRIFT, arXiv 2506.12104](https://arxiv.org/html/2506.12104v2)); AgentDyn found **"zero utility and zero ASR across all agents"** on open-ended tasks because the static plan is too rigid ([AgentDyn, arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)). Tracked in [[Open Questions and Unverified Claims]].

- Only 6 of AgentDojo's 97 tasks need dynamic planning ([AgentDyn](https://arxiv.org/html/2602.03117v1)), so the AgentDojo number reflects tasks whose control flow is knowable up front.
- Acknowledged side channels: loop-count inference, exception-based one-bit leaks, timing ([arXiv HTML](https://arxiv.org/html/2503.18813)).
- Authors' own limitations: users must codify and maintain policies; approval fatigue; third-party tools without capability support degrade utility; and an analogy to CFI being bypassed by ROP-style chaining of allowed flows.
- Adaptive testing: CaMeL was not in [[The Attacker Moves Second]]; the June 2026 out-of-band study included it but is small-scale, and no white-box attack exists ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)).
- Data arguments stay manipulable unless a policy checks provenance: an injected document can still choose *which* value flows into an allowed call.

## CaMeLs Can Use Computers Too (2026)

Foerster, Mullins, Blanchard, Papernot, Nikolić, Tramèr, Shumailov, Zhang, Zhao. arXiv 2601.09923, Jan 2026 ([arXiv](https://arxiv.org/abs/2601.09923)).

- **Single-Shot Planning:** the trusted planner emits a full execution graph with conditional branches before seeing any screen content. **Observe-Verify-Act** boolean checks gate actions ([arXiv HTML](https://arxiv.org/html/2601.09923v1)).
- Numbers (OSWorld; UITars-1.5-7B, OpenCUA-32B, Claude Sonnet 4.5; nine planners): up to 19% improvement for small open models; frontier models retain up to **57%** of original success at pass@5. Token overhead 1.88x for the CaMeL-style design versus 29.6x for an iterative FIDES variant ([arXiv HTML](https://arxiv.org/html/2601.09923v1)).
- **Branch Steering:** the adversary manipulates the UI so a *valid, pre-approved* branch is taken (cookie-popup spoofing in ads; gradient pixel perturbations that defeat redundancy defenses) ([arXiv HTML](https://arxiv.org/html/2601.09923v1)). Fixing control flow is not enough when branch predicates are evaluated on attacker-controlled observations.

## Where the probabilistic part lives

Program authoring by the P-LLM (from trusted input only) and the schema-bounded content of Q-LLM outputs. Enforcement is deterministic. In the computer-use variant, branch predicates evaluated on attacker-visible observations.

## Adopt / Improve / Add

- **Adopt:** provenance and reader labels plus checks at the tool boundary; Q-LLM output constrained to schemas.
- **Improve:** **Proposal:** declarative, analyzable policies ([[Cedar]]) instead of hand-written Python, so policies can be statically checked for over-permissiveness ([[Provenance-Aware Cedar]]). Make STRICT-style control-dependency tainting the default for any call with external side effects.
- **Add:** **Proposal:** a "re-plan with human" fallback instead of failing when data-dependent control flow is needed, the main utility hole ([[Dynamic Tasks Without Control-Flow Hijack]]). For computer use: every branch of an approved plan must pass policy independently, and predicates computed from untrusted data are low-integrity ([[Branch-Steering Resistance]]).

## How it connects

- example-of:: [[Design Patterns for Securing LLM Agents]]
- example-of:: [[Information Flow Control]]
- evaluated-by:: [[AgentDyn]]
- evaluated-by:: [[L2 Injection Benchmarks]]
- contrasts-with:: [[FIDES]]
- contrasts-with:: [[DRIFT]]

CaMeL's "capabilities" are labels, not [[Object Capabilities]]: it relies on the tool layer's ambient credentials, which is the gap the broker fills. Its zero AgentDyn utility is why the MVP uses coarse session labels instead of an interpreter ([[ADR-010 Session-Level Trifecta Labels in the MVP]]). Its policy burden and approval fatigue feed [[Fatigue-Resistant Approval Interfaces]].

## Implications for the build

- Do not embed a CaMeL-style interpreter in the MVP; enforcement stays at the network and tool boundary the broker already mediates.
- The Cedar schema's `McpCtx.args_integrity` field is the hook for CaMeL-style provenance once per-argument labels exist.
- The L2 threshold (benign-utility drop ≤5 points on AgentDojo) is set to beat CaMeL's ~7-point cost; the AgentDyn threshold (≥80% of undefended utility) targets CaMeL's collapse.

## Open questions

- "Operationalizing CaMeL" (arXiv 2505.22852) was not read.
- Whether per-argument provenance can be computed by a network-level broker without an interpreter; this is [[Provenance-Aware Cedar]].

## Sources

- [arXiv 2503.18813](https://arxiv.org/abs/2503.18813); [HTML](https://arxiv.org/html/2503.18813); [code](https://github.com/google-research/camel-prompt-injection)
- [Willison on CaMeL](https://simonwillison.net/2025/Apr/11/camel/)
- [AgentDyn, arXiv 2602.03117](https://arxiv.org/html/2602.03117v1); [DRIFT, arXiv 2506.12104](https://arxiv.org/html/2506.12104v2); [arXiv 2606.26479](https://arxiv.org/abs/2606.26479)
- [arXiv 2505.22852](https://arxiv.org/abs/2505.22852); [CaMeLs for computer use, arXiv 2601.09923](https://arxiv.org/abs/2601.09923), [HTML](https://arxiv.org/html/2601.09923v1)
