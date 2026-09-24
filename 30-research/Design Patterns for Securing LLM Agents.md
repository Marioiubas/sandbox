---
title: "Design Patterns for Securing LLM Agents"
aliases: ["Dual LLM Pattern", "Design Patterns Paper", "Execution Modes"]
type: paper
section: research
tags: [sandbox/research, paper, topic/ifc, topic/policy, milestone/phase2]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "The 2025 six-pattern paper (Action-Selector, Plan-Then-Execute, LLM Map-Reduce, Dual LLM, Code-Then-Execute, Context-Minimization) including Willison's 2023 Dual LLM pattern; adopt the patterns as named execution modes with default capability profiles."
related: ["[[CaMeL]]", "[[Revocable Sub-Agent Delegation]]", "[[Policy Engine and Entity Builder]]", "[[broker.toml Human Policy Layer]]", "[[Information Flow Control]]", "[[ACE and IsolateGPT]]", "[[Dynamic Tasks Without Control-Flow Hijack]]", "[[Agents Rule of Two]]", "[[Object Capabilities]]", "[[FIDES]]", "[[Trifecta Session Labels]]", "[[Threat Model Non-Goals]]"]
sources: ["https://arxiv.org/abs/2506.08837", "https://arxiv.org/html/2506.08837", "https://simonwillison.net/2023/Apr/25/dual-llm-pattern/", "https://arxiv.org/html/2503.18813"]
---

# Design Patterns for Securing LLM Agents

A 2025 position paper from a large cross-institution group names six architectural patterns that limit what a prompt injection can *do*, rather than trying to detect it. It has no benchmark, and it says plainly that general-purpose agents are unlikely to get reliable guarantees. The broker adopts the six patterns as named **execution modes**, each with a default capability profile, so choosing a pattern also chooses the authority the agent gets.

## Citation

- Beurer-Kellner, Buesser, Creţu, Debenedetti, Dobos, Fabian, Fischer, Froelicher, Grosse, Naeff, Ozoani, Paverd, Tramèr, Volhejn. "Design Patterns for Securing LLM Agents against Prompt Injections". arXiv 2506.08837, June 2025 ([arXiv](https://arxiv.org/abs/2506.08837)).
- Venue: preprint (position/pattern paper). No code and no benchmark numbers ([arXiv HTML](https://arxiv.org/html/2506.08837)).
- Foundational precursor: Willison, "The Dual LLM pattern for building AI assistants that can resist prompt injection", 25 April 2023 ([simonwillison.net](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/)).

## Mechanism: the six patterns

The patterns share one idea: they constrain what an injection *can do* once untrusted input is in play, rather than detecting it ([arXiv HTML](https://arxiv.org/html/2506.08837)). The research record gives only the pattern names; the one-line descriptions below are background summaries (except Dual LLM, sourced below) and must be checked against the paper's own definitions before they appear in product docs.

| Pattern | Control-flow source | What untrusted data can influence |
|---|---|---|
| Action-Selector | The LLM picks from a fixed set of actions; tool output is not fed back | Nothing downstream |
| Plan-Then-Execute | Plan fixed from the trusted request before tool output is seen | Data arguments of pre-planned calls |
| LLM Map-Reduce | Isolated workers each process one untrusted item; a controller aggregates constrained results | Only the worker's own bounded output |
| Dual LLM | Privileged LLM (tools, trusted input) plus Quarantined LLM (untrusted content, no tools), mediated by a non-LLM controller | Symbolic variables the P-LLM never reads |
| Code-Then-Execute | The LLM writes a program from the trusted request; an interpreter runs it (the [[CaMeL]] approach) | Values flowing through the program |
| Context-Minimization | Remove the user prompt or untrusted content from context before later steps | Less context to hijack |

The paper grounds the patterns in ten case studies: an OS assistant, a SQL agent, email and calendar, customer service, booking, a product recommender, resume screening, a medication leaflet, a medical diagnosis intermediary, and a software-engineering agent ([arXiv HTML](https://arxiv.org/html/2506.08837)).

### The Dual LLM pattern (Willison, 2023)

The oldest pattern, and the ancestor of CaMeL ([simonwillison.net](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/)):

```text
Controller (ordinary code, not an LLM)
 ├─ P-LLM: sees the trusted user request, may call tools, never sees untrusted text
 ├─ Q-LLM: reads untrusted text, has no tools, returns results stored as $VAR1, $VAR2 ...
 └─ Rule: the controller never forwards Q-LLM output into the P-LLM's context;
          the P-LLM manipulates $VARn symbolically ("summarise $VAR1", "send $VAR2")
```

Willison's acknowledged limitations: the user can still be socially engineered by content shown to them, chaining creates risk, and the design is complex and degrades UX.

## Threat model and assumptions

- **Attacker:** controls untrusted input that reaches the agent (documents, web pages, emails, tool results) and wants to hijack its actions or manipulate its outputs ([arXiv HTML](https://arxiv.org/html/2506.08837)).
- **Trusted:** the user's request and the application designer, who chooses the pattern and writes the non-LLM controller.
- **Goal of the patterns:** stop control-flow hijack, not guarantee correct outputs. The paper explicitly accepts that data parameters can still be manipulated.
- **Adaptive attacks:** none; there is no quantitative evaluation. The closest adaptive data concerns CaMeL, which the June 2026 out-of-band study evaluated at small scale.
- **Code:** none (position paper).

## Evidence

- **Claims, not measurements.** The patterns give "meaningful" resistance, not immunity: "we believe it is unlikely that general-purpose agents can provide meaningful and reliable safety guarantees" ([arXiv HTML](https://arxiv.org/html/2506.08837)).
- **Key residual:** most patterns stop control-flow hijack but still allow **manipulation of data parameters** ([arXiv HTML](https://arxiv.org/html/2506.08837)). An injected document can still choose *which* recipient, file or amount flows into an allowed call. This is the same residual that Branch Steering exposes in CaMeL's computer-use work and that argues against Meta's "[A]+[C] is lower risk" wording ([[Agents Rule of Two]]).

## Counter-evidence and weaknesses

- No quantitative evaluation; the patterns' utility cost is unknown. Code-Then-Execute's closest measured instance, CaMeL, drops to zero utility on AgentDyn's open-ended tasks.
- No treatment of credentials: every pattern assumes the tool layer already holds whatever authority it needs, the same gap as CaMeL and FIDES ([[Object Capabilities]]).
- No treatment of multi-agent delegation or revocation, although Map-Reduce and Dual LLM are delegation structures.

## Where the probabilistic part lives

Not applicable as a system; within each pattern, the LLM that plans (P-LLM, planner, code writer) is probabilistic but sees only trusted input, and the Q-LLM or workers are probabilistic but confined. Security comes from the non-LLM controller.

## Adopt / Improve / Add

- **Adopt:** **Proposal:** the six patterns as named, selectable execution modes in the product. Action-Selector and Plan-Then-Execute are cheap to enforce deterministically. Map-Reduce gives natural per-item sandboxes.
- **Improve:** **Proposal:** bind each mode to a default capability profile in the broker, so choosing a pattern changes authority, not just prompting. Example from the report: Map-Reduce workers get read-only, single-item, no-egress grants. Profiles are expressed in [[broker.toml Human Policy Layer]] and compiled to Cedar by the [[Policy Engine and Entity Builder]].
- **Add:** **Proposal:** credential semantics and revocation, which the paper omits: worker grants are attenuated sub-grants of the session grant, revocable as a group ([[Revocable Sub-Agent Delegation]]). For the data-parameter residual, add provenance conditions on arguments ([[Information Flow Control]]) and a re-plan-with-human path for data-dependent control flow ([[Dynamic Tasks Without Control-Flow Hijack]]).

Illustrative mode profiles (**Proposal**; not compiled):

```toml
[mode.map_reduce.worker]      # one untrusted item per worker
filesystem.write = []
egress = []                   # no network; results return through the broker
labels = { untrusted_input = true }

[mode.plan_then_execute]
plan_source = "trusted_request_only"
widening = "approval_with_authority_diff"
```

## How it connects

- contrasts-with:: [[CaMeL]]
- contrasts-with:: [[ACE and IsolateGPT]]
- depends-on:: [[Policy Engine and Entity Builder]]
- depends-on:: [[broker.toml Human Policy Layer]]

[[CaMeL]] is the measured instance of Code-Then-Execute and Dual LLM; [[FIDES]] extends Dual LLM with labelled, schema-constrained quarantine; [[ACE and IsolateGPT]] extends Plan-Then-Execute with static plan analysis. Map-Reduce needs [[Revocable Sub-Agent Delegation]]. Data-parameter manipulation is the residual targeted by [[Dynamic Tasks Without Control-Flow Hijack]] and by [[Trifecta Session Labels]] at session granularity.

## Implications for the build

- MVP: modes are a phase-2 feature, but keep the profile concept in the TOML schema design so it can be added without breaking configs.
- Map-Reduce and sub-agent workers must never inherit the parent's egress or credentials by default.
- Document in the threat model that no mode prevents data-parameter manipulation within granted scope ([[Threat Model Non-Goals]] covers misuse inside granted scope).

## Open questions

- Which agent frameworks expose enough structure for the broker to know which mode a sub-process is running in? Not in the record; the broker may need an SDK hook or separate `broker run` invocations per worker.
- No utility measurement exists for any pattern except via CaMeL.

## Sources

- [arXiv 2506.08837 (abstract)](https://arxiv.org/abs/2506.08837); [HTML](https://arxiv.org/html/2506.08837)
- [Willison, Dual LLM pattern](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/)
- [CaMeL, arXiv 2503.18813](https://arxiv.org/html/2503.18813)
