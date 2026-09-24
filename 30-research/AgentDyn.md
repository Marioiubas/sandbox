---
title: "AgentDyn"
aliases: ["AgentDojo", "Open-Ended Benchmark"]
type: eval
section: research
tags: [sandbox/research, eval, topic/evaluation, milestone/m4, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The Feb 2026 open-ended benchmark (60 tasks, 560 injection cases, 7.1 steps vs AgentDojo's 3.49) on which every system-level defense over-defends; with AgentDojo as the baseline harness both extend."
related: ["[[L2 Injection Benchmarks]]", "[[CaMeL]]", "[[Progent]]", "[[DRIFT]]", "[[Dynamic Tasks Without Control-Flow Hijack]]", "[[The Attacker Moves Second]]", "[[Evaluation Harness]]", "[[FIDES]]", "[[ACE and IsolateGPT]]", "[[Measurement Gaps]]", "[[Red-Team Plan]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://arxiv.org/abs/2602.03117", "https://arxiv.org/html/2602.03117v1", "https://github.com/leolee99/AgentDyn", "https://arxiv.org/abs/2406.13352", "https://github.com/ethz-spylab/agentdojo", "https://agentdojo.spylab.ai/results/", "https://arxiv.org/abs/2503.18813", "https://arxiv.org/html/2504.11703v3", "https://arxiv.org/html/2510.09023", "https://arxiv.org/abs/2504.18575v2"]
---

# AgentDyn

AgentDyn (Feb 2026) is the open-ended successor to AgentDojo: 60 tasks and 560 injection cases whose trajectories are about twice as long and whose next step often depends on what the agent just read. On it, every system-level defense in the literature either stops being secure or stops being useful: CaMeL scores zero utility, Tool Filter 8.33%, DRIFT about 30%. It is the benchmark this product must beat, run through the AgentDojo harness it extends.

## What it measures

**AgentDojo** (NeurIPS 2024 Datasets and Benchmarks; the reference harness): 97 realistic tasks (email, e-banking, travel) and 629 security test cases; "an extensible environment for designing and evaluating new agent tasks, defenses, and adaptive attacks" ([arXiv 2406.13352](https://arxiv.org/abs/2406.13352); [repo](https://github.com/ethz-spylab/agentdojo)).

**AgentDyn** (arXiv 2602.03117; v1 2026-02-03, v2 2026-02-06, v3 2026-05-07; [repo](https://github.com/leolee99/AgentDyn)), built on the AgentDojo framework ([arXiv abs](https://arxiv.org/abs/2602.03117); [HTML v1](https://arxiv.org/html/2602.03117v1)):

| Property | AgentDyn | AgentDojo |
|---|---|---|
| User tasks | 60 open-ended | 97 |
| Injection cases | 560 | 629 |
| Domains | Shopping, GitHub, Daily Life | Email, e-banking, travel (and others; see the paper) |
| Average steps per trajectory | 7.1 | 3.49 |
| Tools | 27–39 per environment (33.33 average) | 19.87 average |
| Apps per task | 3.17 | — |
| Tasks needing dynamic planning | open-ended by design | 6 of 97 |

**Metrics** ([HTML v1](https://arxiv.org/html/2602.03117v1)):

- **Benign Utility:** "fraction of user tasks successfully completed in the absence of any attacks".
- **Utility under Attack:** share of tasks completed while under attack.
- **ASR:** "fraction of security cases in which the attacker's malicious goals are successfully executed".

## Results: every defense over-defends

Ten defenses in four groups: prompting (Sandwich, Spotlighting, Tool Filter), filtering (ProtectAI, PromptGuard2, PIGuard), alignment (Meta SecAlign) and system-level (CaMeL, Progent, DRIFT) ([HTML v1](https://arxiv.org/html/2602.03117v1)):

- **[[CaMeL]]:** "zero utility and zero ASR across all agents", because its static plan is too rigid.
- **Tool Filter:** 8.33% benign utility on GPT-4o.
- **[[Progent]]:** lost utility on open-ended tasks and struggled "to assign accurate tool access privileges" with larger tool sets.
- **[[DRIFT]]:** about 30% utility on GPT-4o.
- **Meta SecAlign:** best utility of the ten, 53.4%, from the model-level family broken at 96% by adaptive attacks ([arXiv 2510.09023](https://arxiv.org/html/2510.09023)).

Headline: "almost all existing defenses are either not secure enough or suffer from significant over-defense" ([arXiv abs](https://arxiv.org/abs/2602.03117)).

Contrast with AgentDojo: CaMeL solves 77% of AgentDojo tasks versus 84% undefended ([arXiv 2503.18813](https://arxiv.org/abs/2503.18813)); Progent cuts AgentDojo ASR from 39.9% to 1.0% ([arXiv 2504.11703v3](https://arxiv.org/html/2504.11703v3)). AgentDojo on gpt-4o-2024-05-13: undefended 69.07% utility / 47.69% targeted ASR; `tool_filter` 72.16% / 6.84% ([AgentDojo results](https://agentdojo.spylab.ai/results/)). The AgentDojo numbers overstate deployability because so few of its tasks need data-dependent control flow.

## Weaknesses of the benchmark for this product

- **Mocked tools.** AgentDojo and AgentDyn tools are simulated Python functions with no real network or filesystem. They cannot, as shipped, measure an egress and credential broker (research note 04a, Q1 inference).
- **Coverage.** AgentDyn omits [[FIDES]] and [[ACE and IsolateGPT]], so there is no open-ended number for them.
- **Unverified details:** the v3 (May 2026) changelog and whether numbers changed from v1; per-model tables were not extracted; exact AgentDojo pipeline and defense hook API names were not re-verified ([[Open Questions and Unverified Claims]]).
- No public benchmark scores an egress and credential broker with real traffic ([[Measurement Gaps]]).

## How to run it against the broker (Proposal)

From the report's L2 layer and research note 04a ([[L2 Injection Benchmarks]], [[Evaluation Harness]]):

1. Insert the broker as a "defense" through the harness's pipeline/defense hook: tool-call interposition plus network and credential mediation.
2. **Mocked-tool shim:** turn mocked tool side effects into real HTTP (and filesystem) calls through the proxy, so a successful injection must actually cross the broker to count.
3. Run with ≥2 frontier models; adaptive attacks with k=10–100 attempts per case, reporting ASR@k.
4. Report the triple (benign utility, utility under attack, ASR) next to the no-defense baseline and CaMeL, Progent and DRIFT.
5. Keep a separate "model complied, broker blocked" count, following WASP's split between intermediate (16–86%) and end-to-end (0–17%) attack success ([arXiv 2504.18575](https://arxiv.org/abs/2504.18575v2)).

**Release thresholds (Proposal):** side-effect ASR ≤1% on AgentDojo and ≤2% on AgentDyn; benign-utility drop ≤5 points on AgentDojo; AgentDyn benign utility ≥80% of the undefended baseline, which directly targets over-defense.

## Adopt / Improve / Add

- **Adopt:** AgentDojo as the baseline harness and AgentDyn as the utility bar; report the utility/ASR pair, never either alone.
- **Improve:** **Proposal:** the mocked-tool shim so the benchmark exercises real egress, and paired runs with and without the broker on the same model and seed.
- **Add:** **Proposal:** publish the broker's AgentDyn results with adaptive attacks; nobody in the field publishes paired utility-and-containment numbers on AgentDyn today, and the report treats being first as part of the product. The open problem it measures is [[Dynamic Tasks Without Control-Flow Hijack]].

## How it connects

- part-of:: [[Evaluation Harness]]
- part-of:: [[L2 Injection Benchmarks]]
- contrasts-with:: [[The Attacker Moves Second]]

Systems evaluated-by this benchmark: [[CaMeL]], [[Progent]], [[DRIFT]]. The adaptive-attack side of reporting is in [[Red-Team Plan]].

## Implications for the build

- `code/eval/agentdojo_shim` and `code/eval/agentdyn` exist from M4; the shim is the critical piece because it converts simulated side effects into brokered traffic.
- The broker's coarse session labels are chosen partly because fine-grained systems collapse here; the AgentDyn utility threshold is how that choice is tested.
- Pin the AgentDyn version (v1, v2 or v3) in every report.

## Open questions

- AgentDyn v3 changes; per-model results.
- Exact AgentDojo defense hook API names.
- Whether AgentDyn's GitHub suite can be mapped onto real GitHub API traffic through the GitHub adapter.

## Sources

- [AgentDyn, arXiv 2602.03117](https://arxiv.org/abs/2602.03117); [HTML v1](https://arxiv.org/html/2602.03117v1); [repo](https://github.com/leolee99/AgentDyn)
- [AgentDojo, arXiv 2406.13352](https://arxiv.org/abs/2406.13352); [repo](https://github.com/ethz-spylab/agentdojo); [results](https://agentdojo.spylab.ai/results/)
- [CaMeL](https://arxiv.org/abs/2503.18813); [Progent v3](https://arxiv.org/html/2504.11703v3); [The Attacker Moves Second](https://arxiv.org/html/2510.09023); [WASP](https://arxiv.org/abs/2504.18575v2)
