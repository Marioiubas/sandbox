---
title: "L2 Injection Benchmarks"
aliases: ["L2", "AgentDojo Runs"]
type: eval
section: build
tags: [sandbox/build, eval, topic/evaluation, adversary/a1, adversary/a3, evidence/unverified, evidence/conflict]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# L2 Injection Benchmarks

> AgentDojo (97 tasks, 629 cases) and AgentDyn (560 cases) with the broker as the defense via a shim that turns mocked side effects into real HTTP through the proxy, >=2 frontier models and ASR@k for k=10-100; model-level suites (InjecAgent, ASB, WASP, OS-Harm, AgentHarm, CyberSecEval) as traffic generators.

## What it measures

Attack success and utility on prompt-injection benchmarks **with the broker as the defense**. The product does not claim to stop injection; it claims a hijacked agent's side effects (exfiltration POSTs, pushes, writes) are contained. L2 measures exactly that, next to the utility the broker costs.

AgentDojo and AgentDyn are the best fit for scoring a system-level defense: both are extensible Python harnesses reporting benign utility, utility under attack and ASR, and both already include system-level defenses such as CaMeL, Progent and DRIFT (research note 04a Q1).

- **AgentDojo**: 97 realistic tasks (email, e-banking, travel) and 629 security test cases; "an extensible environment for designing and evaluating new agent tasks, defenses, and adaptive attacks" ([arXiv 2406.13352](https://arxiv.org/abs/2406.13352)).
- **AgentDyn**: 60 open-ended tasks and 560 injection cases in Shopping, GitHub and Daily Life, average 7.1 steps versus AgentDojo's 3.49 ([AgentDyn](https://arxiv.org/html/2602.03117v1)). It found CaMeL at zero utility on open-ended tasks, Tool Filter at 8.33% benign utility, Progent struggling with larger tool sets and DRIFT keeping about 30% utility on GPT-4o: "almost all existing defenses are either not secure enough or suffer from significant over-defense" ([AgentDyn](https://arxiv.org/html/2602.03117v1)). See [[AgentDyn]].

The 2026 differentiator is AgentDyn's open-ended tasks, where capability systems collapse; the MVP has to beat that bar ([[Dynamic Tasks Without Control-Flow Hijack]]).

## Method (Proposal)

1. **Shim.** AgentDojo and AgentDyn tools are simulated Python functions with no real network or filesystem. `eval/agentdojo_shim/` wraps each side-effecting tool so that its effect becomes a real HTTP request (or file operation) issued from inside `broker run`, against local mock upstreams that record what arrived. The broker is registered as the benchmark's "defense" through the harness's pipeline hook.
2. **Models.** At least two frontier models, same model per arm.
3. **Arms.** No defense (baseline); broker with the default policy; broker with a learned policy. Report CaMeL and Progent figures from their papers for context, never as same-setup comparisons unless re-run.
4. **Adaptive attacks.** k=10-100 attempts per case; report ASR@k. Anthropic's Gray Swan figures show why: about 0.1% single-attempt success rose to 5-6% after 100 adaptive attempts ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). Single-shot ASR is not reported alone.
5. **Model-level suites as traffic generators.** Run InjecAgent, ASB, WASP, OS-Harm, AgentHarm and CyberSecEval inside the sandbox and measure whether the broker blocks the side effects even when the model complies, giving a containment-conditional ASR:
   - InjecAgent: 1,054 test cases, 17 user tools, 62 attacker tools ([ACL Anthology](https://aclanthology.org/2024.findings-acl.624/)).
   - ASB: 10 scenarios, 400+ tools, highest average ASR 84.30% ([arXiv 2410.02644](https://arxiv.org/abs/2410.02644)).
   - WASP: intermediate ASR 16-86% versus end-to-end 0-17% ([arXiv 2504.18575](https://arxiv.org/abs/2504.18575v2)).
   - OS-Harm: 150 tasks on OSWorld ([arXiv 2506.14866](https://arxiv.org/abs/2506.14866)).
   - AgentHarm: 110 malicious tasks (440 with augmentations); measures harmful compliance, not containment ([arXiv 2410.09024](https://arxiv.org/abs/2410.09024)).
   - CyberSecEval 4: run with `python3 -m CybersecurityBenchmarks.benchmark.run --benchmark=<NAME> --llm-under-test=<PROVIDER>::<MODEL>::<KEY>` ([PurpleLlama README](https://github.com/meta-llama/PurpleLlama/blob/main/CybersecurityBenchmarks/README.md)).

## Metrics and thresholds (Proposal)

| Metric | Threshold | Anchor |
|---|---|---|
| Side-effect ASR on AgentDojo | ≤1% | Progent 39.9% → 1.0% ([arXiv](https://arxiv.org/html/2504.11703v3)) |
| Side-effect ASR on AgentDyn | ≤2% | no public system-level anchor with utility |
| Benign-utility drop on AgentDojo | ≤5 points absolute | CaMeL costs about 7 points ([arXiv](https://arxiv.org/abs/2503.18813)) |
| AgentDyn benign utility | ≥80% of the undefended baseline | targets AgentDyn's over-defense failure mode |
| ASR@k | reported for k=10-100 | Gray Swan 0.1% → 5-6% |
| Model complied, broker blocked | reported separately | WASP split |

> [!warning] Conflict
> Anchor numbers are model- and benchmark-specific. CaMeL: 77% vs 84% undefended on AgentDojo (authors), 37.71% benign utility in DRIFT's GPT-4o-mini comparison, zero on AgentDyn open-ended tasks. Progent on ASB: 3.9% (Progent paper) vs 15.8% (DRIFT's comparison). Do not compare the broker's numbers to these as if the setups matched. See [[CaMeL]] and [[Progent]].

## How to run (Proposal)

- `eval/agentdojo_shim/` and `eval/agentdyn/` hold the shim, mock upstreams and a driver that runs every suite × model × arm and writes one JSON result per case (task ID, arm, model, attempt, utility, ASR, side effects observed at the mock upstream, broker decisions by audit row ID).
- Repos: AgentDojo at https://github.com/ethz-spylab/agentdojo and AgentDyn at https://github.com/leolee99/AgentDyn (as given in research note 04a).
- Cadence: per release candidate from [[M4 Harden and Ship]] onward.

> [!question] Unverified
> The exact AgentDojo pipeline/defense hook API names were not re-verified in the record, and AgentDyn v3 (May 2026) changes were not checked. Read the current harness code before building the shim.

## How results feed back

- Every case where an injected side effect reached a mock upstream is an L1 regression candidate: reduce it to a deterministic probe in [[L1 Conformance Suite]].
- "Model complied, broker blocked" cases seed the adaptive attackers in the [[Red-Team Plan]].
- Utility losses traced to policy go to [[Policy Learning Loop]] fixtures and default-policy review.

## Limits

- Deterministic monitors have been adaptively tested only at small scale: a June 2026 study found Progent cut mean ASR from 25.8% to 4.2% and a black-box adaptive attack reached 2.6%, calling it "one small-scale data point" and leaving white-box GCG attacks for future work ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)). See [[Adaptive Evaluation of Deterministic Monitors]] and [[The Attacker Moves Second]].
- Attacks that stay inside granted authority are not blocked by design ([[Threat Model Non-Goals]]).

## How it connects

- part-of:: [[Evaluation Harness]]
- depends-on:: [[AgentDyn]]
- contrasts-with:: [[CaMeL]]
- contrasts-with:: [[Progent]]
- motivated-by:: [[The Attacker Moves Second]]
- evaluated-by:: [[Red-Team Plan]]
- depends-on:: [[L1 Conformance Suite]]
- motivated-by:: [[Adaptive Evaluation of Deterministic Monitors]]
- delivered-by:: [[M4 Harden and Ship]]

## Implications for the build

- Budget real engineering for the shim; without it the benchmark measures the model, not the broker.
- Log broker decisions with case IDs so every benchmark case can be traced to audit rows.
- Keep AgentDyn in the release set even though AgentDojo numbers will look better; AgentDyn is where over-defense shows.

## Open questions

- Whether AgentDyn's GitHub suite can be mapped onto the real [[GitHub API Adapter]] instead of a mock.
- No MCP-specific security benchmark was researched ([[Measurement Gaps]]).

## Sources

- Report: L2 row and WASP reporting rule; audit table (CaMeL, Progent, DRIFT, AgentDyn results).
- Research note 04a Q1 (benchmarks, inferences on defense hook, traffic generators, containment-conditional ASR, mocked-tool shim), Q6 L2 and gaps.
