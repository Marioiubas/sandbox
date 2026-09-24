---
title: "L3 Real-Work Utility"
aliases: ["L3", "SWE-bench Verified", "Terminal-Bench"]
type: eval
section: build
tags: [sandbox/build, eval, topic/evaluation, platform/linux, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# L3 Real-Work Utility

> Paired A/B runs, same model and seed, k>=3, on SWE-bench Verified (500 or stratified 100 in CI) and Terminal-Bench 2.x via Harbor, live-internet tasks tagged apart, every deny bucketed as policy-caused, agent noise or legitimately blocked.

## What it measures

The cost of the broker on real coding work: how much does wrapping an agent in the sandbox and brokered egress change its ability to resolve tasks? No published study reports SWE-bench or Terminal-Bench scores with versus without an egress sandbox (research note 04a Q2), so this is one of the numbers the product publishes first ([[Measurement Gaps]]).

## Benchmarks

- **SWE-bench Verified**: 500 engineer-reviewed problems. The harness builds three image tiers (base, environment, instance) and evaluates with `python -m swebench.harness.run_evaluation --dataset_name ... --predictions_path ... --max_workers 8 --run_id ...`. It needs 120 GB disk, 16 GB RAM, 8+ cores and x86_64 ([SWE-bench harness docs](https://www.swebench.com/SWE-bench/reference/harness/)).
- **Terminal-Bench 2.x via Harbor**: Harbor runs "cloud-deployed containers", scales "horizontally to thousands of containers" and "works with any agent that can be installed in a container"; one 2.0 task (`download-youtube`) depended on a live internet service ([tbench.ai announcement](https://www.tbench.ai/news/announcement-2-0)). The docs show the run pattern `harbor run -d terminal-bench/terminal-bench@<ver> -e modal -a claude-code -m <model> -k 5` ([tbench.ai docs](https://www.tbench.ai/docs/run-terminal-bench-2-0)). A Terminal-Bench 2.1 leaderboard exists ([Snorkel](https://snorkel.ai/leaderboard/terminal-bench-2-1/)), and Harbor benchmarks can run on third-party sandboxes such as Vercel Sandbox ([Vercel KB](https://vercel.com/kb/guide/run-terminal-bench-harbor-benchmarks-vercel-sandbox)).

> [!question] Unverified
> The Terminal-Bench 2.0 task count (commonly cited as about 89) was not confirmed from a primary page, and the docs page showed a version string "4.0.0", inconsistent with the 2.0 title. Neither SWE-bench nor Terminal-Bench documents network isolation during agent rollout; how each harness sets container networking needs code inspection before paired runs are trusted.

## Method (Proposal)

1. **Pairing.** Each task runs in arm A (agent without the broker) and arm B (agent under `broker run`), same model, same seed, same container image. The harnesses expose no network-policy knob, so the broker wraps the agent process inside the task container.
2. **Repeats.** k≥3 (3-5) per task per arm for variance.
3. **Policies in arm B.** Test separately: a realistic default allowlist (package registries plus git host) and a learned policy from [[Policy Learning Loop]]. Deny-all is a diagnostic, not a release arm.
4. **Task sets.** SWE-bench Verified: the full 500 per release; a stratified 100 in CI. Terminal-Bench 2.x: the full set via Harbor.
5. **Tagging.** Tasks that depend on the live internet (for example `download-youtube`) are tagged and scored apart.
6. **Deny bucketing.** Every deny event in arm B is logged with the task ID and bucketed as (a) policy-caused: a false deny on a necessary action; (b) agent noise; or (c) a network-dependent task that is legitimately blocked. This separates false-deny rate from benchmark flakiness.
7. **Statistics.** Utility cost is the Δ resolve rate with a bootstrap confidence interval; pairing enables a McNemar test.

## Metrics and thresholds (Proposal)

| Metric | Threshold | Anchor |
|---|---|---|
| Resolve-rate change (B − A) | ≤2 points absolute, 95% CI lower bound ≥-3 | none public; engineering target |
| Tasks blocked at least once by a necessary action | ≤2% | none public |
| Per-action false-deny rate | ≤0.5% | auto-mode 0.4% FPR on 10,000 real tool calls ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)) |
| Added wall-clock per task | ≤5% (shared with [[L4 Product Metrics]]) | none public |

## How to run (Proposal)

- `eval/swebench_ab/`: a driver that generates predictions in both arms (agent run with and without `broker run` inside the instance container), then scores both prediction files with the official harness command above, and joins results with broker audit rows by task ID.
- `eval/tbench_ab/`: two Harbor runs with identical parameters except that arm B's agent entrypoint is wrapped by the broker; the broker's audit database is collected per trial.
- CI: stratified 100 SWE-bench Verified tasks weekly during [[M4 Harden and Ship]]; the full sets per release candidate.

## How results feed back

- Policy-caused false denies (bucket a) become fixtures for the default allowlist or the learned policy, and every resulting policy change passes [[SymCC CI Gates]].
- Adapter bugs found here (for example a registry request shape the [[Registry and LLM API Adapters]] mis-classify) become L1 probes.
- Missed thresholds at M4 are published with the measured values and causes ([[Evaluation Harness]] reporting rules).

## How it connects

- part-of:: [[Evaluation Harness]]
- depends-on:: [[Registry and LLM API Adapters]]
- depends-on:: [[L4 Product Metrics]]
- motivated-by:: [[Measurement Gaps]]
- delivered-by:: [[M4 Harden and Ship]]
- depends-on:: [[Policy Learning Loop]]

## Implications for the build

- The broker must work inside the benchmark containers (Linux, x86_64); ensure the `linux-native` backend runs in a container that may lack some kernel features, and fail closed if it cannot, rather than silently running arm B unsandboxed.
- Log deny events with enough context (task ID, adapter verb, rule) to bucket them automatically where possible.

## Open questions

- Terminal-Bench task count and version string; container networking in both harnesses.
- Whether the default allowlist needs documentation hosts beyond registries and the git host; to be learned from bucket (a) denies.

## Sources

- Report: L3 row of the six-layer table.
- Research note 04a Q2 (harness commands, image tiers, hardware, Harbor, live task, version-string inconsistency, 2.1 leaderboard, Vercel KB; inferences on pairing, bucketing, statistics) and Q6 L3.
