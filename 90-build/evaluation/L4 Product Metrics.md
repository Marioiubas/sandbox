---
title: "L4 Product Metrics"
aliases: ["L4", "Product Metrics"]
type: eval
section: build
tags: [sandbox/build, eval, topic/evaluation, topic/approval, topic/learning, topic/tls, evidence/conflict, evidence/single-source]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-25
summary: AUTO
related: AUTO
sources: AUTO
---

# L4 Product Metrics

> Friction and overhead: >=80% fewer prompts on replayed traces, warm-connection added latency p50 <=5 ms and p95 <=25 ms, new terminated connection p50 <=15 ms, <=5% added wall-clock, native sandbox start <=150 ms, learned policy >=95% coverage within 3 sessions, 0 learned rules broader than a registrable domain without approval.

## What it measures

Whether developers will keep the broker on. Security that adds prompts, latency or startup time gets disabled, and users already approve 93% of Claude Code permission prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)). L4 measures friction (prompts), overhead (latency, wall-clock, start time) and the quality of learned policy (coverage, breadth). The only public numbers in this area come from Anthropic, and no public source gives proxy latency, false-deny rates for a network allowlist, or time-to-policy (research note 04a Q3). These thresholds are engineering targets with no public anchors.

## Metrics and thresholds (Proposal)

| Metric | Definition | Threshold |
|---|---|---|
| Prompt reduction | (prompts per session without broker − with) / without, on the **same replayed traces** | ≥80% |
| Warm-connection added latency | added per request for policy evaluation and credential injection, excluding upstream time, versus a direct connection | p50 ≤5 ms, p95 ≤25 ms |
| New terminated connection added latency | includes TLS termination with a leaf from the per-session CA | p50 ≤15 ms |
| Added wall-clock per task | on L3 benchmark tasks | ≤5% |
| Sandbox start | `broker run` to agent exec, native backends | ≤150 ms |
| Policy-learning coverage | fraction of a held-out trace set's legitimate requests allowed by the learned policy | ≥95% within 3 sessions per project |
| Learned-rule breadth | learned rules broader than a registrable domain without human approval | 0 |
| Policy size and wildcard count | reported alongside coverage | reported |

> [!warning] Conflict
> Research note 05 phrases the M4 latency budget as p50 ≤5 ms per request non-terminated and ≤15 ms terminated, on a laptop. The report's L4 table (used here) says warm-connection p50 ≤5 ms and p95 ≤25 ms, and new terminated connection p50 ≤15 ms. Use the report's figures ([[Open Questions and Unverified Claims]]).

> [!question] Unverified
> Anthropic's "84% fewer permission prompts" has no published methodology (population, baseline configuration, time window) ([Anthropic](https://anthropic.com/engineering/claude-code-sandboxing)). The ≥80% threshold is set near it, but measured by trace replay so the population problem does not recur.

## Reference points

- Auto-mode evaluation is the best public methodology template: three labelled datasets (10,000 real tool calls, 52 real overeager actions, 1,000 synthetic exfiltrations) with FPR/FNR per pipeline stage; the full pipeline reached 0.4% FPR, 17% FNR on overeager actions and 5.7% FNR on synthetic exfiltration ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)).
- A netns, iptables and MITM design with just-in-time certificates added about 14 ms per HTTPS request on an EC2 t3.medium ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)).
- A Linux-VM fallback on macOS raised start time from <5 ms to ~800 ms in one project's measurement ([apple/containerization#737](https://github.com/apple/containerization/issues/737)), which is why the start threshold applies to native backends only.
- Violation telemetry differs by OS: sandbox-runtime taps the macOS sandbox violation log, while Linux/bubblewrap has no built-in reporting and strace is suggested ([srt](https://github.com/anthropic-experimental/sandbox-runtime)). Denied filesystem operations therefore need broker-side instrumentation to count prompts and denies consistently.
- A phished-employee red-team scenario saw credential exfiltration succeed 24 times in 25 retries before mitigations ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)), a reminder that friction metrics are meaningless without the paired containment numbers in [[L2 Injection Benchmarks]].
- Progent needed approval for only 6% of LLM-proposed policy updates on AgentDojo ([arXiv](https://arxiv.org/html/2504.11703v3)), an analog for how often learned-policy widenings should reach a human.

## How to run (Proposal)

- **Prompt replay.** Record tool-call traces from internal and design-partner sessions (opt-in), then replay each trace through the agent's native permission engine and through the broker-wrapped configuration; count prompts in each. Store traces under `eval/` with secrets redacted.
- **Latency.** A local echo server under concurrent load; measure the direct path, the L4 splice path, the warm L7 path and the new-terminated-connection path; report p50/p95/p99 ([[TLS Termination and Per-Session CA]]).
- **Wall-clock.** Taken from the L3 paired runs ([[L3 Real-Work Utility]]).
- **Start time.** Measure `broker run -- /bin/true` on each backend on reference laptops and CI ([[Sandbox Launcher]]).
- **Learning.** For each project, learn from sessions 1..N, test on held-out sessions, and report coverage per N, policy size and wildcard counts ([[Policy Learning Loop]], [[Policy Miner Safeguards]]).

## How results feed back

- Latency regressions block merges once a baseline exists (a CI benchmark job with a tolerance).
- Low coverage points to generaliser parameters (minimum support, k subdomains) in the miner, which must still respect the breadth rule.
- High prompt counts point to approval design; the design goal is to prompt rarely and show authority diffs ([[Fatigue-Resistant Approval Interfaces]]).

## How it connects

- part-of:: [[Evaluation Harness]]
- depends-on:: [[TLS Termination and Per-Session CA]]
- depends-on:: [[Sandbox Launcher]]
- evaluated-by:: [[Policy Learning Loop]]
- depends-on:: [[Policy Miner Safeguards]]
- motivated-by:: [[Fatigue-Resistant Approval Interfaces]]
- motivated-by:: [[Measurement Gaps]]
- delivered-by:: [[M4 Harden and Ship]]
- depends-on:: [[L3 Real-Work Utility]]

## Implications for the build

- Keep the L4 splice path cheap: SNI peek and splice without decryption for hosts with no credential or L7 rule.
- Cache minted tokens per scope digest so steady-state requests do not mint.
- Instrument every prompt and deny with the session ID so replay and live numbers are comparable.

## Open questions

- No data on developer tolerance for proxy latency or on TLS-pinning breakage rates for common dev tools (research note 05 gaps).
- Whether 3 sessions is enough for time-to-policy on large monorepos.

## Sources

- Report: L4 row; ~14 ms reference point.
- Research note 04a Q3 (84% claim, 93% approval, auto-mode datasets, 24 of 25 retries, violation telemetry, metric definitions) and Q6 L4.
- Research note 05 section 5.2 M4 row (conflicting phrasing).

## Build log

- 2026-09-25: the latency harness is `code/tests/conformance/tests/m4_latency.rs` (direct, L4 splice and terminated L7 paths; warm and new connections; 8 concurrent curl clients; `broker run -- /usr/bin/true`). First measurement, macOS 26 on Apple silicon, debug build: splice warm added p50 0.05 ms / p95 0.06 ms; splice new added p50 4.0 ms; terminated warm added p50 2.2 ms / p95 4.5 ms; terminated new added p50 7.5 ms / p95 11.6 ms; `broker run -- /usr/bin/true` p50 58.8 ms / p95 61.9 ms. Thresholds met on this machine; release builds and Linux runs (the `latency` CI job) to follow. Added wall-clock per task needs the L3 runs.
- 2026-09-25: first Linux measurement (GitHub `ubuntu-24.04` runner, debug build, CI run 36084077212): splice warm added p50 −0.1 ms / p95 0.1 ms; splice new added p50 46.7 ms / p95 61.4 ms; terminated warm added p50 7.4 ms / p95 10.2 ms; terminated new added p50 59.1 ms / p95 85.5 ms; `broker run -- /usr/bin/true` p50 70.9 ms. New connections miss the threshold by ~45 ms and warm terminated p50 misses by ~2 ms. Suspected cause: the in-namespace bridge relayed TCP without `TCP_NODELAY` (a small write after another waits for the client's delayed ACK); fixed in the bridge, to be re-measured.
