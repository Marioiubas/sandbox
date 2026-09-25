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
- 2026-09-25: `TCP_NODELAY` on the bridge did not change the Linux numbers (CI run 36085700156: splice new added p50 56 ms, terminated new 116 ms, terminated warm p50 9.3 ms / p95 116 ms), so Nagle was not the cause. The pattern follows audit rows instead: warm spliced requests write none and add ~0.1 ms; each new connection and each terminated request writes write-ahead rows with a full synchronous SQLite commit. The harness now reports audit append latency to confirm fsync cost on the runner; group commit (the recorder's design, not yet built) is the planned fix.
- 2026-09-25: the audit append is not the cause either: on the Linux runner it measured p50 0.39 ms sequential and p50 0.40 ms / p95 5.4 ms from 8 threads (CI run 36087827533), while new connections still added 71-106 ms. Remaining suspect: CPU cost of debug builds (Cedar evaluation per connection, TLS termination) on a 4-vCPU runner with 8 concurrent clients; warm terminated requests, which only evaluate policy, add 12 ms there against 2 ms on the Mac. The `latency` job now measures release builds, which is what the thresholds are for.
- 2026-09-25: release builds. macOS (added p50 / p95): splice warm 0.04 / 0.08 ms; splice new 3.1 / 4.0 ms; terminated warm 0.58 / 1.2 ms; terminated new 4.3 / 6.3 ms; start p50 35.3 ms: every threshold met. Linux runner (CI run 36102519932): splice warm added p50 0.20 ms / p95 1.0 ms; splice new added p50 53.8 ms / p95 125.7 ms; terminated warm added p50 2.6 ms / p95 6.1 ms; terminated new added p50 51.8 ms / p95 106.9 ms; `broker run -- /usr/bin/true` p50 51.1 ms. Warm terminated latency and start time now meet the thresholds on Linux; new connections add a fixed ~52-54 ms whether TLS is spliced or terminated, so neither policy evaluation nor TLS causes it. The pipeline's upstream socket (`TcpStream::connect` in `brokerd::pipeline`) had no `TCP_NODELAY` (the issuer path's socket did): TLS handshake records written back to back wait for the upstream's delayed ACK (≥40 ms on Linux loopback). Fixed; re-measurement pending.
- 2026-09-25: `TCP_NODELAY` on the pipeline's upstream socket did not change Linux either (CI run 36104424285: new connections still add 65-79 ms; warm terminated p50 2.7 ms and start 46 ms meet the thresholds). Three guesses were wrong (bridge Nagle, audit fsync, upstream Nagle); the harness now records curl's phase timings (TCP connect, CONNECT + TLS done, first byte) for new connections so the Linux run shows which stage takes the time.
- 2026-09-25: per-stage timings on Linux (CI run 36108325966, release, sequential): spliced connections are ready inside the broker after ~7 ms (admitted 1.1, logged 2.9, connected 3.4, ClientHello 6.7 ms) yet curl sees TLS done at 21.5 ms (direct 2.7); on terminated hosts the first request is authorized and logged within 1.3 ms but answered at 42 ms, later requests at 1.6 ms. The ~40 ms sits in the broker's first TLS exchange with the upstream. Hypothesis (not yet confirmed): the test upstream server did not disable Nagle, and the broker's TLS client sends its handshake finish and the request separately, so the server's response waits behind its session tickets for the broker's delayed ACK. The test server now sets `TCP_NODELAY` like most production servers; re-measuring.
- 2026-09-25: confirmed half of it: with the test upstream disabling Nagle (as production servers do), the Linux first terminated request is answered at 3.9 ms inside the broker (was 42 ms) and its first byte arrives at 23 ms (was 65 ms) (CI run 36110556727). Still unexplained on Linux: ~18 ms in CONNECT + TLS handshake at one client, ~67 ms added at 8 concurrent clients. The harness now adds a direct baseline loading a bundle as large as the session's (macOS: CA loading costs ~1.4 ms per process) and a single-client new-connection row (macOS: splice +2.5 ms, terminated +4.7 ms).
- 2026-09-25: **found:** most of the Linux new-connection gap is the client loading the session trust bundle, not the broker. A direct curl run that loads a bundle as large as the session's (~125 certificates) reaches TLS done at 15.3 ms against 2.3 ms with one CA (CI run 36112866736, Ubuntu 24.04, OpenSSL 3); through the broker it is 16.5 ms. The broker's own stages agree (spliced connection ready at ~6 ms, first terminated request answered at ~3 ms). Earlier "added latency" figures compared against a one-CA baseline and so counted this load as broker time; the harness now uses a same-size bundle for the direct baseline (macOS, debug build: new connections add 1.1 ms spliced / 3.2 ms terminated with one client, 2.5 / 5.8 ms with 8).
- 2026-09-25: follow-up (open): the session bundle itself is a client-side cost under OpenSSL 3 (~13 ms per load on the runner, per curl process and possibly per connection). Candidates: an OpenSSL hashed CA directory (`SSL_CERT_DIR`, issuers loaded on demand) or fewer public roots; measure before choosing, since GnuTLS and Node clients load trust differently.
- 2026-09-25: **result, release builds, same-size trust bundle on both sides:** Linux (GitHub `ubuntu-24.04` runner, CI run 36115096353): warm terminated added p50 3.1 ms / p95 3.1 ms; new terminated added p50 7.1 ms (8 clients) and 3.1 ms (1 client); warm spliced 0.0 / 0.7 ms; new spliced 3.8 / 2.0 ms; `broker run -- /usr/bin/true` p50 44.9 ms. Every L4 latency threshold is met on Linux and on macOS. Of the earlier findings, two remain real: an upstream that leaves Nagle on can delay the broker's first request on a fresh connection by ~40 ms on Linux (the broker's TLS client sends its handshake finish and the request separately); and the session trust bundle costs OpenSSL 3 clients ~13-18 ms per load. Both are recorded follow-ups. Added wall-clock per task still needs the L3 runs.
