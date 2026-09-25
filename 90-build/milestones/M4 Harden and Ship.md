---
title: "M4 Harden and Ship"
aliases: ["M4"]
type: milestone
section: build
tags: [sandbox/build, milestone, milestone/m4, topic/evaluation, topic/supply-chain, topic/build, platform/macos, platform/linux, evidence/conflict]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-25
summary: AUTO
related: AUTO
sources: AUTO
milestone: M4
---

# M4 Harden and Ship

> Weeks 9-10: >=24 h fuzzing per target with no crashes, threat-model document, notarised Homebrew, deb and rpm, cosign and SBOM, first L2/L3 runs, 3-5 design partners; done when latency and utility thresholds are met or documented and an external pentest closes with no open high findings.

## Goal

M4 converts a working broker into a shippable one. The product's credibility "will rest less on its architecture, which competitors can copy, than on its evidence: a public bypass corpus, SymCC-gated policy changes, and paired utility-and-containment numbers" (report conclusion). M4 therefore produces that evidence for the first time, hardens every parser with long fuzzing campaigns, ships signed artifacts and an honest threat-model document, and puts the broker in front of 3-5 design partners who run it daily.

The hardening emphasis follows the record: the sandbox-runtime NUL-byte parser differential was exposed for about 5.5 months ([Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)), eleven of twelve April 2026 Wasmtime advisories were found "using new LLM-based tools" ([Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-security-advisories)), and the team should expect the same scrutiny of its own proxy.

## Scope

**In scope (report M4 row):** ≥24 h fuzzing per target with no crashes; threat-model document; notarised Homebrew, deb and rpm; cosign plus SBOM; first L2/L3 evaluation runs; 3-5 design partners; performance budget; docs; external pentest of proxy and launcher.

**Out of scope:** new features. Anything that is not hardening, evaluation, packaging or partner support waits for phase 2 ([[MVP Plan]]). The public bug bounty launches with the corpus but may trail M4 ([[Red-Team Plan]]).

## Prerequisites

- [[M3 CI Identity and MCP]] is `status: built` (or its compressed variant, with an ADR).
- Every parser exists: `canon`, `socks5`, `http1`, `h2`, `pktline`, `jsonrpc` ([[Repository Layout]]).
- A pentest vendor engaged for proxy and launcher (and MCP guard where in scope), including a white-box look at the Cedar entity builder ([[Red-Team Plan]]).
- Apple Developer ID certificate and notarisation credentials, cosign keys, CI runners for macOS and Linux; x86_64 machines with 120 GB disk, 16 GB RAM and 8+ cores for the SWE-bench harness ([SWE-bench harness docs](https://www.swebench.com/SWE-bench/reference/harness/)).
- Model API budget for L2/L3 paired runs on ≥2 frontier models.

## Ordered task checklist (Proposal)

**Fuzzing and differential testing**

- [ ] Run each `tests/fuzz/fuzz_targets/*` for ≥24 h (continuous nightly jobs accumulate toward this); triage and fix every crash; add each crashing input to the corpus. — started: `.github/workflows/fuzz-nightly.yml` runs all 16 targets for 2 h each per night with the corpus cached between runs and crash inputs uploaded.
- [ ] HTTP Garden-style differential fuzzing of URL and HTTP parsing against curl, requests/httpx and undici ([arXiv 2405.17737](https://arxiv.org/abs/2405.17737)); acceptance is 0 decision-changing discrepancies ([[L1 Conformance Suite]]).
- [ ] Complete all 12 categories of the [[Conformance Probe Matrix]], including category 11 (covert channels: bandwidth measured and reported, not claimed zero) and category 12 (boundary escape). — 1-10 automated (M0-M3); 11 measured by `m4_covert` (query strings ≈81 KB/s, path choice ≈93 B/s, timing ≈0.9 B/s on one laptop); 12 not started (needs nested VMs).

**Evaluation (eval/)**

- [ ] `eval/agentdojo_shim/`: the shim that turns mocked tool side effects into real HTTP through the proxy; run AgentDojo and AgentDyn with ≥2 frontier models; report ASR@k for k=10-100 ([[L2 Injection Benchmarks]]).
- [ ] `eval/swebench_ab/` and `eval/tbench_ab/`: paired A/B runs, same model and seed, k≥3, SWE-bench Verified (500, or stratified 100 in CI) and Terminal-Bench 2.x via Harbor; tag live-internet tasks separately; bucket every deny ([[L3 Real-Work Utility]]).
- [ ] `eval/escapebench/`: SandboxEscapeBench scenarios at difficulty 1-3, run nested in VMs ([[SandboxEscapeBench]]).
- [x] Latency harness: local echo server under concurrent load; measure warm-connection and new-terminated-connection added latency, per-task wall-clock and sandbox start ([[L4 Product Metrics]]). (`tests/conformance/tests/m4_latency.rs`, run on demand and by the non-gating `latency` CI job on Linux; per-task wall-clock comes with the L3 runs)
- [ ] Trace replay: prompts per session with and without the broker on the same traces; learned-policy coverage within 3 sessions.

**Threat model and docs**

- [x] `docs/threat-model.md` stating the four non-goals so buyers are not misled: misuse inside granted scope, text-only manipulation with no side effect, host-kernel zero-days in the standard tier, and operator abuse (only partly addressed) ([[Threat Model Non-Goals]], [[Threat Model Overview]]).
- [x] `docs/policy-reference.md` and `docs/deployment/` for laptop and CI. (`docs/deployment/laptop.md`, `docs/deployment/ci.md`)
- [x] Audit the CLI output and code comments for any claim that the broker stops prompt injection; it does not ([[CLAUDE]] section 2). (2026-09-25: none found in code, CLI strings, docs or the Action; re-check before release)

**Packaging and supply chain (packaging/)**

- [ ] macOS universal2 build, Developer ID signing with hardened runtime, notarisation via `notarytool`, Homebrew tap formula ([[Tech Stack]]).
- [ ] Linux musl static builds; `.deb` and `.rpm` via nfpm; static tarball; installer handling of the Ubuntu AppArmor userns restriction.
- [ ] cosign signatures, CycloneDX SBOM and SLSA provenance on every artifact.
- [x] `broker doctor` reports every layer and the TLS compatibility matrix (pinning passthrough list, QUIC blocked). (per grant: terminated with protocol and credential, spliced, or passthrough; the protocol matrix; identity and MCP settings; `m4_doctor`)

**Red team and partners**

- [ ] External pentest of proxy and launcher; track findings to closure.
- [ ] Adaptive LLM attackers per probe category (automated ring) report ASR@k ([[Red-Team Plan]]).
- [ ] Onboard 3-5 design partners; collect denies, prompts and breakages weekly; feed false denies into [[Policy Learning Loop]] fixtures.

**Risk review**

- [ ] Walk every row of [[Risk Register]]; update likelihood and status with M4 evidence.

## Components delivered

No new runtime component. M4 delivers the release artifacts, `docs/threat-model.md`, the public `tests/bypass-corpus`, the `eval/` harnesses and the first published numbers from the [[Evaluation Harness]]. It moves every component note that was `built` to include fuzzing and pentest evidence in its Build log.

## Acceptance criteria

| # | Criterion | Test | Threshold |
|---|---|---|---|
| E1 | ≥24 h fuzzing per target with no crashes | fuzz job logs for every target | ≥24 h each; 0 unresolved crashes |
| E2 | L1 release gate ([[L1 Conformance Suite]]) | full conformance + differential run | 100% out-of-policy denied; 0 canary leaks; 100% in-policy controls succeed; 100% denies logged with reason; 0 decision-changing parser discrepancies |
| E3 | Latency thresholds met or documented ([[L4 Product Metrics]]) | echo-server load test | warm-connection added latency p50 ≤5 ms and p95 ≤25 ms; new terminated connection p50 ≤15 ms; ≤5% added wall-clock per task; native sandbox start ≤150 ms |
| E4 | Utility thresholds met or documented ([[L3 Real-Work Utility]]) | paired A/B | resolve-rate change ≤2 points (95% CI lower bound ≥-3); ≤2% of tasks blocked by a necessary action; per-action false-deny ≤0.5% |
| E5 | First L2 run ([[L2 Injection Benchmarks]]) | AgentDojo + AgentDyn with shim | side-effect ASR ≤1% AgentDojo, ≤2% AgentDyn; benign-utility drop ≤5 points on AgentDojo; AgentDyn benign utility ≥80% of undefended (met or documented) |
| E6 | L6 boundary regression | SandboxEscapeBench difficulty 1-3 | 0 escapes with frontier models at default budget |
| E7 | External pentest of proxy and launcher | vendor report | no open high findings |
| E8 | Design partners run daily | partner telemetry (opt-in) | 3 partners daily (research note 05); plan says 3-5 |
| E9 | Signed artifacts | verify cosign, notarisation and SBOM in CI | all artifacts verify |

"Met or documented" means a threshold that is missed must be published with the measured value, the cause and a remediation plan; it does not block release. E1, E2, E6, E7 and E9 are hard gates.

> [!warning] Conflict
> M4 latency targets differ slightly between sources. The report's L4 table says warm-connection added latency p50 ≤5 ms and p95 ≤25 ms, and new terminated connection p50 ≤15 ms. Research note 05 phrases M4 as p50 ≤5 ms per request non-terminated and ≤15 ms terminated, on a laptop. This note uses the report's L4 table, as [[Open Questions and Unverified Claims]] directs.

## Eval layers and probes that must pass

All six layers of the [[Evaluation Harness]]: L1 (hard gate), L2 and L3 (first runs; met or documented), L4 (met or documented), L5 [[SymCC CI Gates]] (100% pass) and L6 [[SandboxEscapeBench]] (hard gate at difficulty 1-3). Every report pairs utility with attack success and keeps a separate "model complied, broker blocked" count.

## Risks

- **Fuzzing finds a design-level bug late** (for example in canonicalisation semantics): fix it even if it slips the date; an unfixed parser differential is the failure the whole product exists to prevent.
- **No public anchors for latency**: the thresholds are engineering targets; a proxy reference point is about 14 ms added per HTTPS request for a netns, iptables and MITM design on an EC2 t3.medium ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)).
- **Benchmark harness networking unknown**: how SWE-bench and Terminal-Bench set container networking needs code inspection before paired runs are trusted ([[L3 Real-Work Utility]]).
- **Pentest scope creep**: keep MCP guard in scope only if time allows; proxy and launcher are mandatory.
- **Design partners hit TLS pinning or QUIC breakage**: keep the passthrough list and `broker doctor` current.

## Definition of done

1. E1, E2, E6, E7, E9 pass; E3, E4, E5, E8 are met or documented with published numbers; test and report names in the Build log.
2. All invariants I1-I9 have passing tests; none was weakened without an ADR.
3. The conformance corpus covers all 12 categories and is published; 100% of out-of-policy probes denied and logged with a reason.
4. Every component note is `status: built` with fuzzing and pentest evidence; deviations have ADRs.
5. [[Build Log]] entry summarising the MVP; [[Risk Register]] updated; resolved items ticked in [[Open Questions and Unverified Claims]].
6. Set this note and [[MVP Plan]] to `status: built`.

## How it connects

- depends-on:: [[M3 CI Identity and MCP]]
- depends-on:: [[Tech Stack]]
- evaluated-by:: [[L1 Conformance Suite]]
- evaluated-by:: [[L2 Injection Benchmarks]]
- evaluated-by:: [[L3 Real-Work Utility]]
- evaluated-by:: [[L4 Product Metrics]]
- evaluated-by:: [[SandboxEscapeBench]]
- evaluated-by:: [[Red-Team Plan]]
- implements:: [[Threat Model Overview]]
- implements:: [[Threat Model Non-Goals]]
- motivated-by:: [[Risk Register]]
- motivated-by:: [[sandbox-runtime SOCKS NUL-Byte Bypass]]
- part-of:: [[MVP Plan]]

## Implications for the build

- Publishing the corpus and paired numbers is a deliverable, not marketing; no neutral benchmark of this kind exists ([[Measurement Gaps]]).
- Keep "model complied, broker blocked" as its own column; it isolates the defense-in-depth value the broker adds.
- Adaptive attacks change numbers: Gray Swan single-attempt success of about 0.1% rose to 5-6% after 100 adaptive attempts ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)), so report ASR@k, not single-shot ASR.

## Open questions

- Terminal-Bench 2.0 task count and the "4.0.0" version string on its docs page ([[L3 Real-Work Utility]]).
- AgentDojo pipeline/defense hook API names ([[L2 Injection Benchmarks]]).
- Developer tolerance for proxy latency and real-world TLS-pinning breakage rates are missing from the record.

## Sources

- Report: milestone row "Weeks 9-10 M4 Harden and ship"; six-layer harness thresholds; red-team plan; conclusion.
- Research note 05 section 5.2 M4 row and section 5.5 (parser differential ~5.5 months exposed).
- Research note 04a Q2 and Q6.

## Build log

- 2026-09-25: started while M3 waits on outside accounts: nightly fuzzing toward E1 (`fuzz-nightly.yml`); the E3 latency harness (`m4_latency`), first measurement on macOS 26, Apple silicon, debug build, 8 concurrent clients, loopback echo server: splice warm added p50 0.05 ms / p95 0.06 ms; splice new added p50 4.0 ms; terminated warm added p50 2.2 ms / p95 4.5 ms; terminated new added p50 7.5 ms / p95 11.6 ms; `broker run -- /usr/bin/true` p50 58.8 ms / p95 61.9 ms (all within the L4 thresholds); `docs/threat-model.md` brought up to M3 (M2 and M3 controls and residuals); the injection-claims audit found nothing to change.
- 2026-09-25: category 11 measured (`m4_covert`); the figures are in [[Conformance Probe Matrix]] and `docs/threat-model.md`.
- 2026-09-25: `broker doctor` shows how TLS is handled per grant and the protocol matrix, and compiles the user policy with its issuers (before, a valid policy with GitHub App or AWS credentials was reported INVALID); test `m4_doctor`.
- 2026-09-25: deployment guides for laptop (requirements per OS, install outside writable mounts, paths, first run) and CI (the Action, identity trust, credentials from the broker, attribution by claims).
- 2026-09-25: Linux latency (CI): new connections added ~47-59 ms (threshold 15 ms), warm terminated p50 7.4 ms (threshold 5 ms); the bridge now sets `TCP_NODELAY`; re-measurement pending.
- 2026-09-25: the bridge `TCP_NODELAY` change did not fix Linux latency; the per-row synchronous audit commit is the next suspect (append latency now measured in the harness).
- 2026-09-25: audit appends measure ~0.4 ms on the Linux runner, so they do not explain its new-connection latency; group commit built anyway (the recorder's design); the `latency` job now measures release builds.
