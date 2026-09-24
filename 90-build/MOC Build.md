---
title: "MOC Build"
aliases: []
type: moc
section: build
tags: [sandbox/build, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "How to build it: stack, repository layout, the ten-week plan with milestones M0-M4 and their acceptance criteria, the six-layer evaluation harness, red-team plan and risks."
related: ["[[Tech Stack]]", "[[Repository Layout]]", "[[MVP Plan]]", "[[M0 Contained Run]]", "[[M1 Secrets Outside]]", "[[M2 Policy Audit and Learn]]", "[[M3 CI Identity and MCP]]", "[[M4 Harden and Ship]]", "[[Evaluation Harness]]", "[[L1 Conformance Suite]]", "[[L2 Injection Benchmarks]]", "[[L3 Real-Work Utility]]", "[[L4 Product Metrics]]", "[[Conformance Probe Matrix]]", "[[Red-Team Plan]]", "[[Risk Register]]", "[[MOC Architecture]]", "[[MOC Decisions]]", "[[SymCC CI Gates]]", "[[SandboxEscapeBench]]", "[[Build Log]]"]
sources: []
---

# MOC Build

> How to build it: stack, repository layout, the ten-week plan with milestones M0-M4 and their acceptance criteria, the six-layer evaluation harness, red-team plan and risks.

This is where Claude Code works. The plan is a ten-week, fail-closed MVP gated by a deterministic egress-bypass conformance suite, injection-benchmark containment runs and paired utility runs. Code lives in `code/` at the vault root, laid out as in [[Repository Layout]] (see [[CLAUDE]]). Work milestone by milestone; a milestone is done only when its acceptance criteria pass and its notes are updated to `status: built`.

## Milestones at a glance (Proposal; 2-3 engineers)

| Weeks | Milestone | Headline acceptance |
|---|---|---|
| 1-2 | [[M0 Contained Run]] | `broker run -- claude` / `-- codex` fix a failing test on macOS and Ubuntu; probe categories 3, 4, 5, 9, 10 fully denied; launch fails closed |
| 3-4 | [[M1 Secrets Outside]] | only sentinels visible in the sandbox; pushes scoped to `agent/*` on the session repo; foreign keys rejected |
| 5-6 | [[M2 Policy Audit and Learn]] | learned policy passes 3 repos x 3 agents with 0 denies; seeded injection blocked and logged; OCSF events reach a test SIEM |
| 7-8 | [[M3 CI Identity and MCP]] | CI agent sees no long-lived secret; IdP subject in audit; GitHub MCP toxic flow stopped at the public write |
| 9-10 | [[M4 Harden and Ship]] | >=24 h fuzzing, no crashes; thresholds met or documented; pentest closes with no open highs |

The conformance corpus starts in week one and grows with every milestone, because enforcement-layer bugs are the dominant failure class.

## Plan and stack

- [[MVP Plan]] — Ten weeks for 2-3 engineers in five milestones, compressible to about seven by dropping MCP and AWS from M3, with the conformance corpus growing from week one; then phase 2 (control plane, VM/container backends, Kubernetes and gateway modes, SOC 2 Type I) and phase 3 (Windows, ID-JAG and Entra registration, Biscuit delegation, anomaly baselines, ACE-style plan analysis).
- [[Tech Stack]] — Rust single static binary (tokio, hyper 1.x, rustls, rcgen; hudsucker as reference), cedar-policy in-process and cedar-policy-symcc with cvc5 in CI, bwrap plus landlock plus seccompiler plus nix, generated SBPL, SQLite WAL, OpenTelemetry/OCSF, axum plus Postgres control plane, and signed, notarised, SBOM-carrying packaging.
- [[Repository Layout]] — The Cargo workspace tree that code/ must follow: crates (broker-cli, brokerd, launcher, netguard, tls, l7, creds, policy, grant, audit, learn, mcpguard), profiles, policies, integrations, ee/, tests (e2e, conformance, bypass-corpus, fuzz), eval, packaging and docs.

## Milestones

- [[M0 Contained Run]] — Weeks 1-2: workspace skeleton, broker run, Seatbelt and bwrap+Landlock+seccomp backends, empty netns plus UDS bridge, CONNECT and SOCKS5 with host allowlist, canonicaliser, broker DNS, fail-closed launch; done when claude and codex fix a failing test on macOS 15/26 and Ubuntu 22.04/24.04 with probe categories 3, 4, 5, 9 and 10 fully denied.
- [[M1 Secrets Outside]] — Weeks 3-4: per-session CA and trust-bundle env, selective TLS termination, sentinel swap in headers and bodies, foreign-credential rejection, keychain store, GitHub App minting (TTL <=1 h), git smart-HTTP adapter, method and path rules; done when scans find only sentinels and pushes are scoped to agent/x on the session repo.
- [[M2 Policy Audit and Learn]] — Weeks 5-6: Cedar schema, TOML-to-Cedar compiler, enforce and audit modes, hash-chained SQLite, OTLP/OCSF export, broker learn and suggest, SymCC CI gates, exporters to Claude Code and Codex; done when learned policy passes 3 repos x 3 agents with 0 denies and a seeded injection is blocked and logged.
- [[M3 CI Identity and MCP]] — Weeks 7-8: GitHub Action with runner OIDC, OIDC device login to Okta/Entra dev tenants, MCP guard with manifest pinning, AWS STS minting with session policy and SigV4, trifecta context; done when an untrusted-issue CI fixture exposes no long-lived secret and the GitHub MCP toxic flow replay is stopped at the public write.
- [[M4 Harden and Ship]] — Weeks 9-10: >=24 h fuzzing per target with no crashes, threat-model document, notarised Homebrew, deb and rpm, cosign and SBOM, first L2/L3 runs, 3-5 design partners; done when latency and utility thresholds are met or documented and an external pentest closes with no open high findings.

## Evaluation harness

Layers L1-L6. L5 is [[SymCC CI Gates]] and L6 is [[SandboxEscapeBench]].

- [[Evaluation Harness]] — The six-layer harness (L1 conformance, L2 injection benchmarks, L3 real-work utility, L4 product metrics, L5 formal gates, L6 boundary regression) with release thresholds anchored to public reference points, metric definitions and reporting rules (utility always paired with attack success; separate 'model complied, broker blocked' count).
- [[L1 Conformance Suite]] — Deterministic, scripted, non-LLM probes in and out of policy for every probe category, HTTP Garden-style differential fuzzing of URL and HTTP parsing against curl, requests/httpx and undici, >=24 h cargo-fuzz per target, and the public bypass corpus; any failure blocks release.
- [[Conformance Probe Matrix]] — The twelve probe categories and pass criteria: allowed-destination abuse, credential exposure, name resolution, IP literals, alternate protocols, redirects, Host/SNI/CONNECT mismatch, parser differentials, proxy bypass, filesystem, covert channels (measured, not claimed zero) and boundary escape.
- [[L2 Injection Benchmarks]] — AgentDojo (97 tasks, 629 cases) and AgentDyn (560 cases) with the broker as the defense via a shim that turns mocked side effects into real HTTP through the proxy, >=2 frontier models and ASR@k for k=10-100; model-level suites (InjecAgent, ASB, WASP, OS-Harm, AgentHarm, CyberSecEval) as traffic generators.
- [[L3 Real-Work Utility]] — Paired A/B runs, same model and seed, k>=3, on SWE-bench Verified (500 or stratified 100 in CI) and Terminal-Bench 2.x via Harbor, live-internet tasks tagged apart, every deny bucketed as policy-caused, agent noise or legitimately blocked.
- [[L4 Product Metrics]] — Friction and overhead: >=80% fewer prompts on replayed traces, warm-connection added latency p50 <=5 ms and p95 <=25 ms, new terminated connection p50 <=15 ms, <=5% added wall-clock, native sandbox start <=150 ms, learned policy >=95% coverage within 3 sessions, 0 learned rules broader than a registrable domain without approval.
- [[Red-Team Plan]] — Three rings: automated (L1 on every commit, nightly fuzzers, adaptive LLM attackers per probe category reporting ASR@k), human (quarterly external pentest incl. white-box attacks on the Cedar entity builder) and public (bug bounty launched with the corpus).

## Risks

- [[Risk Register]] — All risks with evidence and mitigations: vendor bundling, OpenShell as default data plane, the broker's own bugs, credential honeypot, misuse within scope, Seatbelt removal, Linux platform variance, TLS breakage (pinning, QUIC, ECH), learned-policy over-grant, approval fatigue, upstream scoping limits, vendor hook instability, buyer budget.

## How this section connects

- Each milestone links to the components in [[MOC Architecture]] it delivers; build them in the milestone order, not the MOC order.
- Record every design change as an ADR in [[MOC Decisions]] and every session in [[Build Log]].
- Threats that the tests must reproduce come from [[MOC Threat Model]]; what the product can publish as research comes from [[MOC Open Problems]].
