---
title: "Measurement Gaps"
aliases: []
type: problem
section: open
tags: [sandbox/open, problem, topic/evaluation, topic/mcp, topic/egress, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Measurement Gaps

> Three measurement gaps: the first public benchmark scoring egress and credential containment with real traffic, proxy latency and false-deny baselines for agent workloads, and the base rate at which real MCP servers change tool descriptions.

## The problem

Three things nobody in the record measures, each of which the product needs and can publish first:

1. **A public benchmark that scores egress and credential containment with real traffic.** No public benchmark scores an egress and credential broker directly, meaning real network exfiltration and credential injection (report; research note 04a Q1). Existing injection suites use simulated Python tools with no real network or filesystem; model-level suites measure the model, not containment. SandboxEscapeBench targets the container boundary, not egress policy ([arXiv 2603.02277](https://arxiv.org/html/2603.02277v1)).
2. **Proxy latency and false-deny baselines for agent workloads.** No public data exists on per-request latency of Claude Code's sandbox proxy or any comparable agent egress proxy, and no public false-deny numbers for domain allowlists or time-to-policy exist from any vendor or paper (research note 04a Q3). The only public anchors are Anthropic's 84% prompt reduction (no methodology) and auto-mode's classifier metrics ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)), plus one ~14 ms per-request reference for a netns, iptables and MITM design ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)).
3. **The base rate at which real MCP servers change tool descriptions.** Rug pulls (a server changing descriptions after approval) are documented ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)), and postmark-mcp shipped a malicious update that BCC'd every email ([The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)). But no study measures how often benign servers change descriptions, which determines how often the [[MCP Guard]]'s revoke-on-change rule will interrupt users.

## Why it matters

- The report's conclusion: the product's credibility "will rest less on its architecture, which competitors can copy, than on its evidence", and since nobody publishes these numbers, "being first to publish them is part of the product".
- Without baselines, L3 and L4 thresholds cannot be calibrated; they are engineering targets ([[L3 Real-Work Utility]], [[L4 Product Metrics]]).
- Without the MCP base rate, the pinning policy's usability cost is unknown: too many benign changes and users will disable pinning, too few measured and the rule looks free.

## State of the art

- AgentDojo (97 tasks, 629 cases) and AgentDyn (560 cases) score system-level defenses but on simulated tools ([AgentDyn](https://arxiv.org/html/2602.03117v1)).
- WASP separates intermediate (16-86%) from end-to-end (0-17%) attack success in real web environments ([arXiv 2504.18575](https://arxiv.org/abs/2504.18575v2)).
- No open-source agent-egress conformance suite exists in the record ([[Conformance Probe Matrix]]).
- No published study reports SWE-bench or Terminal-Bench scores with versus without an egress sandbox.
- No MCP-specific security benchmark was researched in the record.

## Research approach (Proposal)

1. **Containment benchmark.** Package [[L1 Conformance Suite]] (deterministic probes, bypass corpus) plus the L2 shim that turns AgentDojo/AgentDyn side effects into real HTTP ([[L2 Injection Benchmarks]]) into a public benchmark any egress broker can run: real traffic to mock upstreams, canary credentials, scoring on (utility, containment, "model complied, broker blocked"). Include category-level results for the twelve probe categories.
2. **Latency and false-deny baselines.** Publish the L4 echo-server methodology and results (p50/p95/p99 for splice, warm L7 and new terminated connections), and L3 paired results with the deny buckets (policy-caused, agent noise, legitimately blocked) ([[Evaluation Harness]]).
3. **MCP description-change base rate.** Periodically fetch `tools/list` from a sample of public MCP servers (by package version and, where possible, live endpoints), hash names, schemas and descriptions as the [[MCP Guard]] does, and record change frequency and change type (cosmetic, schema, semantic). With design partners, log pin-revocation events (opt-in).
4. **Boundary layer.** Keep [[SandboxEscapeBench]] runs (difficulty 1-3, nested VMs) in the published set so the OS layer is scored separately from policy.

## How it would change the product

- Evidence becomes the moat: the corpus, SymCC-gated changes and paired numbers, published together.
- The MCP base rate sets the revoke-on-change UX: if benign changes are frequent, re-approval must show a semantic diff of descriptions, not a hash mismatch.

## Hooks in the MVP

- The `eval/` directory and the reporting rules exist from M4 ([[M4 Harden and Ship]]).
- `manifest_pin.rs` in `mcpguard` produces the hashes the base-rate study needs.

## How it connects

- motivated-by:: [[Evaluation Harness]]
- depends-on:: [[L1 Conformance Suite]]
- depends-on:: [[L3 Real-Work Utility]]
- depends-on:: [[L4 Product Metrics]]
- depends-on:: [[MCP Guard]]
- motivated-by:: [[postmark-mcp Rug Pull]]
- depends-on:: [[SandboxEscapeBench]]

## Implications for the build

- Treat the corpus and benchmark harness as publishable artifacts: data files, clear licences, no secrets, reproducible commands.
- Log MCP manifest hash changes with enough detail (which field changed) to support the base-rate study.

## Open questions

- Whether other vendors would run a neutral containment benchmark, and who should host it.
- How to sample MCP servers representatively.

## Sources

- Report: "Three measurement gaps sit alongside these"; "No public benchmark scores an egress and credential broker directly"; Conclusion.
- Research note 04a Q1 and Q3 gaps; research note 02 Q3 gaps (no rug-pull base-rate study).
