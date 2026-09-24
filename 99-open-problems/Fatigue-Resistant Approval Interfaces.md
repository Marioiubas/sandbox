---
title: "Fatigue-Resistant Approval Interfaces"
aliases: []
type: problem
section: open
tags: [sandbox/open, problem, topic/approval, control/hitl, boundary/tb1, adversary/a5, invariant/i8, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Fatigue-Resistant Approval Interfaces

> Approval prompts that show authority diffs and provenance rather than prose, with measured error rates; users approve 93% of prompts and OWASP lists Overwhelming HITL as T10, yet no user study exists.

## The problem

Human approval is the fallback of every capability design (widenings in Progent, irreversible verbs in this broker, `insufficient_scope` step-up in MCP), but humans rubber-stamp. Users approve 93% of Claude Code permission prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)); OWASP lists "Overwhelming HITL" as threat T10 ([OWASP](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)); about 40% of surveyed developers gave agents unrestricted command permissions on low-stakes projects ([METR](https://metr.org/blog/2026-05-19-frontier-risk-report/)). CaMeL, Progent and Willison all flag approval fatigue or approval errors as a limitation ([arXiv](https://arxiv.org/html/2503.18813); [arXiv](https://arxiv.org/html/2504.11703v3); [simonwillison.net](https://simonwillison.net/2025/Apr/11/camel/)), and the record contains no user study.

The research problem: design approval prompts that show ground truth (the authority diff and the provenance of the request) rather than a model's prose summary, and **measure** how often users make the right decision with them.

## Why it matters

- TB1 (human ↔ agent) is a trust boundary; the report trusts the human principal "for intent, not for attentive approval" and requires an approval UI that renders ground truth, not model summaries ([[Trust Boundaries]]).
- Fatigue has been exploited: s1ngularity malware drove local AI CLIs with flags such as `--dangerously-skip-permissions`, `--yolo` and `--trust-all-tools` ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)), and CVE-2025-53773 had an agent write an auto-approve setting ([[Copilot Auto-Approve Settings Write]]). Gemini CLI's prefix-matched allowlist hid a payload behind whitespace ([[Gemini CLI Prefix Allowlist Bypass]]).
- Sandboxing reduces prompts (Anthropic reports 84%, without published methodology ([Anthropic](https://anthropic.com/engineering/claude-code-sandboxing))), which makes the remaining prompts more consequential.

## State of the art

- **Progent**: narrowing updates apply automatically; widenings need approval; only 6% of AgentDojo updates needed approval ([arXiv](https://arxiv.org/html/2504.11703v3)). The paper proposes no UI; research note 02 recommends an approval UX showing the authority diff.
- **MCP authorization**: runtime step-up is signalled by a 403 with `WWW-Authenticate: Bearer error="insufficient_scope"` ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)); the report proposes treating it as the approval hook with an authority diff ([[MCP Authorization Spec]]).
- **Mobile-style incremental prompts** derived from tool-dependency graphs (MiniScope) reduce unnecessary grants with no LLM in the loop.
- **Design rule already adopted**: no flag can disable isolation, egress or brokering; flags only relax in-sandbox prompts ([[I8 No Flag Disables Isolation]]).

> [!question] Unverified
> No user study of approval fatigue for agent capability prompts exists in the record, and no quantitative rubber-stamp data for coding agents beyond Anthropic's 93% and METR's ~40% survey figure.

## Research approach (Proposal)

1. **Prompt content.** Render (a) the authority diff as a Cedar-derived table: new actions, resources and credentials granted, with duration; (b) provenance: which untrusted input (by source and excerpt) preceded the request, from [[Credential Broker as Label Authority]]; (c) reversibility of the verb. Never show the model's own justification as the primary content.
2. **Prompt budget.** Prompt only for irreversible or high-risk verbs (`pr.merge`, `pkg.publish`, forced `git.push`, trifecta-gated writes); everything else is decided by policy or learned.
3. **Study design.** A within-subjects user study with developers: scenarios mixing benign and malicious requests (drawn from the incident record and L2 cases), comparing a prose prompt, an authority-diff prompt, and an authority-diff-plus-provenance prompt. Measure false-approve rate (malicious approved), false-deny rate, time per decision, and decay over a session of N prompts (fatigue).
4. **Field telemetry.** With design partners (opt-in), log prompts shown, decisions and time-to-decision ([[L4 Product Metrics]]).
5. **Adversarial prompts.** Include attacks that craft request content to look benign in the prompt (for example long command strings with hidden payloads, as in the Gemini CLI case) and measure whether the diff view exposes them.

## How it would change the product

- The step-up UI (CLI in the MVP; Slack/Teams in phase 2) would be designed from measured error rates rather than intuition.
- A published result would be a differentiator: the first measured approval-error rates for agent capability prompts.

## Hooks in the MVP

- `grant.request {session_id, action, resource, rationale}` and `decision.explain` on the control API already carry the structured data an authority-diff prompt needs ([[Broker CLI and Daemon]]).
- Prompt and decision events in the audit stream.

## How it connects

- motivated-by:: [[Trust Boundaries]]
- depends-on:: [[I8 No Flag Disables Isolation]]
- motivated-by:: [[Progent]]
- motivated-by:: [[CaMeL]]
- depends-on:: [[MCP Authorization Spec]]
- evaluated-by:: [[L4 Product Metrics]]
- motivated-by:: [[Gemini CLI Prefix Allowlist Bypass]]
- motivated-by:: [[Copilot Auto-Approve Settings Write]]
- contrasts-with:: [[Claude Code and sandbox-runtime]]
- mitigates:: [[Risk Register]]

## Implications for the build

- Every prompt must be generated from structured data (the Cedar delta), never from model text.
- Count prompts per session from M0 so the baseline exists before any UI work.

## Open questions

- Whether provenance excerpts in prompts themselves become an injection vector (attacker-authored text shown to the human).
- What false-approve rate is acceptable, given no public anchor.

## Sources

- Report: problem 8; approval-fatigue paragraph (93%; OWASP T10; prompt rarely, show authority diffs); TB1 row; risk row "Approval fatigue".
- Research note 04b Q2 (84% reduction; METR ~40%; s1ngularity flags; OWASP T10) and gaps.
- Research note 02 Q6 problem 8.
