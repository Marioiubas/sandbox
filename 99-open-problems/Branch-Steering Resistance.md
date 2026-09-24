---
title: "Branch-Steering Resistance"
aliases: []
type: problem
section: open
tags: [sandbox/open, problem, topic/policy, topic/ifc, adversary/a1]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Branch-Steering Resistance

> Require every branch of an approved plan to satisfy policy independently and treat branch predicates computed from untrusted observations as low-integrity.

## The problem

Fixing control flow in advance is not enough if the plan has branches and the attacker controls what the agent observes when it picks one. "CaMeLs Can Use Computers Too" (Jan 2026) has a trusted planner emit a full execution graph with conditional branches before seeing any screen content, gated by observe-verify-act checks. It then shows a new attack, **Branch Steering**: the adversary manipulates the UI so that a valid, pre-approved branch is taken, for example by spoofing cookie pop-ups in ads or with gradient pixel perturbations that defeat redundancy defenses ([arXiv](https://arxiv.org/html/2601.09923v1)). Frontier models retained up to 57% of original success in that design.

The research problem: make plans and policies such that steering the agent onto any pre-approved branch cannot cause a policy violation, and such that predicates evaluated on attacker-visible data cannot unlock authority.

## Why it matters

- Branch steering is one instance of the general residual attack on deterministic monitors: attacks that **choose among allowed actions** (research note 02 Q3 and Q5). The design-patterns paper calls the same thing data-parameter manipulation ([arXiv](https://arxiv.org/html/2506.08837)).
- The broker's policies are also "pre-approved branches": a task grant allows several actions, and an injection can steer which one is used. If any single allowed action is harmful in context, the grant is too broad.

## State of the art

- **CaMeL** tracks provenance per value and checks policies at tool calls, with a STRICT mode that adds conditional tests as dependencies of assigned variables (control-dependency tainting) ([arXiv](https://arxiv.org/html/2503.18813)). See [[CaMeL]].
- **Research note 02's audit** recommends: treat branch predicates as low-integrity when their inputs are untrusted, and require every branch to be independently policy-safe; make STRICT the default for side-effecting calls.
- No paper in the record evaluates a defense against Branch Steering specifically.

## Research approach (Proposal)

1. **All-branches check.** For a plan or grant with alternatives, require that each alternative independently satisfies policy. In Cedar terms, for each action the grant permits, run [[SymCC CI Gates]]-style checks that the action alone (under worst-case context) implies the org ceiling and the flow policies; a grant fails if any permitted branch would violate them.
2. **Predicate integrity.** When the broker can see why a branch was taken (for example an MCP `tools/call` whose arguments or selection depend on a prior untrusted response), mark the resulting request's context `branch_integrity = untrusted` and forbid high-risk verbs under that label unless approved. This builds on per-argument labels from [[Provenance-Aware Cedar]] and [[Information Flow Control]].
3. **Plan-level analysis.** Where a planner emits an explicit plan (ACE-style), analyse every branch statically before execution ([[ACE and IsolateGPT]]).
4. **Evaluate.** Build branch-steering variants of L2 cases: tasks with two allowed actions where the injection selects the harmful one; measure ASR with and without the all-branches check and predicate integrity, and the utility cost.
5. **Adaptive attackers.** Include branch steering as a goal category for the automated red-team ring ([[Adaptive Evaluation of Deterministic Monitors]]).

## How it would change the product

- Grant design would change from "the actions the task needs" to "the actions the task needs, each of which is safe even if chosen adversarially"; this is a sharper least-privilege rule for the learner ([[Trace-Mined Least Privilege]]).
- Approval prompts would fire for high-risk verbs chosen on untrusted evidence, not for all of them, which reduces prompts while closing a class of attacks.

## Hooks in the MVP

- The narrow-verb design (PR create ≠ merge, push only to `agent/*`) already applies the all-branches idea at the verb level.
- The Rule-of-Two forbid is the session-level version of predicate integrity ([[Trifecta Session Labels]]).

## How it connects

- motivated-by:: [[CaMeL]]
- depends-on:: [[Provenance-Aware Cedar]]
- depends-on:: [[Information Flow Control]]
- part-of:: [[Dynamic Tasks Without Control-Flow Hijack]]
- evaluated-by:: [[Adaptive Evaluation of Deterministic Monitors]]
- motivated-by:: [[ACE and IsolateGPT]]

## Implications for the build

- When writing default policies, ask of every permitted action: is it safe if an attacker picks it? If not, split the verb or gate it.
- Preserve in audit events which prior response (by fingerprint) a request's arguments matched, so branch provenance can be analysed later.

## Open questions

- How the broker can observe branch predicates at all when the agent's reasoning is opaque; it may only see the chosen action, not why.
- Whether the all-branches check produces unacceptable false denies on real coding tasks ([[L3 Real-Work Utility]]).

## Sources

- Report: problem 4; audit-table row "CaMeLs for computer use".
- Research note 02 Q2 (Branch Steering: cookie-popup spoofing, pixel perturbations), Q3 inference (attacks that choose among allowed actions), Q6 problem 4.
