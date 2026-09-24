---
title: "Dynamic Tasks Without Control-Flow Hijack"
aliases: []
type: problem
section: open
tags: [sandbox/open, problem, topic/policy, topic/evaluation, evidence/conflict]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Dynamic Tasks Without Control-Flow Hijack

> Allow safe re-planning where every re-plan is checked as a narrowing of the original grant, and measure it on AgentDyn where all current capability systems collapse.

## The problem

Capability-style defenses get their security by fixing control flow from trusted input before untrusted data is seen. That works when the plan is knowable up front and fails when it is not. AgentDyn (Feb 2026; 60 open-ended tasks, 560 injection cases, 7.1 average steps versus AgentDojo's 3.49) found CaMeL at zero utility on open-ended tasks, Tool Filter at 8.33% benign utility, Progent struggling to assign privileges with larger tool sets, and DRIFT keeping only about 30% utility on GPT-4o ([AgentDyn](https://arxiv.org/html/2602.03117v1)). The best-utility defense there, Meta SecAlign at 53.4%, belongs to the family broken at 96% adaptively ([arXiv 2510.09023](https://arxiv.org/html/2510.09023)). **No current design is both robust and useful on dynamic tasks** (report).

The research problem: allow the agent to re-plan as it learns about the task, while guaranteeing that no re-plan widens the authority granted at task start, and show it holds utility on AgentDyn.

## Why it matters

- Coding agents do open-ended work: they discover which files, packages and APIs they need as they go. A broker whose grants cannot follow re-planning either over-grants up front or blocks legitimate work, and blocked developers disable security ([[L4 Product Metrics]]).
- Only 6 of 97 AgentDojo tasks need dynamic planning (research note 02 Q3), so AgentDojo numbers overstate deployability.

## State of the art

- **CaMeL**: control flow from the trusted query; attacks against GPT-4o fell to 0 on AgentDojo; zero utility on AgentDyn's open-ended tasks ([CaMeL](https://arxiv.org/abs/2503.18813); [AgentDyn](https://arxiv.org/html/2602.03117v1)). See [[CaMeL]].
- **Progent**: an LLM proposes policy updates during execution; an SMT solver classifies each as narrowing (applied automatically) or widening (needs approval); only 6% of AgentDojo updates needed approval ([arXiv](https://arxiv.org/html/2504.11703v3)). This is "monotonic confinement". See [[Progent]].
- **DRIFT**: a secure planner emits a minimal trajectory with parameter constraints; an LLM validator judges deviations by read/write/execute privilege ([arXiv](https://arxiv.org/html/2506.12104v2)); utility loss on AgentDyn. See [[DRIFT]].
- **Design patterns**: Plan-Then-Execute and Action-Selector resist control-flow hijack but allow manipulation of data parameters; "unlikely that general-purpose agents can provide meaningful and reliable safety guarantees" ([arXiv](https://arxiv.org/html/2506.08837)). See [[Design Patterns for Securing LLM Agents]].
- **ACE**: abstract plan from trusted input, concrete plan, static IFC analysis before execution ([arXiv](https://arxiv.org/abs/2504.20984)). See [[ACE and IsolateGPT]].

> [!warning] Conflict
> CaMeL utility figures are model- and benchmark-specific: 77% vs 84% undefended on AgentDojo (authors), 37.71% benign utility in DRIFT's GPT-4o-mini comparison, zero on AgentDyn open-ended tasks.

## Research approach (Proposal)

1. **Grant ceiling at task start.** Compute the task's grant from trusted inputs only (the user's request, repo, org policy), as the broker already does at `session.start`.
2. **Re-plans as policy diffs.** When the agent needs a capability outside the current grant (surfaced as a deny, or as an MCP `insufficient_scope` challenge), the broker proposes a policy delta. Accept it automatically only if [[SymCC CI Gates]] prove `check_implies(P_task ∪ delta, P_ceiling)`, i.e. the re-plan stays within the task-start ceiling; otherwise ask the human with an authority diff ([[Fatigue-Resistant Approval Interfaces]]).
3. **Typed summaries for the planner.** Following FIDES's constrained decoding and research note 02's proposal, let the planner see only typed, label-bounded summaries of untrusted data when it re-plans, so an injection cannot directly write the next step.
4. **Provenance gating.** Any delta whose triggering observation is untrusted (per [[Provenance-Aware Cedar]]) is never auto-approved.
5. **Evaluate on AgentDyn** with the L2 shim: utility (target ≥80% of undefended, per [[L2 Injection Benchmarks]]), ASR@k, the fraction of re-plans auto-approved versus escalated, and the human-approval rate compared with Progent's 6%.

## How it would change the product

- The broker could run open-ended coding tasks under a tight initial grant, widening only inside a proved ceiling, instead of requiring learned policies to anticipate everything.
- It would give the first published system-level result that is both robust and useful on AgentDyn, the product's most credible evidence claim ([[Evaluation Harness]]).

## Hooks in the MVP

- `grant.request {session_id, action, resource, rationale}` on the control API is the step-up hook ([[Broker CLI and Daemon]]).
- SymCC narrowing checks already run in CI for learned policies; the same check can run online for re-plans.

## How it connects

- motivated-by:: [[AgentDyn]]
- contrasts-with:: [[CaMeL]]
- contrasts-with:: [[DRIFT]]
- depends-on:: [[Progent]]
- depends-on:: [[SymCC CI Gates]]
- motivated-by:: [[Design Patterns for Securing LLM Agents]]
- motivated-by:: [[ACE and IsolateGPT]]
- evaluated-by:: [[L2 Injection Benchmarks]]

## Implications for the build

- Make `grant.request` produce a machine-checkable policy delta, not free text, from M2 onward.
- Keep the task-start ceiling as a first-class object in the session, separate from the current grant.

## Open questions

- Whether online SymCC checks are fast enough to run per re-plan (no scalability data in the record).
- How to stop an injection from steering which legitimate capability is requested (see [[Branch-Steering Resistance]]).

## Sources

- Report: problem 3; "No current design is both robust and useful on dynamic tasks"; audit table.
- Research note 02 Q3 (AgentDyn), Q6 problem 3 (typed, label-bounded summaries; narrowing check) and synthesis takeaway.
