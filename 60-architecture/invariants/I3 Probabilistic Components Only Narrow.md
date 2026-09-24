---
title: "I3 Probabilistic Components Only Narrow"
aliases: ["Only Narrow"]
type: concept
section: architecture
tags: [sandbox/architecture, concept, invariant/i3, topic/policy, topic/learning, topic/approval, milestone/m2]
status: proposal
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Probabilistic components (LLM policy drafts, explainers, detectors) may only narrow authority, never widen it; an LLM may explain a diff but never merge it."
related: ["[[The Attacker Moves Second]]", "[[Progent]]", "[[Policy Learning Loop]]", "[[SymCC CI Gates]]", "[[ADR-011 Verified Policy Learning Loop]]", "[[AgentSpec]]", "[[Conseca]]", "[[AWS AgentCore]]", "[[Policy Engine and Entity Builder]]", "[[Trifecta Session Labels]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[AgentSentinel]]", "[[Policy Miner Safeguards]]", "[[I4 Repo Policy Only Narrows]]"]
sources: ["https://arxiv.org/html/2510.09023", "https://arxiv.org/html/2504.11703", "https://arxiv.org/abs/2503.18666", "https://arxiv.org/html/2501.17070v3", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/", "https://arxiv.org/abs/2606.26479", "https://arxiv.org/html/2509.07764v1"]
milestone: M2
---

# I3 Probabilistic Components Only Narrow

> Probabilistic components (LLM policy drafts, explainers, detectors) may only narrow authority, never widen it; an LLM may explain a diff but never merge it.

## Statement

**Proposal.** Call a component *probabilistic* if its output depends on a model (LLM or ML classifier) or on attacker-influenceable text. Such a component may:

- **propose** a policy change, which is applied automatically only if the verified analyzer proves the new policy is implied by the old one (`check_implies(P_new, P_old)`) and by the org ceiling;
- **set** restrictive session labels (for example flip `untrusted_input` to true) or raise an alert;
- **explain** a diff, decision or approval request in prose that is displayed *alongside* the machine-generated authority diff, never instead of it.

It may never: merge or enable a widening, clear a label, choose credential scope, approve a step-up, or override a deny. Every widening path requires a SymCC-proved diff plus a human approval that renders the authority diff.

The report calls principle 1 ("Enforce outside the model, and allow probabilistic components only to narrow authority") "the invariant every component must preserve", and research note 02 calls "probabilistic may only narrow" "the single most important design invariant supported by the literature".

## Rationale

- **In-band defenses fall to adaptive attackers.** Adaptive attacks pushed 12 published defenses above 90% success in most cases, with PIGuard at 71%, MetaSecAlign from 2% to 96% and StruQ at 100%; human red-teamers succeeded in 100% of evaluated scenarios ([arXiv 2510.09023](https://arxiv.org/html/2510.09023)). See [[The Attacker Moves Second]].
- **Monotonic confinement works.** Progent lets an LLM draft policies but uses SMT to decide narrowing (automatic) versus widening (needs approval); only 6% of updates needed approval ([arXiv 2504.11703](https://arxiv.org/html/2504.11703)). See [[Progent]].
- **Generated rules miss hazards.** AgentSpec's LLM-written rules reached 95.56% precision but 70.96% recall ([arXiv 2503.18666](https://arxiv.org/abs/2503.18666)); see [[AgentSpec]]. A static ceiling must bound what generation produces.
- **Generate only from trusted context.** Conseca generates per-task policy from trusted context only, with rationale ([arXiv](https://arxiv.org/html/2501.17070v3)); see [[Conseca]]. AgentCore turns natural language into Cedar that analysis then verifies before use ([AWS](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)); see [[AWS AgentCore]].
- **Out-of-band holds, so far.** Progent cut mean attack success from 25.8% to 4.2% under a small adaptive study, which its authors call "one small-scale data point" ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)).
- **Detectors have false positives.** AgentSentinel's hybrid rule and LLM audit had a 10.8% FPR ([arXiv](https://arxiv.org/html/2509.07764v1)), so detectors belong in telemetry and narrowing, not in allow decisions ([[AgentSentinel]]).

## How it is enforced

**Proposal.**

1. **Types.** The `learn` crate and any LLM integration emit `PolicyProposal { diff, evidence, rationale }`. The only function that turns a proposal into an active bundle is `policy::apply_narrowing(old, proposal, ceiling)`, which runs `check_implies(P_new, P_old)` and `check_implies(P_new, P_ceiling)`; on failure it returns counterexamples and a `NeedsHumanApproval` value. There is no other constructor for an active policy set.
2. **Approval.** A widening becomes active only with an approval record signed by a human principal (org review UI in `ee/`, or a local user approval for user-scope policy) that references the diff hash. The approval screen shows the "expansion delta" counterexamples from [[SymCC CI Gates]]; LLM prose is secondary ([[Fatigue-Resistant Approval Interfaces]]).
3. **Labels.** The [[Policy Engine and Entity Builder]] exposes label setters as monotone: `SessionLabels::raise(untrusted_input)`; there is no `lower`. Only session end resets them ([[Trifecta Session Labels]]).
4. **Explainers.** `broker why` and diff explanations are rendered from the audit log and Cedar determining-policy IDs; any LLM summary is marked as such.
5. **CI.** [[Policy Learning Loop]] opens a PR; a bot account used by the learning plane has no merge permission on the policy repo.

## Minimal test

**Proposal.** `tests/policy/only_narrow`:

- feed `apply_narrowing` a synthetic LLM-drafted diff that adds `git.push` to `refs/heads/main`: expect `NeedsHumanApproval` with a counterexample request, and the active bundle unchanged;
- feed a strict narrowing (removes a host): expect automatic acceptance;
- assert at compile time (trybuild test) that `SessionLabels` has no method that clears a label;
- run the learning loop end to end with an injected "grant pastebin.com" suggestion: the PR is opened, the gate fails, and nothing ships.

## What would violate it

- Auto-merging learned policy because "tests passed".
- An LLM "safety judge" whose `allow` verdict can override a Cedar deny.
- Letting a model pick GitHub App permissions or an STS session policy directly.
- Summarising an approval request in prose without the authority diff.
- A detector that can *remove* the `untrusted_input` label after "sanitising" content.

## How it connects

- motivated-by:: [[The Attacker Moves Second]]
- motivated-by:: [[Progent]]
- motivated-by:: [[AgentSpec]]
- motivated-by:: [[Conseca]]
- depends-on:: [[SymCC CI Gates]]
- part-of:: [[Policy Learning Loop]]
- depends-on:: [[Policy Engine and Entity Builder]]
- evaluated-by:: [[SymCC CI Gates]]
- decided-by:: [[ADR-011 Verified Policy Learning Loop]]

## Implications for the build

- This invariant is structural: encode it in crate visibility (`pub(crate)` constructors) so reviewers cannot miss a bypass.
- [[I4 Repo Policy Only Narrows]] is the same mechanism applied to repository-supplied policy; share the implication gate code.
- Keep LLM integrations optional and out of the default build; the product must function with none.

## Open questions

- SymCC's unsupported features and scalability limits are not documented, and it is unclear whether the analysis CLI is Lean-verified end to end ([[Open Questions and Unverified Claims]]); the gate's soundness rests on that.
- Whether label raises from probabilistic detectors should be allowed in enforce mode or only in audit mode, given false-positive rates.

## Sources

- https://arxiv.org/html/2510.09023
- https://arxiv.org/html/2504.11703
- https://arxiv.org/abs/2503.18666
- https://arxiv.org/html/2501.17070v3
- https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/
- https://arxiv.org/abs/2606.26479
- https://arxiv.org/html/2509.07764v1
- Report: invariant I3, principle 1, learning-loop section ("An LLM may explain a diff but never merge it"); research note 02 Q4 and Q5.

## Build log

- 2026-09-24 (M2): the learner is deterministic and never applies anything; `broker suggest` runs the formal gates on every proposal and shows each widening as the requests it newly permits (the narrowing gate is soft: human approval), while the ceiling, confinement, never-errors and deny-live gates are hard ([[ADR-024 Formal Gates as Built]]). No LLM component exists yet. Tests: C3 assertions in `m2_learn::c1_learned_policy_passes_the_task_and_c2_seeded_injection_is_blocked`, `gates::tests::a_learned_widening_shows_counterexamples_and_a_narrowing_is_proved`.
