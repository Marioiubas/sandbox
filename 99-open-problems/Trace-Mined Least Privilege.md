---
title: "Trace-Mined Least Privilege"
aliases: []
type: problem
section: open
tags: [sandbox/open, problem, topic/learning, topic/policy, topic/evaluation, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Trace-Mined Least Privilege

> Record-then-restrict for agents with measured over- and under-privilege rates, including the unstudied risk of learning from compromised runs.

## The problem

Record-then-restrict is mature for syscall and MAC profiles, but nobody has done it for agents with measured results. The MVP's [[Policy Learning Loop]] (record, generalise, emit a Cedar diff, run SymCC gates, human PR, shadow, enforce) is an engineering answer; the research problem is to **measure** it: how much authority does a learned policy grant that the task never needed (over-privilege), how often does it deny what the task did need (under-privilege), and what happens when the runs it learned from were themselves compromised?

## Why it matters

- Least privilege is what shrinks a hijacked agent's authority, and hand-written policies do not scale across repos and agents.
- Learning from a poisoned run bakes the attacker's behaviour into policy. The Cowork incident shows that a learned rule allowing `api.anthropic.com` would not have stopped the attacker-key exfiltration ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).
- No product in the record ships an agent egress "record → enforce" miner (report), and no study of learning from compromised runs exists (research note 03 Q6).

## State of the art

- **Syscall/MAC profiles**: Security Profiles Operator v1.0 (June 2026) records profiles through log or eBPF recorders and merges them across replicas; the article does not discuss the risk of recording compromised workloads ([CNCF](https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/)). IAM Access Analyzer generates policies from CloudTrail activity ([AWS](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/)).
- **Agent policy synthesis** is mostly LLM-generated: AgentSpec's LLM-written rules reached 95.56% precision but 70.96% recall ([arXiv](https://arxiv.org/abs/2503.18666)); see [[AgentSpec]]. Progent and Conseca generate policies from the trusted task.
- **MiniScope** reconstructs permission hierarchies from tool-call relationships with no LLM in the loop and 1-6% latency overhead, on a synthetic dataset ([arXiv](https://arxiv.org/abs/2512.11147)); it is static tool-graph inference, not trace mining. See [[MiniScope]].
- **Enforce/audit modes** exist in OpenShell ([OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)); AgentCore verifies natural-language-generated Cedar with analysis.

> [!question] Unverified
> AppArmor `aa-logprof`, Tetragon and IAM Access Analyzer details are background knowledge in the record; "no vendor ships an agent egress record-to-enforce miner" should be re-checked before it is claimed publicly.

## Research approach (Proposal)

1. **Dataset.** Record audit-mode traces from the M2 3 repos × 3 agents runs, design-partner sessions (opt-in) and L3 benchmark runs, with task labels.
2. **Ground truth.** For a held-out set, label each request as necessary or not (human or LLM labels on a sample, as in the FDR definition of [[L4 Product Metrics]]).
3. **Metrics.** Over-privilege: requests (or request classes) permitted by the learned policy but never necessary in held-out tasks, weighted by risk class. Under-privilege: necessary held-out requests denied. Time-to-policy: sessions until coverage ≥95%. Breadth: rules broader than a registrable domain.
4. **Generaliser study.** Sweep the miner's parameters (minimum support, k distinct subdomains before collapsing to a suffix, operation-level vs path-prefix entries) and plot over- vs under-privilege.
5. **Poisoning study.** Inject compromised runs (the seeded injections from M2, Cowork-style foreign-key calls) into training traces at varying rates; measure how much malicious authority survives each safeguard in [[Policy Miner Safeguards]]: trusted-input-only learning, intersection of N runs, foreign-credential exclusion, org deny ceiling, rate limits.
6. **Proof gate effect.** Report how many learned diffs pass the narrowing and ceiling gates automatically versus need review ([[SymCC CI Gates]]), compared with Progent's 6% approval rate.

## How it would change the product

- Evidence-based defaults for the miner, and a published over/under-privilege curve instead of an unmeasured claim.
- A quantified answer to "can we learn safely from runs that may be compromised", which buyers will ask.
- Possibly a stronger default: learn only from the intersection of N runs, if the poisoning study shows single-run learning is unsafe.

## Hooks in the MVP

- Audit mode records the would-be decision, process ancestry and templated paths ([[Policy Learning Loop]]).
- Requests that carried a foreign credential or tripped the sentinel check are flagged in audit and excluded from learning ([[ADR-011 Verified Policy Learning Loop]]).

## How it connects

- depends-on:: [[Policy Learning Loop]]
- depends-on:: [[Policy Miner Safeguards]]
- contrasts-with:: [[MiniScope]]
- contrasts-with:: [[AgentSpec]]
- evaluated-by:: [[L4 Product Metrics]]
- decided-by:: [[ADR-011 Verified Policy Learning Loop]]
- depends-on:: [[SymCC CI Gates]]

## Implications for the build

- Store traces in a form that supports offline re-mining with different parameters (templated tuples plus task labels), not only the final diff.
- Keep the miner deterministic so the poisoning study is reproducible.

## Open questions

- What "necessary" means for exploratory coding work, where an agent may legitimately read docs it ends up not using.
- Whether the intersection-of-N rule hurts time-to-policy enough to miss the ≥95%-in-3-sessions target.

## Sources

- Report: problem 5; least-privilege learning section and mitigations.
- Research note 02 Q4 (trace-mining inference) and Q6 problem 5.
- Research note 03 Q6 (SPO, AgentCore, poisoning mitigations) and gaps.
