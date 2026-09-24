---
title: "Adaptive Evaluation of Deterministic Monitors"
aliases: []
type: problem
section: open
tags: [sandbox/open, problem, topic/evaluation, topic/policy, adversary/a1, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Adaptive Evaluation of Deterministic Monitors

> White-box and optimization-based attacks on the entity builder and label sources, the gap the June 2026 out-of-band study explicitly leaves open.

## The problem

The record sorts prompt-injection defenses into two classes. In-band defenses (prompting, fine-tuning, detectors) were broken adaptively at 71-100%: Spotlighting above 95%, StruQ at 100%, MetaSecAlign from 2% to 96%, MELON at 76-95%, PIGuard at 71% ([arXiv 2510.09023](https://arxiv.org/html/2510.09023)). Out-of-band, deterministic defenses have held up, but only in small tests: a June 2026 adaptive study found Progent cut mean attack success from 25.8% to 4.2%, and a hand-crafted black-box adaptive attack reached only 2.6%; the authors call this "one small-scale data point" and left white-box GCG attacks for future work ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)). No white-box or optimization-based adaptive attack against CaMeL, FIDES or any deterministic monitor exists in the record.

The research problem: attack the product's own deterministic monitor with white-box, optimization-based and human adaptive attacks, aimed at the places where the guarantee is conditional: the **entity builder** that turns raw traffic into Cedar entities and context, and the **label sources** that feed trifecta and provenance context.

## Why it matters

- A deterministic monitor gives a conditional guarantee: "if the policy is right and the labels are right, no untrusted data reaches a consequential sink". The attacker's moves then shift to getting a bad policy authored, poisoning label sources, choosing among allowed actions, and using channels the monitor does not see (research note 02 Q5).
- Cedar's proofs cover policy semantics, not the enforcement point; how raw traffic is parsed into entities must be tested empirically (report).
- Without this evaluation, the product's containment numbers are only as credible as the attacker that produced them; the [[Evaluation Harness]] exists to publish credible numbers.

## State of the art

- [[The Attacker Moves Second]]: four attack families (gradient descent, RL, random search, human-guided); >90% ASR against most of 12 defenses; human red-teaming 100%; CaMeL and system-level defenses were not evaluated.
- The June 2026 out-of-band study evaluated CaMeL, FIDES, Progent, RTBAS and FORGE, black-box only ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)).
- [[Progent]]'s own adaptive attacks (if-then-else injection, "allow attack tool" request, AgentVigil) produced only marginal ASR increases ([arXiv](https://arxiv.org/html/2504.11703v3)).
- Gray Swan figures show adaptivity matters even for strong models: about 0.1% single-attempt success rose to 5-6% after 100 attempts ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).
- [[Branch-Steering Resistance]] shows one concrete attack on a deterministic design: steering a pre-approved branch.

## Research approach (Proposal)

1. **Threat surfaces to attack.**
   - Entity builder: canonical host, SNI, resolved address, redirects, adapter classification (for example a GitHub request shape the adapter maps to a lower-risk verb), pkt-line parsing.
   - Label sources: trifecta flips (`untrusted_input`, `sensitive_read`), per-argument provenance matching, MCP manifest hashing.
   - Policy authoring: any LLM that drafts or explains policy must never see untrusted input ([[I3 Probabilistic Components Only Narrow]]).
   - Unseen channels: covert channels on allowed hosts (category 11 of [[Conformance Probe Matrix]]).
2. **White-box access.** Give attackers the source, schema, policies and audit output; the product is Apache-2.0, so this is the realistic threat model.
3. **Optimization-based attacks.** Use GCG-style or RL-driven search to produce injections that maximise a reward defined on the broker's decisions (for example "a request reaches the mock upstream with a private-data fingerprint"), not on model output.
4. **Differential and grammar fuzzing** of the entity builder against the upstream's interpretation (HTTP Garden-style) as the non-LLM half ([[L1 Conformance Suite]]).
5. **Human ring.** The quarterly pentest includes a white-box attempt on the entity builder ([[Red-Team Plan]]).
6. **Report** ASR@k per surface, paired with utility, with "model complied, broker blocked" counted separately; publish attack code where safe.

## How it would change the product

- It would turn "held up in small tests" into a measured robustness claim, or find the bugs first.
- Findings feed the conformance corpus and may force schema or adapter changes; each is recorded as an ADR if it changes the design.

## Hooks in the MVP

- Mock upstreams and the L2 shim ([[L2 Injection Benchmarks]]) give a reward signal without real side effects.
- The audit stream records the entity-builder output and determining policy IDs for every decision ([[Policy Engine and Entity Builder]]).

## How it connects

- motivated-by:: [[The Attacker Moves Second]]
- evaluated-by:: [[Red-Team Plan]]
- depends-on:: [[Policy Engine and Entity Builder]]
- depends-on:: [[L2 Injection Benchmarks]]
- motivated-by:: [[Progent]]
- depends-on:: [[Branch-Steering Resistance]]
- depends-on:: [[L1 Conformance Suite]]

## Implications for the build

- Keep the entity builder small, pure and separately testable; it is the most valuable target.
- Expose a test-only interface that returns the Cedar request built for a raw input, so fuzzers and attackers can target it without a live session.

## Open questions

- What reward functions give optimization-based attackers useful gradients against a binary allow/deny monitor.
- How to evaluate label-source attacks on L4-spliced traffic that the broker does not decrypt.

## Sources

- Report: problem 7; red-team human ring; two-classes finding.
- Research note 02 Q3 (2606.26479 leaves white-box GCG for future work; no white-box attack on CaMeL or FIDES), Q5 inference (attacker's moves) and Q6 problem 7.
