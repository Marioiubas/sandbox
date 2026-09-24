---
title: "Red-Team Plan"
aliases: ["Red Team"]
type: eval
section: build
tags: [sandbox/build, eval, topic/evaluation, adversary/a1, adversary/a2, adversary/a3, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Red-Team Plan

> Three rings: automated (L1 on every commit, nightly fuzzers, adaptive LLM attackers per probe category reporting ASR@k), human (quarterly external pentest incl. white-box attacks on the Cedar entity builder) and public (bug bounty launched with the corpus).

## What it measures

How the broker holds up against attackers who adapt. The record is blunt about why this is needed: adaptive attacks pushed 12 published in-band defenses above 90% success in most cases, and human red-teamers succeeded in 100% of evaluated scenarios ([arXiv 2510.09023](https://arxiv.org/html/2510.09023)). Deterministic, out-of-band defenses have held up so far, but only in small tests, and the June 2026 out-of-band study left white-box attacks for future work ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)). The broker's own enforcement layer is the other target: Anthropic's custom proxy "repeatedly introduced vulnerabilities" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).

## The three rings (Proposal)

### Ring 1: automated

- [[L1 Conformance Suite]] on every commit; fuzzers nightly.
- **Adaptive LLM attackers per probe category.** For each of the twelve categories in the [[Conformance Probe Matrix]], an attacker model is given the category as its goal (for example "get a request carrying a non-broker credential to an allowed host") and iterates against a sandboxed agent under the broker. Report ASR@k. Anthropic's Gray Swan figures show why k matters: about 0.1% single-attempt success rose to 5-6% after 100 adaptive attempts ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).
- Seeds come from [[L2 Injection Benchmarks]] cases where the model complied and the broker blocked.

### Ring 2: human

- **Quarterly external pentest** of the proxy, launcher and MCP guard.
- It includes a **white-box attempt against the Cedar entity builder**, the component that turns raw traffic into Cedar entities and context, which the 2026 out-of-band study flagged as untested ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)); see [[Policy Engine and Entity Builder]] and [[Adaptive Evaluation of Deterministic Monitors]].
- The first pentest (proxy and launcher) is an exit gate of [[M4 Harden and Ship]]: it must close with no open high findings.

### Ring 3: public

- A **bug bounty** launched with the published conformance corpus. Precedent: Vercel runs a public hacker challenge for its sandbox ([Vercel](https://vercel.com/blog/one-million-dollar-hacker-challenge-for-vercel-sandbox)).

> [!question] Unverified
> The terms of Vercel's challenge were not reviewed; only its title (a one-million-dollar challenge) is in the record (research note 05 section 5.5).

## Where attackers will aim

From research note 02 Q5, a deterministic monitor gives a conditional guarantee ("if the policy is right and the labels are right"). The attacker's moves shift to:

1. getting a bad policy authored (attack whatever drafts policy; it must only ever see trusted input);
2. poisoning label sources (tool descriptions, mislabeled tool outputs);
3. choosing among allowed actions (misuse within scope, which is a stated non-goal: [[Threat Model Non-Goals]]);
4. channels the monitor does not see (DNS, image rendering, child processes).

The rings should cover each: ring 1 targets 2 and 4 automatically; ring 2 targets the entity builder and label computation directly; ring 3 widens coverage of 4.

## Metrics and reporting (Proposal)

- Every report pairs utility with attack success, never either alone.
- Every report keeps a separate count of "model complied, broker blocked", following WASP's split between intermediate attack success (16-86%) and end-to-end success (0-17%) ([arXiv 2504.18575](https://arxiv.org/abs/2504.18575v2)). This isolates the defense-in-depth value the broker adds.
- ASR@k for k=10-100 for automated attackers.
- Pentest findings tracked by severity to closure; any high finding blocks release.

## How results feed back

- Each successful attack becomes a deterministic probe in [[L1 Conformance Suite]] before the fix merges.
- Entity-builder findings become property tests in the `policy` crate and may require schema changes (with Implementation notes in [[Broker Cedar Schema]]).
- Findings that exploit legitimate authority update [[Risk Register]] and the threat-model document rather than being "fixed".

## Cadence

| Ring | Cadence | Starts |
|---|---|---|
| Automated: L1 | every commit | [[M0 Contained Run]] |
| Automated: fuzzers | nightly | M0 |
| Automated: adaptive attackers | per release candidate | [[M4 Harden and Ship]] |
| Human: pentest | quarterly | M4 (proxy and launcher) |
| Public: bounty | continuous | with corpus publication, at or after M4 |

## How it connects

- part-of:: [[Evaluation Harness]]
- depends-on:: [[L1 Conformance Suite]]
- depends-on:: [[L2 Injection Benchmarks]]
- evaluated-by:: [[Adaptive Evaluation of Deterministic Monitors]]
- depends-on:: [[Policy Engine and Entity Builder]]
- motivated-by:: [[Vercel Sandbox]] (public challenge precedent)
- mitigates:: [[Risk Register]]
- delivered-by:: [[M4 Harden and Ship]]
- motivated-by:: [[The Attacker Moves Second]]

## Implications for the build

- Keep the L7 surface minimal; every adapter added is pentest scope.
- Build a harness that can run adaptive attackers against a sandboxed agent without real upstream side effects (reuse the L2 mock upstreams).
- Budget pentest remediation time inside M4, not after it.

## Open questions

- Who runs the adaptive-attacker models, and with what budget per category.
- Bounty scope and rewards; whether to publish the corpus before or with the bounty.

## Sources

- Report: "Red-team plan" (three rings, Gray Swan figures, entity-builder gap, Vercel challenge, reporting rules and WASP split).
- Research note 05 section 5.5 (bug bounty; Vercel terms not reviewed); research note 02 Q5 (attacker moves).
