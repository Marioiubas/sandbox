---
title: "MOC Open Problems"
aliases: []
type: moc
section: open
tags: [sandbox/open, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Eight research problems the product can own plus the measurement gaps; each is a publishable contribution that strengthens the product."
related: ["[[Provenance-Aware Cedar]]", "[[Credential Broker as Label Authority]]", "[[Dynamic Tasks Without Control-Flow Hijack]]", "[[Branch-Steering Resistance]]", "[[Trace-Mined Least Privilege]]", "[[Revocable Sub-Agent Delegation]]", "[[Adaptive Evaluation of Deterministic Monitors]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[Measurement Gaps]]", "[[MOC Research]]", "[[Open Questions and Unverified Claims]]", "[[Evaluation Harness]]"]
sources: []
---

# MOC Open Problems

> Eight research problems the product can own plus the measurement gaps; each is a publishable contribution that strengthens the product.

The report names eight research problems open in the record and three measurement gaps. Each is a publishable contribution that strengthens the product; none blocks the MVP. Claude Code should not try to solve these during M0-M4, but should leave hooks (context attributes, audit fields, trace formats) that make them tractable, and record any finding here.

Separate from these, [[Open Questions and Unverified Claims]] lists facts that must be verified before the build relies on them.

## Policy and information flow

- [[Provenance-Aware Cedar]] — Put per-argument integrity and reader labels into Cedar context and prove properties such as 'no untrusted-integrity value can reach git.push to a public repo'; no paper combines IFC with a formally verified policy engine.
- [[Credential Broker as Label Authority]] — Derive confidentiality labels from the OAuth scope, tenant or repo visibility that produced each datum, closing FIDES's annotation gap from a source the model cannot influence (FlowSeal's principle).

## Planning under attack

- [[Dynamic Tasks Without Control-Flow Hijack]] — Allow safe re-planning where every re-plan is checked as a narrowing of the original grant, and measure it on AgentDyn where all current capability systems collapse.
- [[Branch-Steering Resistance]] — Require every branch of an approved plan to satisfy policy independently and treat branch predicates computed from untrusted observations as low-integrity.

## Least privilege and delegation

- [[Trace-Mined Least Privilege]] — Record-then-restrict for agents with measured over- and under-privilege rates, including the unstudied risk of learning from compromised runs.
- [[Revocable Sub-Agent Delegation]] — Membrane-style revocable delegation to sub-agents and map-reduce workers; no agent paper evaluates revocation or sub-agent attenuation.

## Evaluation and humans

- [[Adaptive Evaluation of Deterministic Monitors]] — White-box and optimization-based attacks on the entity builder and label sources, the gap the June 2026 out-of-band study explicitly leaves open.
- [[Fatigue-Resistant Approval Interfaces]] — Approval prompts that show authority diffs and provenance rather than prose, with measured error rates; users approve 93% of prompts and OWASP lists Overwhelming HITL as T10, yet no user study exists.
- [[Measurement Gaps]] — Three measurement gaps: the first public benchmark scoring egress and credential containment with real traffic, proxy latency and false-deny baselines for agent workloads, and the base rate at which real MCP servers change tool descriptions.

## How this section connects

- The literature behind each problem is in [[MOC Research]]; the MVP's deliberately shallow versions (session-level labels, SymCC narrowing, the miner) are in [[MOC Policy]].
- Measurement gaps are addressed first by the [[Evaluation Harness]]: publishing the conformance corpus and paired utility-and-containment numbers is part of the product.
