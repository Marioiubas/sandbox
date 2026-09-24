---
title: "MOC Research"
aliases: []
type: moc
section: research
tags: [sandbox/research, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "The literature audit: foundations, the adaptive-attack record, every audited defense with its Adopt/Improve/Add verdict, the benchmarks, and the ten design principles ranked by evidence."
related: ["[[Object Capabilities]]", "[[Macaroons and Biscuit]]", "[[Information Flow Control]]", "[[Lethal Trifecta]]", "[[Agents Rule of Two]]", "[[Design Patterns for Securing LLM Agents]]", "[[The Attacker Moves Second]]", "[[CaMeL]]", "[[FIDES]]", "[[Progent]]", "[[DRIFT]]", "[[ACE and IsolateGPT]]", "[[AgentSpec]]", "[[Conseca]]", "[[MiniScope]]", "[[AgentSentinel]]", "[[AgentDyn]]", "[[SandboxEscapeBench]]", "[[MOC Open Problems]]", "[[MOC Policy]]", "[[MOC Threat Model]]", "[[Evaluation Harness]]"]
sources: []
---

# MOC Research

> The literature audit: foundations, the adaptive-attack record, every audited defense with its Adopt/Improve/Add verdict, the benchmarks, and the ten design principles ranked by evidence.

The literature splits defenses into two classes. **In-band** defenses (prompting, fine-tuning, detectors) were all broken adaptively at 71-100%. **Out-of-band, deterministic** defenses have held so far, but only in small tests, and on the open-ended AgentDyn benchmark every one of them over-defends. No current design is both robust and useful on dynamic tasks: that is the frontier the product sits on.

Each paper note carries the report's **Adopt / Improve / Add** verdict. Watch the terminology trap: CaMeL's and FIDES's "capabilities" are information-flow labels, not object-capability references; the missing ocap layer is exactly the credential broker ([[Object Capabilities]]).

## Ten design principles, ranked by strength of evidence (Proposal)

The report derives these from the literature; principle 1 is the invariant every component must preserve ([[I3 Probabilistic Components Only Narrow]]).

1. Enforce outside the model; allow probabilistic components only to narrow authority. ([[The Attacker Moves Second]], [[Progent]])
2. Take control flow from trusted input only. ([[CaMeL]], [[Design Patterns for Securing LLM Agents]], [[ACE and IsolateGPT]])
3. Source labels from systems of record. ([[Information Flow Control]], [[Credential Broker as Label Authority]])
4. Keep credentials out of the context window; the model names capabilities and never holds them. ([[Object Capabilities]], [[I1 No Secrets in the Sandbox]])
5. Make tokens attenuable, short-lived and audience-bound; widenings need approval with an authority diff. ([[Macaroons and Biscuit]], [[Just-in-Time Credential Minting]], [[Fatigue-Resistant Approval Interfaces]])
6. Write policy in an analyzable language with verified semantics. ([[Cedar]], [[SymCC CI Gates]])
7. Treat egress, DNS included, as a capability enforced at the network layer. ([[Topology-Forced Egress]], [[Broker DNS Resolver]])
8. Pin tool manifests and revoke derived grants when a description changes. ([[MCP Guard]])
9. Keep a kernel backstop under tool-level mediation. ([[AgentSentinel]], [[Two-Tier Isolation Design]])
10. Evaluate on dynamic benchmarks against adaptive and human attackers. ([[AgentDyn]], [[Evaluation Harness]])

Three gaps no paper fills become the product's research contributions: [[Provenance-Aware Cedar]], [[Credential Broker as Label Authority]] and [[Revocable Sub-Agent Delegation]].

## Foundations

- [[Object Capabilities]] — Authority only through unforgeable, attenuable references (Miller: POLA, caretakers, membranes), the confused deputy (Hardy 1988, now a named MCP-proxy attack), and why CaMeL/FIDES 'capabilities' are IFC labels, leaving the credential broker as the missing ocap layer.
- [[Macaroons and Biscuit]] — Attenuable bearer tokens: Macaroons (chained HMAC caveats, third-party discharge) and Biscuit (public-key signed, offline attenuation, Datalog caveats); deferred to later phases for sub-agent delegation.
- [[Information Flow Control]] — Confidentiality-by-integrity label lattices applied to agents, label creep, why labels must come from systems of record (FlowSeal) rather than models (RTBAS, AgentArmor), SkillGuard's taint-narrows-grants, and typed quarantine (type-directed separation, OpenClaw privilege separation).
- [[Lethal Trifecta]] — Private data plus untrusted content plus external communication in one session equals exfiltration (Willison, Jun 2025); the shape behind most incidents.
- [[Agents Rule of Two]] — Meta's per-session rule: satisfy at most two of [A] untrusted input, [B] sensitive access, [C] state change or external communication; and Willison's critique that [A]+[C] without [B] is still dangerous.
- [[Design Patterns for Securing LLM Agents]] — The 2025 six-pattern paper (Action-Selector, Plan-Then-Execute, LLM Map-Reduce, Dual LLM, Code-Then-Execute, Context-Minimization) including Willison's 2023 Dual LLM pattern; adopt the patterns as named execution modes with default capability profiles.

## The adaptive-attack record

- [[The Attacker Moves Second]] — Adaptive attacks broke 12 in-band defenses (most above 90%) and humans won 100% of scenarios; the in-band versus out-of-band split, the small June 2026 out-of-band study, and the deterministic/probabilistic classification of every audited system.

## Capability and IFC systems for agents

Control flow from trusted input plus a reference monitor on tool calls.

- [[CaMeL]] — Google DeepMind/ETH design where a privileged LLM writes code from the trusted query, an interpreter tracks readers and provenance, and Python policies gate tool calls: 77% vs 84% AgentDojo utility, zero on AgentDyn open-ended tasks; plus CaMeLs for computer use and Branch Steering.
- [[FIDES]] — Microsoft's IFC planner with confidentiality-by-integrity labels, selective hiding and schema-constrained quarantined LLM answers: injections 21/152 -> 3/152 but completion 41-59%; the 'who annotates labels' gap the broker can close.
- [[ACE and IsolateGPT]] — ACE (NDSS 2026): abstract plan from trusted input, concrete plan, static IFC analysis of the plan, execution with barriers; IsolateGPT (NDSS 2025): hub-and-spoke per-app isolation, which ACE breaks; basis for per-MCP-server principals and phase-3 plan analysis.

## Privilege and policy systems

Who writes the policy (human, LLM or tool graph) and how widening is gated.

- [[Progent]] — Berkeley's privilege-control layer: JSON-Schema allow/forbid rules on tool arguments, LLM-drafted, with SMT deciding narrowing (automatic) versus widening (approval): AgentDojo ASR 39.9% -> 1.0%; the monotonic-confinement model this design re-hosts on Cedar.
- [[DRIFT]] — NeurIPS 2025 defense with a secure planner, an LLM dynamic validator using read/write/execute privilege classes and an injection isolator: AgentDojo 30.7% -> 1.3% at 58.48% utility, but large utility loss on AgentDyn.
- [[AgentSpec]] — ICSE 2026 trigger-predicate-action runtime rules: >90% unsafe code execution prevented, but LLM-written rules reach only 70.96% recall, the evidence that generated policy needs a coverage check and a static ceiling.
- [[Conseca]] — HotOS 2025 per-task policy generated from trusted context only with human-readable rationale and a deterministic enforcer: 12/20 tasks vs 14/20 unrestricted and 0/20 static-restrictive.
- [[MiniScope]] — Least-privilege framework that reconstructs permission hierarchies from tool-call relationships with mobile-style prompts and no LLM in the loop (1-6% latency); basis for tool-graph-derived incremental MCP grants.

## Kernel-level backstops

- [[AgentSentinel]] — CCS 2025 eBPF and LSM tracing with hybrid rule and LLM audit: 79.6% defense success at 10.8% FPR; adopt a kernel-level backstop for telemetry, never the primary decision point.

## Benchmarks used by this product

- [[AgentDyn]] — The Feb 2026 open-ended benchmark (60 tasks, 560 injection cases, 7.1 steps vs AgentDojo's 3.49) on which every system-level defense over-defends; with AgentDojo as the baseline harness both extend.
- [[SandboxEscapeBench]] — UK AISI's 18-scenario container-breakout benchmark (ICML 2026): frontier models reliably exploit misconfigurations, success scales log-linearly with compute; this vault's eval layer L6 (0 escapes at difficulty 1-3, run in nested VMs).

## How this section connects

- Principles 1, 4, 6 and 7 become invariants in [[MOC Architecture]]; principle 6 is realised in [[MOC Policy]].
- The benchmarks feed the [[Evaluation Harness]] layers L2 ([[L2 Injection Benchmarks]]) and L6 ([[SandboxEscapeBench]]).
- Every unsolved item becomes a note in [[MOC Open Problems]].
- Incidents that motivated each defense are in [[MOC Threat Model]].
