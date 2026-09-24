---
title: "Information Flow Control"
aliases: ["IFC", "Taint Tracking", "Typed Quarantine", "FlowSeal", "SkillGuard", "RTBAS", "AgentArmor"]
type: concept
section: research
tags: [sandbox/research, concept, topic/ifc, topic/policy, evidence/conflict, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Confidentiality-by-integrity label lattices applied to agents, label creep, why labels must come from systems of record (FlowSeal) rather than models (RTBAS, AgentArmor), SkillGuard's taint-narrows-grants, and typed quarantine (type-directed separation, OpenClaw privilege separation)."
related: ["[[FIDES]]", "[[CaMeL]]", "[[Trifecta Session Labels]]", "[[Credential Broker as Label Authority]]", "[[Provenance-Aware Cedar]]", "[[Lethal Trifecta]]", "[[ACE and IsolateGPT]]", "[[Cedar]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[Object Capabilities]]", "[[Agents Rule of Two]]", "[[Open Questions and Unverified Claims]]", "[[AgentDyn]]"]
sources: ["https://arxiv.org/html/2505.23643", "https://arxiv.org/html/2503.18813", "https://arxiv.org/abs/2606.26479", "https://arxiv.org/abs/2502.08966", "https://www.pdl.cmu.edu/PDL-FTP/BigLearning/RTBAS.pdf", "https://arxiv.org/abs/2508.01249", "https://arxiv.org/abs/2608.30041", "https://arxiv.org/html/2609.14003", "https://arxiv.org/abs/2509.25926", "https://arxiv.org/abs/2603.13424", "https://arxiv.org/abs/2503.15547", "https://arxiv.org/abs/2409.19091", "https://arxiv.org/abs/2601.08012"]
---

# Information Flow Control

Information flow control (IFC) attaches labels to data (who may read it, and how trustworthy its source is) and checks, at each sink, that the labels allow the flow. Applied to agents, it is the only mechanism in the literature that addresses *which data* reaches a tool call, rather than *which tool* is called. Its two failure modes are label creep and labels produced by a model the attacker can steer, so the record's strongest lesson is that labels must come from systems of record, which in this design means the broker.

## Label models used by agent systems

**FIDES** uses a product lattice: confidentiality (binary Low/High, or the powerset of authorised readers) times integrity (binary Trusted/Untrusted, or the powerset of writers). Labels join as data mixes ([arXiv 2505.23643](https://arxiv.org/html/2505.23643)). See [[FIDES]].

**CaMeL** tags every interpreter value with *readers* (who may see it) and *provenance* (user literal, tool X, CaMeL transformation) and checks Python policies at each tool call ([arXiv 2503.18813](https://arxiv.org/html/2503.18813)). See [[CaMeL]].

A June 2026 adaptive-evaluation paper frames CaMeL, FIDES, Progent and RTBAS as classic Biba integrity protection, reference monitoring and least privilege ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)). In Biba terms, the invariant is "no low-integrity value may influence a high-integrity sink": untrusted text must not choose the recipient of a `send_email` or the target of a `git.push`.

Minimal pseudo-structure of the check at a sink:

```text
label(v)        = (readers: Set<Principal>, integrity: Trusted | Untrusted)
label(f(a, b))  = join(label(a), label(b))        # readers ∩, integrity = min
allow(sink, args) iff  ∀ a ∈ args: sink.audience ⊆ label(a).readers
                   and (sink.consequential ⇒ ∀ a: label(a).integrity = Trusted)
```

(Illustrative; the FIDES and CaMeL papers define their own policy forms.)

## Label creep

When labels join on every mix, anything that touches untrusted data becomes untrusted, and a long agent session ends up with everything labelled High/Untrusted. FIDES lists "over-conservative label propagation through LLM calls" as a limitation ([arXiv 2505.23643](https://arxiv.org/html/2505.23643)). Its mitigation, **selective hiding**, keeps high-label results in variables instead of the context and lets a quarantined LLM inspect them only through schema-constrained answers. The research calls this "the most practical anti-label-creep mechanism in the literature".

This design's mitigation is structural: labels are session-level and coarse, so the answer to creep is **small tasks**, a fresh session per task rather than one long-lived taint ([[ADR-010 Session-Level Trifecta Labels in the MVP]]).

## Who produces the labels

| System | How labels or dependencies are computed | Evidence | Probabilistic part |
|---|---|---|---|
| RTBAS (Feb 2025) | Tool-level IFC; LM-as-judge and attention-saliency screeners decide which labels propagate; asks the user only when integrity or confidentiality cannot be ensured | Prevents all targeted AgentDojo attacks with 2% utility loss under attack ([arXiv 2502.08966](https://arxiv.org/abs/2502.08966); [CMU PDF](https://www.pdl.cmu.edu/PDL-FTP/BigLearning/RTBAS.pdf)) | Dependency screening |
| AgentArmor (Aug 2025) | Runtime traces to CFG/DFG/PDG, a property registry of tool and data metadata, a type system for policy checking | AgentDojo ASR 3%, utility drop 1% ([arXiv 2508.01249](https://arxiv.org/abs/2508.01249)) | Graph built from the LLM trace |
| SkillGuard (30 Aug 2026) | Once untrusted data enters state, restricts future capabilities via a Skill Impact Graph, "steerability signatures" and an inline reference monitor; no extra model inference | Attacks eliminated on 3 of 4 AgentDojo suites, 4.8–14.3% ASR on Slack, vs Spotlighting, CaMeL, AttriGuard ([arXiv 2608.30041](https://arxiv.org/abs/2608.30041)) | None |
| FlowSeal (2026) | Provenance labels from underlying systems, not model inference; mandatory interceptor outside the LLM; lattice with controlled declassification | Leakage 0–3.3% on SPR, PrivacyLens and ConVerse at 72.4% benign utility; three new attacks reach 43.8–75.6% leakage against a prior defense ([arXiv 2609.14003](https://arxiv.org/html/2609.14003)) | LLM declassification oracle |

RTBAS's full author list, and AgentSpec, MiniScope and AgentArmor code, are unverified in the record. AgentArmor's numbers are AgentDojo-only and self-reported.

FlowSeal states the principle this design adopts: when enforcement depends on the model recognising privacy-relevant interactions inside adversary-controlled conversation, "the attack surface and defense mechanism coincide" ([arXiv 2609.14003](https://arxiv.org/html/2609.14003)). **Labels come from systems, not the model.**

> [!warning] Conflict
> FlowSeal's fetched page showed a date of 12 Sep 2024, which conflicts with arXiv ID 2609 (Sep 2026). Treat it as Sep 2026, unverified ([[Open Questions and Unverified Claims]]).

## Typed quarantine

The cheapest deterministic IFC is to stop untrusted text reaching the planner at all.

- **Type-directed privilege separation** (Jacob, Alghamdi, Hu, Alomair, Wagner; arXiv 2509.25926, Sep 2025, rev. May 2026) converts untrusted data into a curated set of narrow types (not raw strings) before it reaches the privileged agent; case studies only ([arXiv 2509.25926](https://arxiv.org/abs/2509.25926)).
- **Agent privilege separation in OpenClaw** (Cheng, Tsao; arXiv 2603.13424): a two-agent pipeline with tool partitioning and JSON formatting. On 649 LLMail-Inject attacks that beat a single-agent baseline, the full pipeline had 0% ASR, isolation alone 0.31%, JSON formatting alone 14.18% ([arXiv 2603.13424](https://arxiv.org/abs/2603.13424)). Isolation is doing most of the work.
- Related work: Prompt Flow Integrity (arXiv 2503.15547, no numbers extracted) ([arXiv](https://arxiv.org/abs/2503.15547)); f-secure LLM system (arXiv 2409.19091, 2024, case studies only) ([arXiv](https://arxiv.org/abs/2409.19091)); "Towards Verifiably Safe Tool Use" (arXiv 2601.08012, 4-page vision paper) ([arXiv](https://arxiv.org/abs/2601.08012)).

## Where Cedar stops

Information-flow properties such as "data derived from file F never leaves" are not expressible in stateless request authorization. Cedar can only check the labels the broker gives it (research note 04a, Q5, limit 4). IFC in this product is therefore a split: the broker *computes* labels from what it observes; [[Cedar]] *checks* them as context attributes.

## Adopt / Improve / Add

- **Adopt:** FlowSeal's principle (labels from systems of record) and SkillGuard's "taint narrows the grant set", which is the session-level form this design uses in [[Trifecta Session Labels]].
- **Improve:** **Proposal:** replace model-computed dependencies (RTBAS, AgentArmor) with broker-observed facts: repo visibility from the forge API, tenant and scope from the credential that fetched the data. This is [[Credential Broker as Label Authority]].
- **Add:** **Proposal:** a "typed quarantine" SDK: tool outputs declare a schema; free-text fields are auto-labelled untrusted and hidden (FIDES-style) from the planner. Later, per-argument labels in Cedar context ([[Provenance-Aware Cedar]]), and ACE-style static analysis of plans in phase 3 ([[ACE and IsolateGPT]]).

## How it connects

- contrasts-with:: [[Object Capabilities]]
- depends-on:: [[Cedar]]
- decided-by:: [[ADR-010 Session-Level Trifecta Labels in the MVP]]

[[FIDES]] and [[CaMeL]] are the two fine-grained instances audited in this section. The [[Lethal Trifecta]] and [[Agents Rule of Two]] are coarse, session-level IFC. The MVP's implementation is [[Trifecta Session Labels]]; the research extensions are [[Provenance-Aware Cedar]] and [[Credential Broker as Label Authority]]. [[ACE and IsolateGPT]] applies IFC statically to plans. On [[AgentDyn]], the fine-grained IFC systems lose most of their utility, which is why the MVP stays coarse.

## Implications for the build

- MVP labels are exactly three booleans per session (`untrusted_input`, `sensitive_read`, `external_effect`), computed only by the broker from traffic it mediates; no model output may set or clear them (I3).
- Label sources must be deterministic and listed: which hosts and API responses flip `untrusted_input` or `sensitive_read` is configuration, reviewed like policy.
- Encourage one session per task in CLI ergonomics to keep label creep bounded.

## Open questions

- FlowSeal's publication date.
- No independent replication of FIDES; no head-to-head comparison of the IFC systems beyond AgentDyn, which omits FIDES and ACE.
- Can per-argument labels be carried into Cedar context while keeping SymCC analysis tractable? That is the [[Provenance-Aware Cedar]] problem.

## Sources

- [arXiv 2505.23643](https://arxiv.org/html/2505.23643) (FIDES); [arXiv 2503.18813](https://arxiv.org/html/2503.18813) (CaMeL); [arXiv 2606.26479](https://arxiv.org/abs/2606.26479)
- [arXiv 2502.08966](https://arxiv.org/abs/2502.08966), [CMU PDF](https://www.pdl.cmu.edu/PDL-FTP/BigLearning/RTBAS.pdf) (RTBAS); [arXiv 2508.01249](https://arxiv.org/abs/2508.01249) (AgentArmor)
- [arXiv 2608.30041](https://arxiv.org/abs/2608.30041) (SkillGuard); [arXiv 2609.14003](https://arxiv.org/html/2609.14003) (FlowSeal)
- [arXiv 2509.25926](https://arxiv.org/abs/2509.25926); [arXiv 2603.13424](https://arxiv.org/abs/2603.13424); [arXiv 2503.15547](https://arxiv.org/abs/2503.15547); [arXiv 2409.19091](https://arxiv.org/abs/2409.19091); [arXiv 2601.08012](https://arxiv.org/abs/2601.08012)
