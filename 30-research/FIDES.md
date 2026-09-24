---
title: "FIDES"
aliases: ["Microsoft FIDES"]
type: paper
section: research
tags: [sandbox/research, paper, topic/ifc, topic/policy, topic/audit, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Microsoft's IFC planner with confidentiality-by-integrity labels, selective hiding and schema-constrained quarantined LLM answers: injections 21/152 -> 3/152 but completion 41-59%; the 'who annotates labels' gap the broker can close."
related: ["[[Information Flow Control]]", "[[CaMeL]]", "[[Credential Broker as Label Authority]]", "[[Object Capabilities]]", "[[Trifecta Session Labels]]", "[[Provenance-Aware Cedar]]", "[[AgentDyn]]", "[[The Attacker Moves Second]]", "[[Audit Recorder and Event Schema]]", "[[Design Patterns for Securing LLM Agents]]", "[[Open Questions and Unverified Claims]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]"]
sources: ["https://arxiv.org/abs/2505.23643", "https://arxiv.org/html/2505.23643", "https://github.com/microsoft/fides", "https://arxiv.org/html/2601.09923v1", "https://arxiv.org/abs/2606.26479", "https://arxiv.org/html/2609.14003", "https://arxiv.org/html/2602.03117v1"]
---

# FIDES

FIDES is Microsoft Research's information-flow-controlled agent planner. Every value carries a confidentiality and an integrity label; deterministic checks stop untrusted data from driving consequential actions; and **selective hiding** keeps sensitive tool results out of the planner's context, exposing them only through a quarantined LLM whose answers are forced into small schemas. It cuts successful injections on AgentDojo from 21/152 to 3/152, but task completion falls to 41–59%. Its open question, "who annotates the labels?", is the one this broker is positioned to answer.

## Citation

- Costa, Köpf, Kolluri, Paverd, Russinovich, Salem, Tople, Wutschitz, Zanella-Béguelin (Microsoft Research). "Securing AI Agents with Information-Flow Control". arXiv 2505.23643, May 2025, revised Sep 2025 ([arXiv](https://arxiv.org/abs/2505.23643)).
- Code and tutorial: [microsoft/fides](https://github.com/microsoft/fides).
- Venue: preprint in the record.

## Mechanism

From the paper ([arXiv HTML](https://arxiv.org/html/2505.23643)):

**Labels.** A product lattice of confidentiality (binary Low/High, or the powerset of authorised readers) and integrity (binary Trusted/Untrusted, or the powerset of writers). Labels join as data mixes. The planner performs dynamic taint tracking over these labels.

**Deterministic policies** checked before tool calls:

- Consequential tool calls only when the action's integrity label is Trusted (the action was not chosen under the influence of untrusted data).
- Confidentiality: data flows only to authorised readers.
- An explicit-secrecy policy; the authors acknowledge that indirect flows through *tool choice* remain observable.

**Selective hiding.** When a tool result is more restrictive than the current context (higher confidentiality or lower integrity), it is stored in a variable instead of being appended to the context. The planner refers to it by name.

**Quarantined inspection with constrained decoding.** A quarantined LLM may inspect hidden variables only through constrained decoding into schema-restricted outputs (bool, enum, bounded string), which bounds how much information, and how much injected instruction, can leak back into the planner.

```text
tool_result r, label(r) = (High, Untrusted)
  if label(r) ⋢ label(context):  vars["$r7"] = r        # hidden; planner sees only "$r7"
planner: "is $r7 an invoice from a known vendor?"
  Q-LLM(r, schema = bool)  → true                       # ≤ 1 bit returns, labelled with r's label
planner acts on `true`; policy check sees label(true) ⊒ label(r)
```

(Illustrative of the mechanism above, not FIDES's API.)

## Threat model and assumptions

Summarised from the mechanism and stated limitations ([arXiv HTML](https://arxiv.org/html/2505.23643)); the paper's own threat-model wording was not extracted in the record.

- **Attacker:** controls some data sources the agent reads (tool outputs, documents, messages) and tries to either trigger consequential actions or leak confidential data to unauthorised readers.
- **Trusted:** the user's task, the planner's deterministic policy checks, and the label annotations on tool outputs.
- **Assumed:** labels are correct. Whoever annotates tool outputs is inside the trusted computing base; a mislabelled source silently defeats the policy. This is the "who annotates labels" gap.
- **Accepted leakage:** a bounded number of bits through quarantined answers, and implicit flows through tool choice.
- **Code:** public ([microsoft/fides](https://github.com/microsoft/fides)).

## Evidence

AgentDojo, as extracted in the research record ([arXiv HTML](https://arxiv.org/html/2505.23643)):

| Configuration | Successful injections | Task completion |
|---|---|---|
| Basic planner (no FIDES) | not extracted | 75–98.8% |
| FIDES without policies | 21/152 | not extracted |
| FIDES with policies | 3/152 | 41–59% |
| FIDES with o1 | near-zero attacks | ~68% |

Token cost: in the computer-use adaptation measured by "CaMeLs Can Use Computers Too", an iterative FIDES variant cost **29.6x** tokens versus 1.88x for the CaMeL-style design ([arXiv 2601.09923](https://arxiv.org/html/2601.09923v1)).

## Counter-evidence and weaknesses

- **Utility:** completion with policies (41–59%) is far below the undefended planner (up to 98.8%).
- **Labels must be annotated or inferred.** The authors list this, plus unoptimised efficiency, over-conservative label propagation through LLM calls (label creep), and the need for policy-aware prompts ([arXiv HTML](https://arxiv.org/html/2505.23643)).
- **Implicit flows** via tool choice stay observable under explicit secrecy.
- **Replication:** no independent replication of FIDES numbers is in the record. AgentDyn does not evaluate FIDES, so its open-ended utility is unknown ([arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)).
- **Adaptive attacks:** FIDES is in the June 2026 out-of-band study, but that study is small-scale and has no white-box attack ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)); it was not in [[The Attacker Moves Second]].
- **No credential layer:** like CaMeL, FIDES relies on the tool layer's ambient credentials ([arXiv HTML](https://arxiv.org/html/2505.23643)); see [[Object Capabilities]].

## Where the probabilistic part lives

Label annotation (whoever or whatever assigns labels to tool outputs) and the bounded quarantined LLM answers. Enforcement is deterministic. FlowSeal names the risk of model-assigned labels: "the attack surface and defense mechanism coincide" ([arXiv 2609.14003](https://arxiv.org/html/2609.14003)).

## Adopt / Improve / Add

- **Adopt:** selective hiding and typed quarantine: store high-label results as variables, not context, and allow inspection only through constrained decoding into small schemas. This is the most practical anti-label-creep mechanism in the literature and the basis of the proposed typed-quarantine SDK ([[Information Flow Control]]).
- **Improve:** **Proposal:** derive labels from broker and credential metadata (which account, tenant, repo visibility and OAuth scope produced each datum) instead of hand annotation. That closes FIDES's "who annotates labels" gap with a source the model cannot influence ([[Credential Broker as Label Authority]]). In the MVP the same idea runs at session granularity in [[Trifecta Session Labels]].
- **Add:** **Proposal:** explicit, audited declassification capabilities: who may downgrade which label, recorded in the hash-chained log ([[Audit Recorder and Event Schema]]). FIDES leaves declassification informal. Longer term, carry FIDES-style labels into Cedar context so policies over them are analyzable ([[Provenance-Aware Cedar]]).

## How it connects

- example-of:: [[Information Flow Control]]
- contrasts-with:: [[CaMeL]]
- contrasts-with:: [[Object Capabilities]]

[[Credential Broker as Label Authority]] is the open problem built on FIDES's annotation gap. FIDES extends the Dual LLM pattern from [[Design Patterns for Securing LLM Agents]] with labels and bounded answers. Its missing benchmark coverage on [[AgentDyn]] is a measurement gap.

## Implications for the build

- MVP: FIDES-level per-value labels are out of scope ([[ADR-010 Session-Level Trifecta Labels in the MVP]]); the broker computes session labels from observed systems of record.
- Design adapter outputs so the metadata FIDES needs (tenant, repo, visibility, credential scope) is recorded per response; that is what a label authority would emit later.
- Declassification, when added, is a grant action with its own Cedar action and audit event, never a model decision.

## Open questions

- No independent replication; no open-ended benchmark result.
- How much utility selective hiding recovers when labels come from the broker rather than annotation: untested anywhere.

## Sources

- [arXiv 2505.23643](https://arxiv.org/abs/2505.23643); [HTML](https://arxiv.org/html/2505.23643); [microsoft/fides](https://github.com/microsoft/fides)
- [CaMeLs for computer use, arXiv 2601.09923](https://arxiv.org/html/2601.09923v1)
- [arXiv 2606.26479](https://arxiv.org/abs/2606.26479); [FlowSeal, arXiv 2609.14003](https://arxiv.org/html/2609.14003); [AgentDyn, arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)
