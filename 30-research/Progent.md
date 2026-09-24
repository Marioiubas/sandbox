---
title: "Progent"
aliases: ["Monotonic Confinement"]
type: paper
section: research
tags: [sandbox/research, paper, topic/policy, topic/learning, topic/approval, invariant/i3, milestone/m2, evidence/conflict]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Berkeley's privilege-control layer: JSON-Schema allow/forbid rules on tool arguments, LLM-drafted, with SMT deciding narrowing (automatic) versus widening (approval): AgentDojo ASR 39.9% -> 1.0%; the monotonic-confinement model this design re-hosts on Cedar."
related: ["[[SymCC CI Gates]]", "[[I3 Probabilistic Components Only Narrow]]", "[[Policy Learning Loop]]", "[[The Attacker Moves Second]]", "[[AgentDyn]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[Cedar]]", "[[ADR-011 Verified Policy Learning Loop]]", "[[DRIFT]]", "[[Conseca]]", "[[AgentSpec]]", "[[Provenance-Aware Cedar]]", "[[L2 Injection Benchmarks]]", "[[Policy Miner Safeguards]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://arxiv.org/abs/2504.11703", "https://arxiv.org/html/2504.11703", "https://arxiv.org/html/2504.11703v3", "https://github.com/sunblaze-ucb/progent", "https://arxiv.org/abs/2606.26479", "https://arxiv.org/html/2602.03117v1", "https://arxiv.org/html/2506.12104v2", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/", "https://docs.rs/cedar-policy-symcc"]
---

# Progent

Progent is a privilege-control layer for tool-calling agents. Policies are allow/forbid rules over tool names and arguments, drafted by an LLM from the trusted task; as the task runs, the LLM may propose updates, and an SMT solver decides whether each update **narrows** authority (applied automatically) or **widens** it (needs user approval). On AgentDojo it cut attack success from 39.9% to 1.0% with utility maintained. Its "monotonic confinement" rule is the literature's explicit form of this product's [[I3 Probabilistic Components Only Narrow]], and the broker re-hosts the narrowing check on Cedar's verified analyzer.

## Citation

- Shi, He, Wang, Li, Wu, Guo, Song (UC Berkeley et al.). "Securing AI Agents with Privilege Control" (title as recorded in the research notes; check the current arXiv version). arXiv 2504.11703, Apr 2025; v3 14 May 2026 ([arXiv](https://arxiv.org/abs/2504.11703)).
- Code: [sunblaze-ucb/progent](https://github.com/sunblaze-ucb/progent).
- Venue: preprint in the record.

## Mechanism

From the paper ([arXiv HTML](https://arxiv.org/html/2504.11703); [v3](https://arxiv.org/html/2504.11703v3)):

- **Rule language.** Symbolic allow/forbid rules over tool names and arguments, written as **JSON Schema**, chosen because LLMs emit JSON reliably. Conditions support logic, comparisons, membership, regex and member access on typed arguments. Deny by default.
- **Fallback actions** on a denied call: terminate, ask the user, or return an error to the agent.
- **Authoring.** An LLM generates the initial policy from the trusted task.
- **Updates.** During execution the LLM may propose policy updates. An SMT solver classifies each transition: narrowing updates apply automatically; expansion (widening) updates need user approval. This is **monotonic confinement**.
- **Enforcement** is deterministic, at the tool-call boundary.

Illustrative rule and update check (not Progent's exact syntax):

```json
{ "tool": "send_money", "effect": "allow",
  "args": { "recipient": { "enum": ["DE89 3704 0044 0532 0130 00"] },
            "amount":    { "type": "number", "maximum": 100 } } }
```

```text
propose(P_old → P_new):
  if SMT ⊨ (P_new ⇒ P_old)   apply automatically      # narrowing
  else                       ask user (show P_new ∖ P_old)  # widening
```

## Threat model and assumptions

- **Attacker:** injects instructions through tool results or the environment to make the agent call dangerous tools or pass dangerous arguments ([arXiv HTML](https://arxiv.org/html/2504.11703)).
- **Trusted:** the user's task (the initial policy is generated from it) and the user who approves widenings.
- **Assumed:** the policy LLM translates the task into rules that are neither too narrow (utility) nor too broad (security); there is no independent check that the *initial* policy is minimal, only that later updates narrow it.
- **Out of scope (stated):** attacks within the granted privilege, text-only outputs, non-text agents, and built-in tools in proxy mode.
- **Adaptive attacks:** covered below; three author-run attacks plus one independent small-scale study.

## Evidence

- AgentDojo ASR **39.9% → 1.0%** (gpt-4o as agent and policy model), utility maintained ([arXiv HTML](https://arxiv.org/html/2504.11703)).
- ASB ASR **70.3% → 3.9%** ([arXiv HTML](https://arxiv.org/html/2504.11703)).
- Only **6%** of policy updates needed user approval on AgentDojo ([v3](https://arxiv.org/html/2504.11703v3)).
- Three adaptive attacks (an if-then-else injection, an "allow attack tool" request, AgentVigil red-teaming) produced only marginal ASR increases ([arXiv HTML](https://arxiv.org/html/2504.11703)).
- **Independent:** the June 2026 out-of-band study found Progent reduced mean ASR from 25.8% to 4.2%, and a hand-crafted black-box adaptive attack reached only 2.6%, while calling this "one small-scale data point" and leaving white-box GCG untested ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)).

## Counter-evidence

> [!warning] Conflict
> On ASB, Progent reports 3.9% ASR; DRIFT's comparison measured **15.8%** for Progent in its setup (DRIFT 4.8%) ([DRIFT, arXiv 2506.12104](https://arxiv.org/html/2506.12104v2)). Different models and attack sets; tracked in [[Open Questions and Unverified Claims]].

- **AgentDyn:** Progent lost utility on open-ended tasks and "struggles" to assign accurate tool-access privileges with larger tool sets, blocking useful tools over time ([arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)).
- **Stated limitations:** cannot stop attacks that stay inside least privilege (for example preference manipulation); no protection for text-only outputs; text agents only; user approval errors; proxy mode cannot see built-in tools ([arXiv HTML](https://arxiv.org/html/2504.11703)).
- **Audit weaknesses (research inference):** (1) security of the initial policy depends on an LLM translating the task into JSON rules, so a subtly over-broad rule is silently accepted; (2) a wrong-but-allowed recipient chosen from untrusted data passes; (3) no data-flow labels, so exfiltration through an allowed channel is possible; (4) adaptive evaluation is small.

## Where the probabilistic part lives

Initial policy authoring and proposed updates (LLM). The SMT check and the monitor are deterministic. Crucially, the LLM can only *narrow* without a human: that is the property this product generalises.

## Adopt / Improve / Add

- **Adopt:** monotonic confinement as the core invariant: a capability can be attenuated without consent, never widened. JSON-Schema-over-arguments is a good LLM-friendly authoring surface; the product's equivalent is the TOML front-end.
- **Improve:** **Proposal:** run the narrowing check on Cedar's verified analyzer instead of an ad-hoc JSON-Schema→SMT encoding: `check_implies(P_new, P_old)` in `cedar-policy-symcc`, with counterexamples shown as the expansion delta ([docs.rs](https://docs.rs/cedar-policy-symcc); [[SymCC CI Gates]], [[Cedar]]). Bound every generated policy by a static org ceiling (`check_implies(P_new, P_ceiling)`), as AgentCore's neuro-symbolic loop does ([AWS](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)). Add provenance conditions to argument constraints ("`recipient` must be user-literal or from a trusted directory"; [[Provenance-Aware Cedar]]).
- **Add:** **Proposal:** an approval UI that shows the *authority diff*, since approval errors are a stated limitation ([[Fatigue-Resistant Approval Interfaces]]); and learning from traces rather than only LLM drafting ([[Policy Learning Loop]], [[ADR-011 Verified Policy Learning Loop]]), with the safeguards in [[Policy Miner Safeguards]].

## How it connects

- evaluated-by:: [[AgentDyn]]
- evaluated-by:: [[L2 Injection Benchmarks]]
- contrasts-with:: [[DRIFT]]
- contrasts-with:: [[Conseca]]
- contrasts-with:: [[AgentSpec]]

Design notes that re-host Progent: [[SymCC CI Gates]] (narrowing gate), [[I3 Probabilistic Components Only Narrow]] (the invariant), [[Policy Learning Loop]] and [[ADR-011 Verified Policy Learning Loop]] (widenings go through human PR). [[The Attacker Moves Second]] explains why the deterministic check, not the LLM, carries the guarantee. Progent's 1.0% AgentDojo ASR anchors the L2 threshold.

## Implications for the build

- M2: every learned or edited policy change runs `check_implies(P_new, P_old)`; non-implied changes block merge and show counterexample requests.
- Runtime step-up (`grant.request`) follows the same rule: narrowing needs no prompt; widening shows the diff and needs approval.
- L2 release threshold: side-effect ASR ≤1% on AgentDojo (Progent-level).

## Open questions

- The ASB conflict (3.9% vs 15.8%).
- How to avoid Progent's AgentDyn failure (privileges drifting too narrow on large tool sets) in a learned policy: measure over- and under-privilege rates ([[Policy Learning Loop]]).

## Sources

- [arXiv 2504.11703](https://arxiv.org/abs/2504.11703); [HTML](https://arxiv.org/html/2504.11703); [v3](https://arxiv.org/html/2504.11703v3); [code](https://github.com/sunblaze-ucb/progent)
- [arXiv 2606.26479](https://arxiv.org/abs/2606.26479); [AgentDyn](https://arxiv.org/html/2602.03117v1); [DRIFT](https://arxiv.org/html/2506.12104v2)
- [AWS AgentCore Policy blog](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/); [cedar-policy-symcc](https://docs.rs/cedar-policy-symcc)
