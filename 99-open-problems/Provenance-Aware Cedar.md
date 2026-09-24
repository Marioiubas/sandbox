---
title: "Provenance-Aware Cedar"
aliases: []
type: problem
section: open
tags: [sandbox/open, problem, topic/policy, topic/ifc, milestone/phase3]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Provenance-Aware Cedar

> Put per-argument integrity and reader labels into Cedar context and prove properties such as 'no untrusted-integrity value can reach git.push to a public repo'; no paper combines IFC with a formally verified policy engine.

## The problem

Cedar decides each request with Lean-proved semantics and can be analysed symbolically, but it is a stateless request-authorization language: information-flow properties such as "data derived from file F never leaves" are not expressible in it directly. Cedar can only check the labels the broker gives it (report; research note 04a Q5). Information-flow systems for agents (CaMeL, FIDES) track labels per value but enforce policies written in unanalysable forms: CaMeL's policies are hand-written Python per tool, and FIDES assumes someone annotates labels. No paper in the record combines information-flow control with a formally verified policy engine (report; research note 02 Q6).

The research problem: design a schema, entity builder and monitor that inject **per-argument** provenance (integrity) and reader (confidentiality) labels into Cedar request context, so that the analyzer can prove flow properties such as "no untrusted-integrity value can reach `git.push` to a public repo", or "can any untrusted-integrity value reach `send_email.to`?".

## Why it matters

- **Choosing among allowed actions is the residual attack surface** for every deterministic design. An injected document can still choose which value flows into an allowed call (the design-patterns paper's "data parameter manipulation"; CaMeL for computer use calls it Branch Steering) ([arXiv](https://arxiv.org/html/2506.08837); [arXiv](https://arxiv.org/html/2601.09923v1)). Only provenance-conditioned policies ("recipient must originate from the user or a trusted directory") or human confirmation address it (research note 02 Q3).
- **AgentCore Policy** authorizes calls on inputs and identity with Cedar at a gateway, but its docs do not describe tracking where argument values came from ([AgentCore docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html)); see [[AWS AgentCore]]. Adding provenance attributes to the request context would turn Cedar into a CaMeL-style monitor without changing the engine (research note 02 Q4).
- The MVP's session-level trifecta labels are coarse and inherit IFC's label-creep problem ([[ADR-010 Session-Level Trifecta Labels in the MVP]]). Per-argument labels are the precise version.

## State of the art

- **CaMeL**: values carry readers and provenance tags; Python policies check them at each tool call. 77% of AgentDojo tasks vs 84% undefended, attacks against GPT-4o fell to 0 ([arXiv](https://arxiv.org/html/2503.18813)); zero utility on AgentDyn's open-ended tasks ([AgentDyn](https://arxiv.org/html/2602.03117v1)). See [[CaMeL]].
- **FIDES**: confidentiality × integrity labels with selective hiding; injections 21/152 → 3/152 with policies, but completion fell to 41-59% ([arXiv](https://arxiv.org/html/2505.23643)). See [[FIDES]].
- **Cedar**: authorization semantics proved in Lean; symbolic compilation to SMT sound and complete ([cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)); `cedar-policy-symcc` exposes `check_implies`, `check_always_denies` and related queries with counterexamples ([docs.rs](https://docs.rs/cedar-policy-symcc)). See [[Cedar]].
- **Guarantee limits**: proofs hold only relative to the schema; `like` patterns are string patterns, not DNS semantics; flow properties need labels carried in context (report).
- Sequence rules (Invariant's `->`) are not native to Cedar; the report proposes a broker automaton exposed as context attributes ([[Trifecta Session Labels]]).

## Research approach (Proposal)

1. **Label model.** Define integrity ∈ {user-literal, trusted-system, untrusted} and a readers set, per value. Sources: the user's task text (user-literal); responses from systems of record the broker proxies, labelled by the credential and resource that produced them ([[Credential Broker as Label Authority]]); everything else untrusted.
2. **Where labels attach.** The broker sees request and response bodies on the L7 path. For each outbound request, the adapter identifies argument fields (for example `git.push` target repo and ref, a GitHub `issue.comment` body, an MCP `tools/call` argument) and computes each field's label by matching it against recorded response values in the session (exact or normalised match), defaulting to untrusted when unknown.
3. **Schema extension.** Extend `HttpCtx`, `GitCtx` and `McpCtx` in the [[Broker Cedar Schema]] with per-argument records, for example `args: { to: { integrity: String, readers: Set<String> } }`. `McpCtx.args_integrity` in the report's sketch is the one-field precursor.
4. **Properties as SymCC queries.** Encode "no untrusted-integrity argument reaches `git.push` on a repo with `visibility == "public"`" as a reference policy and check `check_implies(P, P_ref)` restricted to that action's request environment; a counterexample is a concrete violating request.
5. **Evaluate.** Measure on AgentDojo and AgentDyn with the L2 shim ([[L2 Injection Benchmarks]]): ASR on data-parameter attacks, utility, and label-creep rate (fraction of values that end up untrusted). Compare against session-level labels.
6. **Adversarial test.** Attack the label matcher directly (paraphrase, encoding, splitting a value across fields); this is the white-box target named in [[Adaptive Evaluation of Deterministic Monitors]].

## How it would change the product

- Policies could express "open a PR, but the PR body may not contain values read from a private repo" as an analyzable rule instead of a session-wide Rule-of-Two block, which should reduce over-blocking.
- SymCC gates could prove flow properties at policy-change time, not just narrowing ([[SymCC CI Gates]]).
- A publishable first: IFC on a formally verified policy engine.

## Hooks in the MVP

- Keep the trifecta `Session` record and `McpCtx.args_integrity` in the schema so per-argument labels are an extension, not a rewrite.
- Record response metadata (resource, credential ID, repo visibility) in audit events so labels can be computed offline from traces.

## How it connects

- depends-on:: [[Cedar]]
- depends-on:: [[Broker Cedar Schema]]
- depends-on:: [[Credential Broker as Label Authority]]
- motivated-by:: [[Information Flow Control]]
- motivated-by:: [[CaMeL]]
- motivated-by:: [[FIDES]]
- contrasts-with:: [[AWS AgentCore]]
- contrasts-with:: [[Trifecta Session Labels]] (the coarse session-level form in the MVP)
- decided-by:: [[ADR-010 Session-Level Trifecta Labels in the MVP]] (deferred from the MVP)
- evaluated-by:: [[L2 Injection Benchmarks]]

## Implications for the build

- Do not hard-code session-level labels into the entity builder in a way that prevents per-argument context later.
- Log enough response provenance in the audit stream (without secret values) to support offline label computation.

## Open questions

- How to label derived values (summaries, reformatted strings) without an LLM judge; RTBAS-style LM-judge dependency screening is probabilistic ([[Information Flow Control]]).
- Whether SymCC scales to schemas with nested per-argument records ([[SymCC CI Gates]]).

## Sources

- Report: "Eight research problems" item 1; "Three gaps no paper fills" bullet 1; Cedar guarantees and their hard edges.
- Research note 02 Q3, Q4 inference (provenance attributes in request context; AgentCore does not track argument origin) and Q6 open problem 1.
