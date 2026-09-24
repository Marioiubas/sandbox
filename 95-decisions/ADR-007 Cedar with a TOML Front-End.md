---
title: "ADR-007 Cedar with a TOML Front-End"
aliases: ["ADR-007"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, topic/learning, invariant/i3, invariant/i4, invariant/i6, invariant/i9, milestone/m2, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Use Cedar (Lean-verified, SymCC-analyzable, µs latency, agent-gateway precedent) behind a small TOML layer; reject OPA/Rego, Progent JSON-Schema, Invariant rules and a custom DSL."
related: ["[[Cedar]]", "[[broker.toml Human Policy Layer]]", "[[SymCC CI Gates]]", "[[Progent]]", "[[AWS AgentCore]]", "[[Trifecta Session Labels]]", "[[Broker Cedar Schema]]", "[[Example Cedar Policies]]", "[[Policy Engine and Entity Builder]]", "[[Local Credential Proxies]]", "[[AgentSpec]]", "[[Provenance-Aware Cedar]]", "[[Hostname Canonicaliser]]", "[[Policy Learning Loop]]", "[[Native Config Exporters]]", "[[Tech Stack]]", "[[I3 Probabilistic Components Only Narrow]]", "[[I4 Repo Policy Only Narrows]]", "[[I6 Single Canonicaliser]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[ADR-008 Grant Representation as Entities and Txn-Token JWT]]", "[[ADR-015 Rust for the Endpoint and Custom Proxy]]", "[[M2 Policy Audit and Learn]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md", "https://arxiv.org/html/2403.04651", "https://docs.rs/cedar-policy-symcc", "https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/", "https://goteleport.com/blog/benchmarking-policy-languages/", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/", "https://github.com/strongdm/leash", "https://arxiv.org/html/2504.11703", "https://github.com/invariantlabs-ai/invariant", "https://arxiv.org/abs/2503.18666", "https://www.harness.io/blog/policy-as-code-in-2026-opa-kyverno-cedar-and-what-s-next", "https://natoma.ai/blog/mcp-access-control-opa-vs-cedar-the-definitive-guide"]
---

# ADR-007 Cedar with a TOML Front-End

> Use Cedar (Lean-verified, SymCC-analyzable, µs latency, agent-gateway precedent) behind a small TOML layer; reject OPA/Rego, Progent JSON-Schema, Invariant rules and a custom DSL.

## Status

**Proposed** (2026-09-24). Delivered in [[M2 Policy Audit and Learn]] (Cedar schema, TOML→Cedar compiler, enforce and audit modes, SymCC CI gates). M0 and M1 use a host allowlist and method/path rules that M2 re-expresses in Cedar. Not superseded.

## Context

The policy engine sits on every request's hot path. It is also the thing the learning loop must prove narrowings about, and the thing humans review. Four requirements follow:

- verified allow/deny semantics;
- decidable analysis (is policy B narrower than policy A?);
- microsecond latency with no pathological inputs;
- a representation humans can write and review.

**Cedar's semantics are proved in Lean.** The proved properties are: forbid overrides permit; a request is allowed only if explicitly permitted; evaluation order and duplicates do not matter; type checking is sound. Its symbolic compilation to SMT is sound and complete ([cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)). Differential random testing between the Rust implementation and the Lean model found about two dozen bugs ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)).

**Cedar is analyzable today.**

- `cedar-policy-symcc` exposes six queries on cvc5, each with a counterexample variant: `check_never_errors`, `check_always_allows`, `check_always_denies`, `check_implies`, `check_equivalent` and `check_disjoint` ([docs.rs](https://docs.rs/cedar-policy-symcc)).
- Cedar Analysis classifies two policy sets as equivalent, more permissive, less permissive or incomparable, and flags shadowed permits ([AWS Open Source Blog](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/)).
- The paper reports an average of 75.1 ms to encode and solve decidable analyses ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)).

**Cedar is fast and deterministic.**

- Median authorization takes 4.0–11.0 µs. In the Cedar paper's benchmark it is 28.7–35.2x faster than OpenFGA and 42.8–80.8x faster than Rego ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)).
- Teleport's benchmark (2025, background) finds Cedar deterministic, deliberately regex-free and latency-bounded, while Rego showed runtime exceptions and regex DoS sensitivity ([Teleport](https://goteleport.com/blog/benchmarking-policy-languages/)).

**There is agent precedent.** AgentCore Policy puts Cedar at an agent→tool gateway, default-deny, and turns natural language into Cedar that analysis then verifies ([AWS](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/); [[AWS AgentCore]]). StrongDM Leash uses Cedar over file, process and network events ([Leash](https://github.com/strongdm/leash); [[Local Credential Proxies]]). Practitioner comparisons of OPA and Cedar for MCP and agent access control exist from 2026 ([Harness](https://www.harness.io/blog/policy-as-code-in-2026-opa-kyverno-cedar-and-what-s-next); [Natoma](https://natoma.ai/blog/mcp-access-control-opa-vs-cedar-the-definitive-guide)).

**Cedar's guarantees have hard edges** ([[Cedar]]):

- They cover policy semantics, not how raw traffic is parsed into entities.
- They hold only relative to the schema; non-canonical host strings produce proofs about the wrong thing.
- `like` patterns are string patterns, not DNS semantics.
- Information-flow and sequence properties are not expressible in stateless request authorization.

**The alternatives each fail one requirement.**

- Progent's JSON-Schema rules with an ad-hoc SMT narrowing check cut AgentDojo attack success from 39.9% to 1.0% ([arXiv](https://arxiv.org/html/2504.11703); [[Progent]]), but the encoding has no proved semantics.
- Invariant's rule language has a `->` sequence operator but embeds ML detectors with thresholds ([Invariant](https://github.com/invariantlabs-ai/invariant)).
- LLM-written AgentSpec rules reached 95.56% precision but only 70.96% recall ([arXiv](https://arxiv.org/abs/2503.18666); [[AgentSpec]]).

## Decision

**Proposal.**

1. **One engine.** Every allow/deny decision on the endpoint is made in-process by the `cedar-policy` crate against the `Broker` namespace schema ([[Broker Cedar Schema]]). The engine is invoked by [[Policy Engine and Entity Builder]]. No second engine or ad-hoc allowlist decides anything after M2.
2. **Analysis in CI.** `cedar-policy-symcc` plus cvc5 runs the merge-blocking gates: narrowing, org ceiling, credential confinement, never-errors, live deny rules, and tenant disjointness ([[SymCC CI Gates]]).
3. **A small human layer.** `broker.toml` (profiles, filesystem write and deny-read lists, and `egress` array-of-tables entries with host, protocol, methods, git rules and credential kind) compiles deterministically to Cedar policies plus entity data ([[broker.toml Human Policy Layer]]). Power users may write Cedar directly, and it goes through the same gates.
4. **Grants are entities, not policy text.** Expiry and revocation are data updates ([[ADR-008 Grant Representation as Entities and Txn-Token JWT]]).
5. **Session state goes into Cedar context, never into the engine.** Trifecta labels and a small sequence automaton (for Invariant-style `get_inbox -> send_email` rules) are computed by the broker and exposed as context attributes ([[Trifecta Session Labels]]).
6. **Hygiene.**
   - Entities are built only from canonical values ([[Hostname Canonicaliser]]).
   - Time is modelled as epoch seconds until Cedar `datetime` support is verified.
   - Schema validation is strict; a policy that fails validation is not loaded.

Testable form:

- The compiler is deterministic: byte-identical output for the same TOML.
- Every compiled bundle passes `check_never_errors`.
- The canonicalisation test proves a non-canonical host string never reaches the entity builder.
- Every audit event carries the determining policy IDs.
- p50 authorization latency on reference hardware sits within the L4 budget.

## Alternatives considered

| Alternative | Pros | Cons (evidence) | Why rejected |
|---|---|---|---|
| **OPA/Rego** | Very expressive; mature ecosystem; good for data-rich config validation | 42.8–80.8x slower in the Cedar paper's benchmark; runtime exceptions and regex DoS sensitivity ([Teleport](https://goteleport.com/blog/benchmarking-policy-languages/)); limited pre-verification tooling | No verified narrowing analysis on the hot path. (The only sourced speed comparison is Cedar's own paper; Rego's analyzability limits are background knowledge.) |
| **Progent JSON-Schema rules** | Proven agent results; natural for tool arguments | Ad-hoc JSON-Schema→SMT encoding; no proved semantics; no principal, action or resource model for egress | Adopt its monotonic-confinement idea, re-hosted on a verified analyzer |
| **Invariant rules** | Sequence operator `->`; Apache-2.0 | ML detector thresholds inside rules make decisions probabilistic, which [[I3 Probabilistic Components Only Narrow]] forbids; not analyzable | Adopt sequence semantics as broker-side state exposed as Cedar context |
| **Custom DSL** | Tailored to egress | Another parser on a hostile boundary; no proofs; everything built from scratch | The enforcement-layer bug record argues against new custom components |
| **cedar-go** | Would fit a Go endpoint | Feature parity with the Rust crate unverified | Moot while the endpoint is Rust ([[ADR-015 Rust for the Endpoint and Custom Proxy]]) |

## Consequences

**Positive.**

- Narrowing becomes a proof, not a review opinion. This makes [[I4 Repo Policy Only Narrows]] and [[I3 Probabilistic Components Only Narrow]] mechanically checkable (`check_implies`).
- Decisions are fast and deterministic enough for every request, with explainable determining policies for `broker why`.
- One source can also be exported to vendor configs ([[Native Config Exporters]]).
- LLM authoring of drafts stays safe because drafts pass gates before use, as AgentCore does.

**Negative.**

- Two languages to maintain: TOML semantics must be specified precisely, and the compiler is security-critical.
- No regex and string-only `like` push matching work into the canonicaliser and adapters.
- IFC is not expressible natively; provenance-aware policies remain a research problem ([[Provenance-Aware Cedar]]).
- SymCC's unsupported features and scalability limits are not documented; the analysis CLI is not confirmed Lean-verified end to end.

**Follow-up work.**

- Compile the schema sketch; it has never been compiled.
- Pin crate versions after verifying maturity.
- Add a compiler golden-test corpus.
- Schedule the white-box attack on the entity builder in the red-team plan.

## Revisit triggers

- SymCC cannot scale to real org policy sets within CI time, or lacks a feature the gates need.
- The schema needs regex or DNS-aware matching that canonicalisation cannot supply.
- Provenance-aware extensions require an engine change rather than context attributes.
- The endpoint language changes away from Rust.

## Invariants and components affected

- **Upholds** [[I3 Probabilistic Components Only Narrow]] and [[I4 Repo Policy Only Narrows]] (SymCC gates) and [[I9 Hash-Chained Audit Outside the Sandbox]] (determining policy IDs are logged).
- **Depends on** [[I6 Single Canonicaliser]], because proofs are only as good as the schema's canonical strings.
- **Weakens none.**
- Components: [[Policy Engine and Entity Builder]], [[broker.toml Human Policy Layer]], [[SymCC CI Gates]], [[Policy Learning Loop]].

## How it connects

- depends-on:: [[Cedar]]
- implements:: [[Broker Cedar Schema]]
- implements:: [[broker.toml Human Policy Layer]]
- evaluated-by:: [[SymCC CI Gates]]
- motivated-by:: [[Progent]]
- motivated-by:: [[AWS AgentCore]]
- contrasts-with:: [[AgentSpec]]
- depends-on:: [[Trifecta Session Labels]]
- delivered-by:: [[Policy Engine and Entity Builder]]
- delivered-by:: [[M2 Policy Audit and Learn]]

## Implications for the build

- M2 acceptance ("every learned change passes the narrowing or ceiling gates or shows counterexamples") needs SymCC wired into CI before the miner produces diffs.
- Keep TOML fail-closed: empty lists deny, and omitted methods do not mean "all" ([[ADR-006 Deny Unmatched L7 Requests]]).
- Fuzz the TOML parser and property-test the compiler against a reference interpretation.

## Open questions

- Cedar `datetime` and `duration` availability across SDKs ([[Open Questions and Unverified Claims]]).
- SymCC limits; crate versions beyond `hudsucker` and `landlock` ([[Tech Stack]]).
- cedar-go parity (only if Go is reconsidered).

## Sources

- https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md
- https://arxiv.org/html/2403.04651
- https://docs.rs/cedar-policy-symcc
- https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/
- https://goteleport.com/blog/benchmarking-policy-languages/
- https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/
- https://github.com/strongdm/leash
- https://arxiv.org/html/2504.11703
- https://github.com/invariantlabs-ai/invariant
- https://arxiv.org/abs/2503.18666
- https://www.harness.io/blog/policy-as-code-in-2026-opa-kyverno-cedar-and-what-s-next
- https://natoma.ai/blog/mcp-access-control-opa-vs-cedar-the-definitive-guide
- Report: "Why Cedar, and where its guarantees stop", schema sketch, formal gates, tech-stack policy row, decision table row "Policy language". Research note 02 Q4, research note 03 Q5.
