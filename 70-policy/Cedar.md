---
title: "Cedar"
aliases: ["Cedar Policy Language", "cedar-policy"]
type: standard
section: policy
tags: [sandbox/policy, standard, topic/policy, invariant/i3, invariant/i4, milestone/m2]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Cedar as the decision core: Lean-proved semantics (forbid wins, default deny, order-independence, sound typing), sound and complete SMT compilation, 4-11 µs median latency, no regex, agent-gateway precedent (AgentCore Policy, Leash), and the hard edges of its guarantees."
related: ["[[ADR-007 Cedar with a TOML Front-End]]", "[[SymCC CI Gates]]", "[[Broker Cedar Schema]]", "[[AWS AgentCore]]", "[[Local Credential Proxies]]", "[[Provenance-Aware Cedar]]", "[[Hostname Canonicaliser]]", "[[Policy Engine and Entity Builder]]", "[[Progent]]", "[[Example Cedar Policies]]", "[[broker.toml Human Policy Layer]]", "[[Trifecta Session Labels]]", "[[Information Flow Control]]", "[[I6 Single Canonicaliser]]", "[[Tech Stack]]", "[[Open Questions and Unverified Claims]]", "[[CaMeL]]", "[[Policy Learning Loop]]"]
sources: ["https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md", "https://arxiv.org/html/2403.04651", "https://dl.acm.org/doi/10.1145/3649835", "https://docs.rs/cedar-policy-symcc", "https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/", "https://goteleport.com/blog/benchmarking-policy-languages/", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/", "https://github.com/strongdm/leash", "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html", "https://github.com/cedar-policy/cedar/issues/1385", "https://arxiv.org/html/2504.11703v3", "https://github.com/invariantlabs-ai/invariant"]
---

# Cedar

> Cedar as the decision core: Lean-proved semantics (forbid wins, default deny, order-independence, sound typing), sound and complete SMT compilation, 4-11 µs median latency, no regex, agent-gateway precedent (AgentCore Policy, Leash), and the hard edges of its guarantees.

## What it specifies

Cedar is a typed authorization language. A request is a tuple of **principal, action, resource and context**. A policy set of `permit` and `forbid` rules decides it, and a schema types entities, attributes and actions. The language was published as "Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization" at OOPSLA 2024 ([ACM DL](https://dl.acm.org/doi/10.1145/3649835); [arXiv 2403.04651](https://arxiv.org/html/2403.04651)).

The broker uses Cedar for two separate jobs:

1. **Runtime decision.** Every classified request (an `http.POST` on a path, a `git.push` of one ref, a `credential.use`, an `mcp.call_tool`) is one Cedar request, evaluated in-process by the `cedar-policy` crate inside [[Policy Engine and Entity Builder]].
2. **Change-time proof.** Every edited or learned policy set is checked with the symbolic analyzer before it can merge ([[SymCC CI Gates]]).

The decision to use Cedar with a TOML front-end is [[ADR-007 Cedar with a TOML Front-End]].

## Proved semantics

Cedar's authorization semantics are formalised and proved in Lean ([cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)):

| Property | Statement (quoted from the Lean README) | Why the broker needs it |
|---|---|---|
| Forbid wins | "If some forbid policy is satisfied, then the request is denied." | Org ceilings and trifecta forbids cannot be overridden by a later permit |
| Explicit allow | "A request is allowed only if it is explicitly permitted." | Unknown hosts, verbs and repos deny with no extra code (fail closed) |
| Default deny | "If not explicitly permitted, a request is denied." | An empty grant set grants nothing, unlike [[sandbox-runtime Empty Allowlist Bypass]] |
| Order independence | "Authorization produces the same result regardless of policy evaluation order or duplicates." | Bundles can be merged from org, user and repo layers without precedence bugs |
| Sound typing | Well-typed expressions can fail only with `entityDoesNotExist`, `extensionError` or `arithBoundsError` | Validation at bundle-build time removes most runtime error paths |

The same README also lists sound policy slicing, sound level-based entity slicing, "sound and complete symbolic compilation" and "sound and complete verification", meaning no false negatives and no false positives ([cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)).

The Rust implementation is checked against the Lean model by differential random testing, which found about two dozen bugs ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)).

## Analysis

The symbolic compiler maps policies to SMT and is sound and complete for decidable analyses such as equivalence, averaging 75.1 ms to encode and solve in the paper's evaluation ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)). The open-source analyzer `cedar-policy-symcc` exposes six queries (`check_never_errors`, `check_always_allows`, `check_always_denies`, `check_implies`, `check_equivalent`, `check_disjoint`), each with a counterexample variant, and runs on cvc5 ([docs.rs](https://docs.rs/cedar-policy-symcc)). Cedar Analysis classifies two policy sets as equivalent, more permissive, less permissive or incomparable, and flags shadowed permits and impossible conditions ([AWS Open Source Blog](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/)). How the broker turns these into merge gates is in [[SymCC CI Gates]].

## Performance and determinism

- Median authorization latency is 4.0-11.0 µs. Cedar was 28.7-35.2x faster than OpenFGA and 42.8-80.8x faster than Rego in the paper's benchmark ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)).
- Teleport's 2025 benchmark describes Cedar as "type-safe, memory safe and data-race safe", deterministic and analyzable, with no regex by design and consistently bounded latency. Rego showed runtime exceptions and regex DoS sensitivity, and OpenFGA failed at 100K-set scale ([Teleport](https://goteleport.com/blog/benchmarking-policy-languages/)).

The broker's per-request policy budget is therefore dominated by TLS and parsing, not by Cedar. The latency targets in [[L4 Product Metrics]] are end-to-end, so they still have to be measured.

## Agent precedent

- **AWS AgentCore Policy** puts Cedar at the AgentCore Gateway, default-deny, evaluating every agent-to-tool call. It uses partial evaluation to hide denied tools from the LLM, and turns natural language into Cedar that Cedar Analysis then checks ([AWS Security Blog](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)). Its principals are `AgentCore::OAuthUser` or `AgentCore::IamEntity`, and its schema is generated from tool definitions with tool inputs in context ([AWS docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html)). See [[AWS AgentCore]].
- **StrongDM Leash** enforces Cedar over file, process and network telemetry from an eBPF monitor, plus MCP tool calls ([GitHub](https://github.com/strongdm/leash)). See [[Local Credential Proxies]].
- **Progent** decides narrowing versus widening of tool policies with an SMT check ([arXiv 2504.11703](https://arxiv.org/html/2504.11703v3)). The broker re-hosts that check on Cedar's verified analyzer ([[Progent]]).

## Limits: where the guarantees stop

The proofs are about *policy semantics*. Four hard edges follow, and each one is a build obligation:

1. **Not the enforcement point.** Nothing in Lean covers how raw bytes become Cedar entities: host, SNI, IP, redirects, pkt-lines. Conformance categories 4, 6, 7 and 8 must still be tested empirically ([[L1 Conformance Suite]]).
2. **Schema-relative.** A proof holds only for the schema and request environment it was run against. A schema that admits non-canonical host strings yields proofs about the wrong thing. This is why [[I6 Single Canonicaliser]] runs *before* the entity builder, via [[Hostname Canonicaliser]].
3. **`like` is not DNS.** `*.example.com` is a string pattern. It knows nothing about trailing dots, IDNA forms or case. Canonicalise first, then match.
4. **No information flow.** Stateless request authorization cannot express "data derived from file F never leaves". Cedar can only check labels the broker puts into context ([[Trifecta Session Labels]], [[Information Flow Control]]). Carrying per-argument provenance is the open problem [[Provenance-Aware Cedar]].

A fifth, practical edge: Cedar has no sequence operator. Invariant's rule language has a `->` operator for ordered tool calls ([GitHub](https://github.com/invariantlabs-ai/invariant)). The broker keeps sequence state in a small automaton and exposes it as context ([[Trifecta Session Labels]]).

> [!question] Unverified
> - Cedar `datetime`/`duration` availability across SDKs as of September 2026 was not verified. The schema models time as epoch seconds (`Long`) until it is ([[Broker Cedar Schema]]).
> - Whether the analysis CLI is Lean-verified end to end, which Cedar features SymCC does not support, and its scalability limits are not documented in the record. A roadmap discussion exists in [cedar issue #1385](https://github.com/cedar-policy/cedar/issues/1385).
> - cedar-go feature parity with the Rust crate was not verified. This only matters if Go is reconsidered ([[Tech Stack]]).
> See [[Open Questions and Unverified Claims]].

## How the broker uses it

**Proposal:** Principal is always the `Task`, which carries user, agent, repo and expiry. Actions are adapter verbs, not raw HTTP only. Grants are entity data, so expiry and revocation are data updates with no recompile ([[Broker Cedar Schema]]). A protocol adapter may emit several Cedar requests for one network request (for example `http.POST` on a path plus `credential.use` on the GitHub credential), and **all** must allow before the credential is minted ([[Policy Engine and Entity Builder]]).

**Proposal:** Every decision records its determining policy IDs so `broker why` can explain it, and so the learning loop can count evidence per rule ([[Policy Learning Loop]]).

## How it connects

- decided-by:: [[ADR-007 Cedar with a TOML Front-End]]
- evaluated-by:: [[SymCC CI Gates]]
- part-of:: [[Policy Engine and Entity Builder]]
- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[Broker Cedar Schema]]
- motivated-by:: [[Progent]]
- motivated-by:: [[AWS AgentCore]]
- contrasts-with:: [[Local Credential Proxies]]
- contrasts-with:: [[CaMeL]]
- example-of:: [[Information Flow Control]]
- depends-on:: [[Trifecta Session Labels]]
- Open extension: [[Provenance-Aware Cedar]] adds per-argument labels to the context this note's fourth limit cannot express.

Alternatives (OPA/Rego, Progent JSON-Schema, Invariant rules, a custom DSL) are rejected in [[ADR-007 Cedar with a TOML Front-End]].

## Implications for the build

- Use the `cedar-policy` crate in-process; no FFI, no sidecar ([[Tech Stack]]).
- Validate every bundle against [[Broker Cedar Schema]] at build time and refuse to load one that fails validation (fail closed, [[I2 Fail-Closed Launch]] spirit).
- Never put a raw, uncanonicalised host string into an entity UID. Unit-test that the entity builder rejects anything the canonicaliser would reject.
- Put a Cedar-evaluation microbenchmark into CI so a schema change cannot silently blow the latency budget.
- Treat Cedar proofs as necessary but not sufficient: every enforcement-layer category in [[Conformance Probe Matrix]] still needs a deterministic probe.

## Open questions

- Is `datetime` usable in the Rust crate and in the analyzer for the shipped version? If so, should `expires_at` move from `Long` to `datetime`?
- Which Cedar features does SymCC not support (for example extension functions used in `like` or IP matching), and how does solve time scale with a 1,000-rule learned policy?
- Can partial evaluation (as AgentCore uses it) tell the agent in advance which verbs it will be denied, reducing wasted attempts without leaking policy?

## Sources

- [cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)
- [arXiv 2403.04651](https://arxiv.org/html/2403.04651); [ACM DL](https://dl.acm.org/doi/10.1145/3649835)
- [docs.rs cedar-policy-symcc](https://docs.rs/cedar-policy-symcc)
- [AWS Open Source Blog: Cedar Analysis](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/)
- [Teleport policy-language benchmark](https://goteleport.com/blog/benchmarking-policy-languages/)
- [AWS Security Blog: AgentCore Policy](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/); [AgentCore policy docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html)
- [StrongDM Leash](https://github.com/strongdm/leash)
- [cedar issue #1385](https://github.com/cedar-policy/cedar/issues/1385)
- [Progent](https://arxiv.org/html/2504.11703v3)
- [Invariant](https://github.com/invariantlabs-ai/invariant)
