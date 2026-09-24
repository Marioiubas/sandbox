---
title: "SymCC CI Gates"
aliases: ["cedar-policy-symcc", "L5 Formal Gates", "Formal Gates"]
type: concept
section: policy
tags: [sandbox/policy, concept, topic/policy, topic/evaluation, topic/learning, invariant/i3, invariant/i4, milestone/m2, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "cedar-policy-symcc's six queries (never_errors, always_allows, always_denies, implies, equivalent, disjoint, each with counterexamples, on cvc5) and the six merge-blocking gates: narrowing, org ceiling, credential confinement, no runtime errors, live deny rules, tenant disjointness. This is eval layer L5."
related: ["[[Cedar]]", "[[Progent]]", "[[Policy Learning Loop]]", "[[Policy Miner Safeguards]]", "[[I3 Probabilistic Components Only Narrow]]", "[[I4 Repo Policy Only Narrows]]", "[[Evaluation Harness]]", "[[Control Plane and Policy Bundles]]", "[[M2 Policy Audit and Learn]]", "[[ADR-011 Verified Policy Learning Loop]]", "[[Broker Cedar Schema]]", "[[Example Cedar Policies]]", "[[Hostname Canonicaliser]]", "[[L1 Conformance Suite]]", "[[Open Questions and Unverified Claims]]", "[[broker.toml Human Policy Layer]]", "[[AWS AgentCore]]"]
sources: ["https://docs.rs/cedar-policy-symcc", "https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/", "https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md", "https://arxiv.org/html/2504.11703v3", "https://arxiv.org/html/2403.04651", "https://github.com/cedar-policy/cedar/issues/1385", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/"]
---

# SymCC CI Gates

> cedar-policy-symcc's six queries (never_errors, always_allows, always_denies, implies, equivalent, disjoint, each with counterexamples, on cvc5) and the six merge-blocking gates: narrowing, org ceiling, credential confinement, no runtime errors, live deny rules, tenant disjointness. This is eval layer L5.

## Summary

Every policy change, whether a human edit, a repository `.broker/` file or a learned diff, must pass a set of machine-checked properties before it can merge or ship in a bundle. The checks run on `cedar-policy-symcc`, Cedar's open-source symbolic compiler, which is proved sound and complete. That turns [[I3 Probabilistic Components Only Narrow]] and [[I4 Repo Policy Only Narrows]] from review guidelines into CI failures. In the [[Evaluation Harness]] this is layer **L5**, with a release threshold of 100% pass.

## Details

### The analyzer

- `cedar-policy-symcc` exposes six queries: `check_never_errors`, `check_always_allows`, `check_always_denies`, `check_implies`, `check_equivalent` and `check_disjoint`. Each has a `*_with_counterexample` variant that yields "a synthesized request and entity store". Inputs are a schema, a request environment (from `schema.request_envs()`) and a policy set. The solver is cvc5 1.3.1, located via the `CVC5` environment variable ([docs.rs](https://docs.rs/cedar-policy-symcc)).
- It was open-sourced on 2025-06-16 together with the Cedar Analysis CLI. The CLI classifies two policy sets as equivalent, more permissive, less permissive or incomparable, and flags shadowed permits, impossible conditions, forbid overrides and complete denials. When analysis confirms a property "it guarantees this holds true for all possible scenarios", and a reported violation means a real scenario exists ([AWS Open Source Blog](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/)).
- The Lean model states "sound and complete symbolic compilation" and "sound and complete verification" ([cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)). The paper reports an average of 75.1 ms to encode and solve ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)).

A request environment is one (principal type, action, resource type) triple. **Proposal:** Run every gate over every environment from `schema.request_envs()` and fail if any environment fails. Otherwise a gate can pass vacuously on the environments it happened to check.

### What each query proves

| Query | Proves | Useful for |
|---|---|---|
| `check_never_errors(P)` | No request in the environment makes P hit a runtime error | Catching attribute access on optional fields, bad extension calls |
| `check_always_allows(P)` | Every request in the environment is allowed | *Negative* use: a high-risk action must **not** be always-allowed |
| `check_always_denies(P)` | Every request is denied | Detecting dead policies; proving a forbidden action is unreachable |
| `check_implies(P1, P2)` | Every request P1 allows, P2 also allows (P1 ⊆ P2) | Narrowing and ceiling gates |
| `check_equivalent(P1, P2)` | Same decision on every request | Refactors and TOML re-compilation must not change meaning |
| `check_disjoint(P1, P2)` | No request is allowed by both | Tenant isolation |

### The six merge-blocking gates (Proposal, from the report)

| Gate | SymCC query | Blocks merge when |
|---|---|---|
| Learned or edited policy is a narrowing | `check_implies(P_new, P_old)` | Not implied; counterexample requests are shown to the reviewer as the "expansion delta" |
| Org ceiling holds | `check_implies(P_new, P_ceiling)` | Any request permitted by the new policy but not by the ceiling |
| Credential confinement | `P ∧ credential.use ∧ dest ∉ allowlist_X` is unsatisfiable, for every brokered secret X | Satisfiable |
| No runtime errors | `check_never_errors` | Any error path |
| Deny rules stay live | Shadowed-forbid and always-allows checks for high-risk actions (`pkg.publish`, `pr.merge`, `git.push` with force) | Shadowed forbid, or always-allow on a high-risk action |
| Tenant isolation | `check_disjoint` between tenants' credential grants | Overlap |

This is Progent's narrowing-versus-widening check, where an SMT query decides whether a policy update narrows (automatic) or widens (needs approval) ([arXiv 2504.11703](https://arxiv.org/html/2504.11703v3)), re-hosted on an analyzer with proved soundness and completeness ([[Progent]]).

### Gate semantics in the review workflow

**Proposal:**

- **Narrowing passes → auto-mergeable** after a human glance. A narrowing can break a task but cannot add authority.
- **Narrowing fails, ceiling passes → human review required.** The PR shows the counterexample requests as a concrete authority diff ("this change newly permits `http.POST api.github.com/repos/acme/web/issues/{n}/comments`"). This is the only way a widening ships ([[I3 Probabilistic Components Only Narrow]]).
- **Ceiling, confinement, errors, live-deny or tenant gate fails → hard block.** No override flag exists. Changing the ceiling itself is an org-scope change with its own review.
- **Repository policy** is gated as `check_implies(P_repo ∧ P_org, P_org)`, the CLAUDE.md minimum test for [[I4 Repo Policy Only Narrows]]. Composing policy sets is a union of permits and forbids, so "repo ∧ org" is computed by adding the repo's policies to the org set and checking the result is still implied by the org set alone.

### Encoding credential confinement

From the evaluation research note. For each brokered credential X, build a reference policy `P_ref_X` that permits `credential.use` on X only when the destination is in X's allowlist. Then check `check_implies(P, P_ref_X)` restricted to the `credential.use` environment, or equivalently that `P ∧ ¬P_ref_X` is unsatisfiable. A counterexample is the offending request. Sketch (**Proposal; not compiled**):

```cedar
// P_ref for the GitHub App credential
permit (principal, action == Broker::Action::"credential.use",
        resource == Broker::Credential::"github_app:acme")
when { ["github.com", "api.github.com"].contains(context.dest_host) };
```

The runtime ceiling in [[Example Cedar Policies]] (`forbid ... unless { resource.allowed_hosts.contains(context.dest_host) }`) makes this gate pass by construction, *provided* the entity data is correct. The gate proves the policy text. A separate data check must confirm that `allowed_hosts` in `entities.json` matches issuer config.

### CI invocation (Proposal)

```text
broker policy check --bundle ./bundle --baseline ./bundle@main --ceiling ./org/ceiling.cedar
  → validate schema + policies
  → for env in schema.request_envs():
        never_errors(P_new); implies(P_new, P_ceiling); implies(P_new, P_old) [report only]
        for X in credentials: implies(P_new|credential.use, P_ref_X)
        for a in HIGH_RISK: !always_allows(P_new|a); forbid-shadowing check
  → for (t1, t2) in tenant pairs: disjoint(grants_t1, grants_t2)
  → emit JSON report + counterexamples; exit non-zero on any hard failure
```

The same command runs in the customer's policy-repo CI and inside `brokerd` before a bundle is activated. A bundle that fails is never loaded ([[Control Plane and Policy Bundles]]).

## Limits

What a passing gate does **not** prove:

1. **Not the enforcement point.** The proof covers policy semantics, not how the proxy parses host, SNI, IP or redirects into entities. Conformance categories 4, 6, 7 and 8 are tested empirically in [[L1 Conformance Suite]].
2. **Schema-relative.** Results hold relative to the schema and request environment. A schema admitting non-canonical host strings gives proofs about the wrong thing, hence [[Hostname Canonicaliser]] runs first.
3. **`like` is string matching,** not DNS semantics: `*.example.com` versus `example.com.` or IDNA forms must be canonicalised before evaluation.
4. **No information flow.** "Data from file F never leaves" is not expressible; Cedar checks only the labels in context ([[Trifecta Session Labels]]).
5. **Narrowing is not correctness.** A narrowing can still be wrong (it may block needed work, or keep an old over-grant). The ceiling and human review cover that.

> [!question] Unverified
> The record found no official list of Cedar features that SymCC does not support, no documented scalability limits, and no peer-reviewed SymCC paper (only the 2025 blog). Whether the analysis CLI is Lean-verified end to end is unconfirmed. See [cedar issue #1385](https://github.com/cedar-policy/cedar/issues/1385) and [[Open Questions and Unverified Claims]]. Measure solve time on a realistic learned policy before promising "seconds in CI".

## How it connects

- depends-on:: [[Cedar]]
- depends-on:: [[Broker Cedar Schema]]
- implements:: [[I3 Probabilistic Components Only Narrow]]
- implements:: [[I4 Repo Policy Only Narrows]]
- motivated-by:: [[Progent]]
- part-of:: [[Evaluation Harness]]
- part-of:: [[Policy Learning Loop]]
- depends-on:: [[Policy Miner Safeguards]]
- part-of:: [[Control Plane and Policy Bundles]]
- decided-by:: [[ADR-011 Verified Policy Learning Loop]]
- delivered-by:: [[M2 Policy Audit and Learn]]
- contrasts-with:: [[AWS AgentCore]] (NL-to-Cedar checked by analysis, but no narrowing-against-previous gate described)

## Implications for the build

- M2 acceptance: "every learned change passes the narrowing or ceiling gates or shows counterexamples" ([[M2 Policy Audit and Learn]]). Wire this command before writing the miner.
- Pin cvc5 1.3.1 in CI and record the version in each report; a solver change is a toolchain change.
- Keep `policies/` gate specs (ceiling, high-risk action list, credential allowlists) under `code/policies/` so they are versioned with the bundle.
- Add a regression corpus of deliberately widening diffs; each must fail with a counterexample.
- Recompiling [[broker.toml Human Policy Layer]] must pass `check_equivalent` against the previous compile when the TOML did not change.

## Open questions

- How long does a full gate run take on 1,000 policies and 50 credentials? No figure is in the record.
- Can shadowed-forbid detection be done with symcc alone, or does it need the Cedar Analysis CLI?
- Should the narrowing gate compare against the last *shipped* bundle or the last *merged* policy?

## Sources

- [docs.rs cedar-policy-symcc](https://docs.rs/cedar-policy-symcc)
- [AWS Open Source Blog: Cedar Analysis](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/)
- [cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)
- [arXiv 2403.04651](https://arxiv.org/html/2403.04651)
- [Progent](https://arxiv.org/html/2504.11703v3)
- [cedar issue #1385](https://github.com/cedar-policy/cedar/issues/1385)
- [AWS Security Blog: AgentCore Policy](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)
