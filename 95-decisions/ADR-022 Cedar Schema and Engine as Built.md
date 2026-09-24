---
title: "ADR-022 Cedar Schema and Engine as Built"
aliases: ["ADR-022"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, control/egress, control/l7, invariant/i4, invariant/i6, invariant/i8, milestone/m2]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The compiled Broker schema and engine: Host in Domain/HostCategory, Repo in Host, a segmented Path record instead of PathPrefix entities, net.resolve/net.connect for L4 admission, Cedar like semantics for ref globs, a record mode bounded by the org ceiling, conjunctive repo layer, and the M1 tables kept only as the deny-reason explainer and differential oracle."
related: ["[[Broker Cedar Schema]]", "[[Policy Engine and Entity Builder]]", "[[Example Cedar Policies]]", "[[Policy Learning Loop]]", "[[Policy Miner Safeguards]]", "[[I4 Repo Policy Only Narrows]]", "[[I6 Single Canonicaliser]]", "[[I8 No Flag Disables Isolation]]", "[[ADR-007 Cedar with a TOML Front-End]]", "[[M2 Policy Audit and Learn]]", "[[MOC Decisions]]"]
sources: []
superseded_by:
code: ["code/crates/policy/src/cedar", "code/policies/default.cedar", "code/policies/ceiling.cedar", "code/crates/policy/src/egress.rs"]
---

# ADR-022 Cedar Schema and Engine as Built

> Compile the schema sketch into what `cedar-policy` 4.13 validates and the M0/M1 decisions need, and make every egress and L7 decision a Cedar authorization.

## Status

Built (2026-09-24) with the first M2 step.

## Context

[[Broker Cedar Schema]] is a sketch "not compiled against `cedar-policy`". Porting the M0/M1 allowlists and rule tables to Cedar needed constructs the sketch lacks (L4 admission before DNS, subdomain grants without string patterns on hosts, segment-bounded path globs, address classes) and forced choices on semantics that must stay equal to what M0/M1 shipped.

## Decision

1. **Schema changes from the sketch** (compiled in `crates/policy/src/cedar/schema.cedarschema`, validated strictly together with every default policy):
   - `Domain in [Domain]` and `HostCategory` entities; `Host in [Domain, HostCategory]` with `ip_literal`. A `*.name` grant is `resource in Domain::"name"`; the entity builder gives a host a `Domain` parent for each proper label-boundary suffix, so `*.name` never matches `name` itself, and no policy uses `like` on hosts.
   - `Repo in [Host]` with `authority`, `owner`, `full_name`, `visibility`, so host grants and categories apply to repositories.
   - **No `PathPrefix` entities.** HTTP actions target the `Host`; the path is a context record `Path = { n, s0..s15 }` (plus `path_str`). A path glob compiles to segment equalities, `like` within one segment for `*`, and `n >= k` for a trailing `**`. This keeps "`*` never crosses `/`" exact; `**` is allowed only as the last segment.
   - `net.resolve` and `net.connect` (context `ConnCtx { port, addr_classes }`) for L4 admission: the name and port are authorized before any DNS query, then the classes of every resolved address together.
   - `git.advertise` (the receive-pack ref advertisement), `http.OTHER` (non-standard methods, with the method in context), `pkg.publish`, `pr.create`, `pr.merge`, `issue.comment`, `contents.write`; `port` in `HttpCtx` and `GitCtx`.
   - `Credential.allowed_domains` and `CredCtx.dest_domains`, so the credential ceiling also covers `*.name` credential hosts.
   - Time stays epoch seconds. (`datetime` is a default feature of the Rust SDK 4.13, but SymCC support for it is unverified.)
2. **Default set** (`code/policies/default.cedar`): the credential host ceiling, task expiry, Rule of Two, pinned MCP only, and approval for `pkg.publish` and `pr.merge`. **Ceiling** (`code/policies/ceiling.cedar`): DoH resolvers, paste sites (including `gist.github.com`) and tunnel services, from built-in category lists; enforced in every mode. Every policy carries `@id` and forbids carry `@reason`.
3. **Grants compile to permits** whose IDs name the grant (`user:llm#http`, `user:git#push0`); plain host grants allow every request on their host (M0/M1 semantics).
4. **Credential binding:** the credential of the grant whose permits allowed every action of a request (from Cedar's determining policies), then a `credential.use` Cedar request against the base set.
5. **Ref globs use Cedar `like` semantics:** `*` spans `/`, so `agent/*` now also matches `refs/heads/agent/a/b` (M1 matched one component). This is the design's own example policy.
6. **Record mode** (`broker learn`): permits that apply only when `context.session.mode == "record"` admit public, non-literal HTTPS names and any L7 request on admitted hosts. Default forbids and the ceiling still apply, no credential is bound outside a grant, and the sandbox, proxy and audit are unchanged. The enforce-mode verdict is recorded as `would_deny`.
7. **Repo layer:** conjunctive (`base ∧ repo`); repo scope rejects `credential`, `passthrough` and `addrs`; `credential.use` is decided by the base set only.
8. **Explainer:** the M0/M1 tables no longer decide anything. They name the most specific reason for a Cedar deny that no forbid determined, and are the oracle of a property test that Cedar and the M1 semantics agree.
9. **Address classes per grant:** all resolved addresses must be allowed by one grant's classes, not by the union across grants (strictly narrower than M0 in a multi-grant corner case).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| `PathPrefix` entity hierarchy | Cannot express `*` within one segment (`/repos/*/*/issues`); a record with per-segment conditions can |
| `like` on hosts for `*.name` | String patterns are not DNS semantics; the report forbids it |
| Keep ref globs component-bounded | Needs a ref segment record; the design's example policy and SymCC gates use `like` |
| Record mode that allows everything | Contradicts the ceiling and I8's intent; record stays bounded |
| Evaluate the repo layer as a union | Would let repository content widen (I4) |

## Consequences

- Behaviour changes visible to users: paste sites and tunnels are denied even when granted; `agent/*` covers nested branch names; `**` in the middle of a path pattern is a compile error.
- `broker why` names Cedar policy IDs for allows and forbid reasons or specific explainer reasons for denies.
- Every M0/M1 conformance, pipeline and invariant test passes unchanged on the engine; `cedar_agrees_with_the_reference` (128 generated cases) passes.
- While migrating, `cedar-policy` enabled serde_json's `preserve_order` feature workspace-wide, which changed key order in the audit's canonical JSON. The canonical encoder now sorts keys itself (`order_independent_of_insertion`); logs written by M0/M1 still verify.

## Invariants affected

- [[I6 Single Canonicaliser]]: upheld; entities come only from canonical hosts, paths and repository IDs.
- [[I4 Repo Policy Only Narrows]]: structurally enforced by conjunction plus repo-scope key restrictions (the SymCC gate follows).
- [[I8 No Flag Disables Isolation]]: `broker learn` changes task permits only; sandbox, proxy, credential rules and ceiling are unchanged.
- **Ref-glob widening (decision 5)**: a documented change in what a push rule means; no invariant is weakened.

## Relationships

- decided-by:: [[M2 Policy Audit and Learn]]
- motivated-by:: [[Broker Cedar Schema]]
- supersedes::

## Build log

- 2026-09-24: created and built. Tests: `policy::cedar::tests::*` (golden worked decisions, admission semantics, record mode, repo narrowing, credential ceiling, malformed requests, differential property test), all M0/M1 suites.
- 2026-09-24: record mode narrowed: forced pushes are no longer permitted in record mode (`record#push` requires `!context.force`), found by the force gate of [[ADR-024 Formal Gates as Built]].
