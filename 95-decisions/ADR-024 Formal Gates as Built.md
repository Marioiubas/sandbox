---
title: "ADR-024 Formal Gates as Built"
aliases: ["ADR-024"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, topic/evaluation, invariant/i3, invariant/i4, invariant/i7, milestone/m2]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The SymCC gates as built on cedar-policy-symcc 0.7.0 and cvc5 1.3.1: credential confinement moved into the policy text (entity data is arbitrary to the analyzer), deny-live redefined as forbids-can-fire plus approval and force-opt-in proofs, record mode no longer allows forced pushes, the I4 gate proves a single-set encoding of the runtime conjunction, tenant disjointness deferred."
related: ["[[SymCC CI Gates]]", "[[M2 Policy Audit and Learn]]", "[[I3 Probabilistic Components Only Narrow]]", "[[I4 Repo Policy Only Narrows]]", "[[I7 Reject Foreign Credentials]]", "[[Example Cedar Policies]]", "[[ADR-022 Cedar Schema and Engine as Built]]", "[[Policy Learning Loop]]", "[[Open Questions and Unverified Claims]]", "[[MOC Decisions]]"]
sources: ["https://docs.rs/cedar-policy-symcc", "https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.1"]
superseded_by: 
---

# ADR-024 Formal Gates as Built

> `broker policy check` proves five hard gates and one soft gate over all 24 request environments of the Broker schema with `cedar-policy-symcc` 0.7.0 and cvc5 1.3.1; four details differ from [[SymCC CI Gates]] because the analyzer quantifies over entity data and over every context.

## Status

built (2026-09-24, M2 step 4).

## Context

[[SymCC CI Gates]] proposed six merge-blocking gates. Building them against the compiled policy set of [[ADR-022 Cedar Schema and Engine as Built]] showed:

1. **Confinement cannot rest on entity data.** The runtime forbid `credential-host-ceiling` reads the credential's hosts from `resource.allowed_hosts`. The analyzer treats entity attributes as arbitrary, so `check_implies(P, P_ref_X)` fails (a counterexample simply sets `allowed_hosts` to the destination). The note's "passes by construction, provided the entity data is correct" does not hold for a symbolic proof.
2. **"No always-allow" is too weak for high-risk actions.** Any policy that keeps `task-expiry` is never always-allowing, so an unconditional `pkg.publish` or forced `git.push` permit would pass. The regression test for that gate failed to fail.
3. **Record mode allowed forced pushes.** The `record#l7` permit (M2 step 1) covered `git.push` without looking at `context.force`; the force gate found it.
4. **Repo policy is conjoined at run time**, not unioned, so "add the repo's policies to the org set" (the note's encoding) would reject every useful repository layer.

cedar-policy-symcc 0.7.0 pins `cedar-policy` =4.13.0 (the version in use) and needs cvc5 1.3.1 ([docs.rs](https://docs.rs/cedar-policy-symcc)); the static release builds were fetched from the cvc5 release page and their SHA-256 digests pinned in CI ([cvc5 1.3.1](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.1)).

## Decision

- **Gates** (`code/crates/policy/src/gates/`, feature `gates`), each over every environment in `schema.request_envs()` where it applies:
  - *ceiling* (hard): `implies(P, permit-all ∪ ceiling forbids)`.
  - *credential confinement* (hard): per brokered credential X, `implies(P, P_ref_X)` in `credential.use`, where `P_ref_X` permits X only for its declared hosts and domain suffixes. To make this provable, the compiler now emits a textual forbid per credential, `credential:<id>#confine` (`forbid … resource == Credential::"<id>" unless { [hosts].contains(context.dest_host) || context.dest_domains.containsAny([suffixes]) }`), beside the entity-based ceiling.
  - *never-errors* (hard): `check_never_errors` for every policy (base and repository layer) in every environment its action scope reaches. An erroring forbid is skipped by Cedar, so this is also a deny-rule check.
  - *deny-live* (hard): every forbid with a `@reason` can fire in some environment (`check_never_matches` is false); `pkg.publish` and `pr.merge` are allowed only with `context.session.approved` (`implies(P, approved-only)`); a forced `git.push` is allowed only by a push rule with `force = true` or a plain host grant (uninspected traffic), proved as `implies(P, non-forced ∪ opt-in permits)`.
  - *repo-narrows* (hard, I4): `implies(conjoin(P, R), P)`, where `conjoin` encodes the runtime's "base allows and repo allows" as one set: P, R's forbids, and `repo#layer` = `forbid … unless { cond(r1) || cond(r2) || … }` over R's permits (conditions taken from the Cedar AST). A property test checks the encoding decides like the runtime on generated repository layers.
  - *narrowing* (soft): `implies(P_new, P_old)`; a counterexample is shown as "newly permits: action on host, path, port, session" and means human approval, never an automatic merge (I3).
- **Record mode** narrows: `record#push` permits a push only when `!context.force`; forced pushes are never recorded or learned.
- **Entry points:** `broker policy check [--profile] [--policy] [--baseline] [--repo] [--json]` (exit 0 proved, 2 widens, 1 hard failure, 125 no solver or broker error); `broker suggest` runs the gates on every proposal against the current policy when cvc5 is available and says so when it is not. CI installs cvc5 1.3.1 with pinned digests, sets `BROKER_REQUIRE_SOLVER=1` (a missing solver fails instead of skipping) and checks every shipped profile.
- **Tenant disjointness** is not built: the endpoint has one tenant; it moves to the control plane ([[Control Plane and Policy Bundles]]).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep confinement in entity data and add a separate data check | The proof would then be about a different policy than the one enforced; the textual forbid costs one policy per credential and keeps the entity-based ceiling as defence in depth. |
| Assume entity data via `compile_with_custom_symenv` | The crate documents it as having "no analogue in the Lean" and undocumented invariants; the textual forbid avoids relying on it. |
| Literal "not always-allowed" for high-risk actions | Passes vacuously whenever any unrelated forbid (expiry) exists; the regression corpus showed it. |
| Treat plain host grants as failing the force gate | A plain host grant is spliced at L4; the broker cannot see a push on it, so the policy saying "any action" is the truth. The gate proves nothing else allows a forced push. |
| Run the runtime on the single conjoined set | Would change error semantics (the runtime denies on any repo evaluation error; the single set can short-circuit past one). Kept two-set evaluation; the property test ties them together. |
| Equivalence-based "shadowed forbid" check | A forbid can never be overridden in Cedar; the failure that removes a deny rule is one that can never match or that errors, which the two checks above catch. |

## Consequences

- A full run on a shipped profile is 24 environments and 155-250 solver queries in 0.1-0.2 s (cvc5 1.3.1, Apple M-series). Policy size scaling is still unmeasured beyond these.
- A learned diff always fails the narrowing gate (every proposal adds permits); the report shows one counterexample per affected environment. That is the intended review input, not an error.
- The proofs cover the policy text relative to the schema. Host, path and ref canonicalisation into entities stays the job of the conformance suite.

## Invariants affected

Upholds I3 (a widening is shown, never applied), I4 (proved in the gate, enforced at run time by conjunction), I7/I1 (credential use confined in the policy text). Record mode narrows (forced pushes); no invariant is weakened.

## Relationships

- decided-by:: M2 build
- supersedes::
- motivated-by:: [[SymCC CI Gates]], [[M2 Policy Audit and Learn]] C3

## Build log

- 2026-09-24: created and built. Code: `code/crates/policy/src/gates/{mod,compose,tests}.rs`, `code/crates/policy/src/cedar/compile.rs` (`confinement_policy`, `record#push`), `code/crates/broker-cli/src/cmd/policy.rs` (`check`), `code/crates/broker-cli/src/cmd/suggest.rs`, `.github/workflows/ci.yml`. Tests: `gates::tests::{the_shipped_policy_passes_every_hard_gate, a_learned_widening_shows_counterexamples_and_a_narrowing_is_proved, each_hard_gate_catches_its_regression, the_repository_layer_only_narrows, conjoin_agrees_with_the_runtime}`, `m2_gates::policy_check_proves_flags_widenings_and_blocks_hard_failures`, the C3 assertions in `m2_learn::c1_learned_policy_passes_the_task_and_c2_seeded_injection_is_blocked`.
