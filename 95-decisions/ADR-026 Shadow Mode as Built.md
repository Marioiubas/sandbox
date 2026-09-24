---
title: "ADR-026 Shadow Mode as Built"
aliases: ["ADR-026"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, topic/learning, invariant/i3, invariant/i9, milestone/m2]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Shadow mode as built: `broker policy shadow <file>` activates a candidate broker.toml that every enforce session evaluates beside the enforced policy (mode `shadow`) and logs per decision; it never decides or attaches a credential; `--report` lists what it would tighten or widen; record sessions are never shadowed."
related: ["[[Policy Learning Loop]]", "[[ADR-011 Verified Policy Learning Loop]]", "[[I3 Probabilistic Components Only Narrow]]", "[[Broker Cedar Schema]]", "[[Broker CLI and Daemon]]", "[[M2 Policy Audit and Learn]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
---

# ADR-026 Shadow Mode as Built

> A candidate policy is measured on real sessions before it is enforced: every decision records the candidate's verdict beside the applied one, and nothing the candidate says changes what happens.

## Status

built (2026-09-24, M2 step 6).

## Context

[[Policy Learning Loop]] specifies three modes; `shadow` applies the current policy and logs "both current and candidate policy decisions", and its CLI sketch is `broker policy shadow <bundle>`. Bundles belong to the control plane ([[Control Plane and Policy Bundles]]), which does not exist in M2.

## Decision

- `broker policy shadow <file>` stores a candidate user-scope `broker.toml` in the daemon's state directory (outside every sandbox, I5) after it parses; `--off` removes it; `--report` summarises its effect.
- While a candidate is active, every **enforce** session runs in mode `shadow` (`context.session.mode`, enforce semantics for the applied decision). **Record** sessions are never shadowed.
- The candidate is compiled as profile + candidate (in place of the user layer), with the approved repository layer conjoined as for the real policy. It is evaluated at every admission and every L7 request; each decision row gets `detail.shadow = {allow, differs, reason?, name_only?}` (`name_only` when the enforced policy denied before resolving the name). It never mints or attaches a credential and never forwards anything.
- A candidate that does not compile does not block the session: the session starts, prints a warning and records `shadow.error` on `session.start`; the candidate is not evaluated.
- `broker why` shows the candidate's verdict; `--report` reads the verified chain for the sessions that evaluated this exact candidate (by digest) and lists the requests it would deny that the policy allowed and those it would allow that the policy denied. Enforcing a candidate stays a human step (make it your `broker.toml`).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Wait for bundles | Leaves the loop without its measuring step in M2; a file is the bundle's content. |
| Shadow record sessions too | Record mode relaxes task permits; comparing a candidate against it measures nothing useful. |
| Refuse to start a session when the candidate does not compile | The candidate decides nothing; blocking work on it would punish the user for a draft. The failure is visible and logged. |
| Replace the applied policy after a zero-deny window | An automatic widening; the loop requires human approval (I3). |

## Consequences

- The candidate's verdict is recorded for every request, so a candidate-only deny names the exact request (`broker why`).
- One candidate at a time per user; comparing several candidates needs several passes.
- How long to shadow before enforcing stays open ([[Policy Learning Loop]] open question); the report gives the evidence.

## Invariants affected

Upholds I3 (a candidate never decides and is never promoted automatically) and I9 (shadow verdicts are part of the chained decision rows). Record mode, the ceiling and the sandbox are unchanged.

## Relationships

- decided-by:: M2 build
- motivated-by:: [[Policy Learning Loop]], [[ADR-011 Verified Policy Learning Loop]]

## Build log

- 2026-09-24: created and built. Code: `code/crates/brokerd/src/shadow.rs`, `code/crates/brokerd/src/pipeline.rs`, `code/crates/brokerd/src/l7_pipeline.rs`, `code/crates/brokerd/src/session/assemble.rs`, `code/crates/broker-cli/src/cmd/shadow.rs`, `code/crates/broker-cli/src/cmd/why.rs`, `code/crates/policy/src/cedar/entities.rs` (`Mode::Shadow`). Test: `m2_shadow::a_shadow_candidate_is_logged_but_never_decides` (the enforced policy decides every request; the candidate's tighter and wider verdicts are logged, reported and explained; record sessions and sessions after `--off` carry no shadow verdicts; the chain verifies).
