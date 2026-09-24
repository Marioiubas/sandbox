---
title: "ADR-027 Plain Host Grants Carry No L7 Authority"
aliases: ["ADR-027"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, invariant/i6, milestone/m2]
status: built
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "A plain [[egress]] entry (no protocol, methods, paths, allow or credential) compiles to L4 admission only; it no longer emits an `#any` permit, so on a host another rule terminates it allows no request. Fixes a same-host over-grant that silently disabled method and path rules."
related: ["[[broker.toml Human Policy Layer]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[ADR-022 Cedar Schema and Engine as Built]]", "[[ADR-024 Formal Gates as Built]]", "[[Example Cedar Policies]]", "[[M2 Policy Audit and Learn]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
---

# ADR-027 Plain Host Grants Carry No L7 Authority

> A plain host grant admits a connection and nothing more; request-level authority comes only from rules that say what they allow.

## Status

built (2026-09-24, M2).

## Context

[[broker.toml Human Policy Layer]] specifies that an entry "with no `methods`, no `protocol = \"git\"` and no `credential` compiles to **L4-only passthrough** … It never compiles to 'all methods'", and [[ADR-006 Deny Unmatched L7 Requests]] makes unmatched requests on a terminated host deny. Since M0/M1, and carried into the Cedar compiler of [[ADR-022 Cedar Schema and Engine as Built]], a plain grant compiled to an `#any` permit over every L7 action. That is harmless while the host is spliced, but a host is terminated as soon as any grant for it has rules. A probe showed the effect: with `host = "api.example.org"` plain and `host = "api.example.org"` + `methods = ["GET"]`, the host was terminated and `DELETE` was **allowed** by `user:plain#any`; the read-only rule did nothing. The same permit also made every plain grant a forced-push opt-in for the formal gates ([[ADR-024 Formal Gates as Built]]).

## Decision

- A plain grant compiles to `net.resolve` and `net.connect` permits only.
- The explainer (the M1 tables, now the differential oracle) treats a plain grant as allowing no L7 action, so Cedar and the oracle still agree.
- On a terminated host, only rules that name methods, paths, protocols or git refs allow requests. A host that only plain grants admit stays spliced (no L7 decision is made).
- The force gate's opt-ins are push rules with `force = true` only.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep `#any` and warn when a host has both kinds of entries | A warning does not stop the over-grant; the spec says the opposite. |
| Terminate no host that has a plain grant | Would silently drop the method/path rules and credentials of the other entry. |

## Consequences

- A narrowing: a policy with a plain entry and a rule for the same host now enforces the rule. Anyone relying on the plain entry to "open up" a terminated host must write the methods and paths they need.
- No shipped profile had both kinds of entries for one host; every M0/M1/M2 suite passes unchanged.

## Invariants affected

Tightens fail-closed L7 behaviour (ADR-006); weakens none.

## Relationships

- decided-by:: M2 build
- supersedes::
- motivated-by:: [[broker.toml Human Policy Layer]], [[ADR-006 Deny Unmatched L7 Requests]]

## Build log

- 2026-09-24: built. Code: `code/crates/policy/src/cedar/compile.rs` (no `#any`), `code/crates/policy/src/l7.rs` (`explain`), `code/crates/policy/src/gates/mod.rs` (force opt-ins). Test: `policy::cedar::tests::plain_grants_carry_no_l7_authority`; `cedar_agrees_with_the_reference` still passes (the oracle changed with the compiler).
