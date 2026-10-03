---
title: "ADR-044 Grant JWT Deferred Until a Remote Mode Exists"
aliases: ["ADR-044"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/identity, topic/credentials, platform/ci, milestone/m3]
status: built
confidence: medium
created: 2026-10-03
updated: 2026-10-03
summary: "The Txn-Token-shaped, DPoP-bound grant JWT (Internal Grant JWT) is not built in M3: every shipped mode, CI included, runs the sandbox and the broker on one host, where the grant stays policy inside the broker and nothing token-shaped crosses a boundary. It is built together with the first mode that separates them (CI sidecar or gateway mode), whose ingress is what would verify it."
related: ["[[Internal Grant JWT]]", "[[ADR-008 Grant Representation as Entities and Txn-Token JWT]]", "[[ADR-031 CI Identity as Built]]", "[[M3 CI Identity and MCP]]", "[[DPoP and mTLS-Bound Tokens]]", "[[Netguard Ingress]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
---

# ADR-044 Grant JWT Deferred Until a Remote Mode Exists

> No grant token is built until there is a second host to carry it to.

## Status

built (2026-10-03, M3): the deferral is the decision; nothing is implemented.

## Context

[[ADR-008 Grant Representation as Entities and Txn-Token JWT]] keeps the grant inside the broker on one host and has it travel as a Txn-Token-shaped JWT, sender-constrained with DPoP, "once the sandbox and the broker are on different hosts (CI sidecar or cloud 'gateway mode')" ([[Internal Grant JWT]]). The [[M3 CI Identity and MCP]] checklist lists `crates/grant/src/txn_token.rs` and `dpop.rs` for "the CI sidecar case where sandbox and broker may be on different hosts".

As built, CI mode ([[ADR-031 CI Identity as Built]]) runs `brokerd` and the sandbox on the same runner: the agent reaches the broker over the session's loopback or Unix-socket channel, which carries no grant, and the broker decides from its own compiled policy. No shipped mode separates the two, so no ingress exists that would receive or verify such a token. A token format and verifier with no caller would be untested security code: an attack surface with no user. None of M3's acceptance criteria (D1 to D7) depends on it.

## Decision

1. The Internal Grant JWT (`txn_token.rs`, `dpop.rs`) is not built in M3. Its design note stays `proposal` and remains the specification.
2. It is built together with the first mode in which the sandbox and the broker run on different hosts, as part of that mode's ingress, which must refuse every connection without a valid token and DPoP proof (fail closed) before any policy is evaluated.
3. Until then, nothing in the broker accepts a grant from outside its own process: the only grant is policy compiled inside `brokerd`.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Build the token and verifier now | No caller: untested parser and crypto paths with no ingress to exercise them, and a format likely to change with the remote mode's transport (DPoP vs mTLS SVID). |
| Mark M3 blocked on it | It specifies a deployment shape M3 does not ship; the milestone's acceptance criteria are all met without it on one host. |
| Drop it from the design | The cross-host case is real (CI sidecars, gateway mode, [[Cloud Sandbox Runtimes]]); the note keeps the design ready. |

## Consequences

- M3 no longer waits on the grant JWT; its remaining items are D2 against real Okta and Entra tenants and D6 against a real AWS account (owner resources).
- A remote mode cannot ship without this ADR's item 2; the Risk Register's honeypot and confused-deputy rows apply to that mode's ingress when it is designed.
- [[Netguard Ingress]] keeps accepting only the session's own local channel.

## Invariants affected

None weakened: the decision adds no surface. I1 and I7 are upheld by construction (no token travels; no foreign credential is accepted).

## Relationships

- decided-by:: M3 review (2026-10-03)
- narrows:: [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]
