---
title: "ADR-008 Grant Representation as Entities and Txn-Token JWT"
aliases: ["ADR-008"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/credentials, topic/identity, topic/policy, control/task-tok, boundary/tb3, invariant/i1, invariant/i7, invariant/i9, milestone/m2, milestone/m3, milestone/phase2, milestone/phase3, platform/ci, evidence/conflict, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Represent grants as Cedar entities inside the broker and as a Txn-Token-shaped DPoP-bound JWT across hosts, with Biscuit later for sub-agents; reject Macaroons or Biscuit from day one and opaque handles only."
related: ["[[Internal Grant JWT]]", "[[Broker Cedar Schema]]", "[[Macaroons and Biscuit]]", "[[Transaction Tokens and Agent Auth Drafts]]", "[[DPoP and mTLS-Bound Tokens]]", "[[Revocable Sub-Agent Delegation]]", "[[Open Questions and Unverified Claims]]", "[[RFC 8693 Token Exchange]]", "[[RFC 9396 Rich Authorization Requests]]", "[[Object Capabilities]]", "[[Policy Engine and Entity Builder]]", "[[Netguard Ingress]]", "[[Cloud Sandbox Runtimes]]", "[[MVP Plan]]", "[[I1 No Secrets in the Sandbox]]", "[[I7 Reject Foreign Credentials]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[ADR-005 Mint Credentials Per Task]]", "[[ADR-007 Cedar with a TOML Front-End]]", "[[M3 CI Identity and MCP]]", "[[Architecture Overview]]"]
sources: ["https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08", "https://www.rfc-editor.org/rfc/rfc8693", "https://www.rfc-editor.org/rfc/rfc9449", "https://www.rfc-editor.org/rfc/rfc8705", "https://www.rfc-editor.org/rfc/rfc9396", "https://docs.runloop.ai/docs/devboxes/agent-gateways", "https://github.com/runloopai/api-client-ts/issues/839", "https://doc.biscuitsec.org/getting-started/introduction.html", "https://research.google.com/pubs/archive/41892.pdf", "https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/", "https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol", "http://www.erights.org/talks/thesis/"]
---

# ADR-008 Grant Representation as Entities and Txn-Token JWT

> Represent grants as Cedar entities inside the broker and as a Txn-Token-shaped DPoP-bound JWT across hosts, with Biscuit later for sub-agents; reject Macaroons or Biscuit from day one and opaque handles only.

## Status

**Proposed** (2026-09-24). Grants as entities are delivered with the Cedar schema in M2. The cross-host JWT arrives with CI in [[M3 CI Identity and MCP]] and gateway mode in phase 2. Biscuit comes later, and its phase is in conflict (see below). Not superseded.

## Context

A *grant* is the task-scoped authority the broker computed at `session.start`: the repo, the branch prefix, the allowed method/host/path tuples, the credential bindings, the expiry, and the trifecta labels. It must be representable in two places.

1. **Inside the broker**, where Cedar evaluates it on every request.
2. **Across hosts**, when the sandbox and the broker are on different machines: a CI sidecar, or the phase-2 remote-sandbox gateway ([[Architecture Overview]]).

**Forces.**

- **Revocation and expiry should not require recompiling policy.** If grants are entities, "expiry and revocation are then data updates with no policy recompile" (report schema sketch; [[Broker Cedar Schema]]).
- **On one laptop nothing token-shaped needs to leave the broker.** The sandbox holds only a per-session sentinel. On macOS that sentinel authenticates the loopback data plane as `Proxy-Authorization`, and leaking it grants nothing beyond the session's own policy on that host ([[Netguard Ingress]]).
- **Across hosts, a standards-shaped carrier already exists.** Transaction Tokens (draft-08, March 2026) are short-lived JWTs ("on the order of minutes or less"). They require `txn`, `sub`, `scope`, `aud` (the trust domain), `iat`, `exp` and `req_wl`, and may carry an immutable `tctx`. They are obtained through RFC 8693 exchange and travel in a `Txn-Token` header within one trust domain ([draft-08](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08); [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693); [[Transaction Tokens and Agent Auth Drafts]]). RFC 8693's nested `act` claim expresses the user → agent → sandbox chain ([[RFC 8693 Token Exchange]]).
- **Leaked bearer grants must be useless.** DPoP binds a token to a key through `cnf.jkt` ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)); mTLS-bound tokens use `cnf.x5t#S256` ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705); [[DPoP and mTLS-Bound Tokens]]). Runloop's "devbox-bound" gateway tokens apply the same idea to opaque tokens ([Runloop](https://docs.runloop.ai/docs/devboxes/agent-gateways)). Runloop also shows a token-invalidation bug on suspend and resume ([issue #839](https://github.com/runloopai/api-client-ts/issues/839)).
- **Offline attenuation matters only for delegation.** Biscuit is public-key signed and supports offline attenuation with Datalog caveats ([Biscuit](https://doc.biscuitsec.org/getting-started/introduction.html)). Macaroons chain HMAC caveats, and third-party caveats need discharge macaroons ([Macaroons, NDSS 2014](https://research.google.com/pubs/archive/41892.pdf)). Research note 02 recommended Biscuit between the broker and tool adapters, but found no evaluated use of either for LLM agent tool calls ([[Macaroons and Biscuit]]).
- **Agent auth drafts are unsettled.** draft-klrc-aiagent-auth was adopted by WIMSE and replaced by `draft-ietf-wimse-aims` ([datatracker](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/)). AAuth (draft-10, August 2026) signs every request with HTTP Message Signatures ([datatracker](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol)).
- **RAR is the only OAuth structure for method-and-location scopes.** RFC 9396 `authorization_details` can express method and location scopes, but its semantics are per type ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396); [[RFC 9396 Rich Authorization Requests]]).

> [!warning] Conflict
> The report's internal-grant section defers Biscuit "to phase 2" for sub-agent delegation, while its later-phases paragraph lists "Biscuit-based sub-agent delegation" under phase 3. Tracked in [[Open Questions and Unverified Claims]] and [[MVP Plan]]. This ADR does not pick the phase. It fixes only that Biscuit is **not** in the MVP.

## Decision

**Proposal.**

1. **In the broker (all modes): a grant is Cedar entity data.**
   - The `Task` entity carries `owner`, `agent`, `repo`, `branch_prefix` and `expires_at` (epoch seconds), and links to `Credential`, `Host`, `PathPrefix` and `Repo` entities.
   - Policies reference these attributes; they never embed per-task literals.
   - Revocation deletes or updates entities. Expiry is enforced by the org forbid `context.session.now >= principal.expires_at` ([[Policy Engine and Entity Builder]], [[ADR-007 Cedar with a TOML Front-End]]).
2. **Same host (laptop): nothing token-shaped leaves `brokerd`.** The sandbox receives only per-session sentinels.
3. **Across hosts (CI sidecar, gateway mode): the grant travels as a Txn-Token-shaped JWT.** The report sketch (**Proposal; not compiled**) has:
   - `iss` (broker tenant) and `aud` (`broker:<tenant>`);
   - `sub` (IdP subject);
   - the nested `act` chain (agent, then SPIFFE sandbox ID);
   - `txn` (task ID), `scope: "task"`, and `tctx` with `repo`, `branch_prefix`, `allowed[{method, host, path}]` and `labels`;
   - `iat`, and `exp` 900 s after `iat`;
   - `cnf.jkt`.

   The receiving broker verifies the signature, audience, expiry and DPoP proof (or the mTLS SVID binding), then **materialises `tctx` as entities**. Cedar remains the only decision point. The JWT is never forwarded upstream, and upstream credentials are minted separately ([[ADR-005 Mint Credentials Per Task]]). Format details live in [[Internal Grant JWT]].
4. **Biscuit is deferred** to the sub-agent delegation phase, where holders need to attenuate offline ([[Revocable Sub-Agent Delegation]]).

Testable form:

- A grant JWT replayed from another key fails DPoP verification.
- A JWT with `exp` in the past or an `aud` for another tenant is rejected before any Cedar call.
- Revoking a task entity denies that task's next request without a policy reload.
- The laptop sandbox's env and files contain no JWT.

## Alternatives considered

| Alternative | Pros | Cons (evidence) | Why rejected |
|---|---|---|---|
| **Macaroons from day one** | Holder attenuation; third-party caveats map onto human-approval discharge | HMAC verification needs the root secret at every verifier; no evaluated agent use; no current need for offline attenuation | Offline attenuation is needed only for sub-agents |
| **Biscuit from day one** | Public-key verification; Datalog caveats for argument constraints; recommended by research note 02 | A second authorization language beside Cedar, and its caveats are not checked by SymCC; no evaluated agent use; not standards-aligned with the OAuth and IdP chain | Deferred; revisit when sub-agents land |
| **Opaque handles only** (Runloop-style devbox-bound tokens) | Simple; nothing to parse; revocable server-side | Cross-host verification needs a lookup to the issuer; carries no standard identity chain for audit; Runloop shows the lifecycle bugs of binding ([issue #839](https://github.com/runloopai/api-client-ts/issues/839)) | Standards-aligned JWT now; opaque sentinels are kept only for the same-host case |
| **RAR `authorization_details` as the grant** | The only OAuth structure for method and location scopes | Per-type semantics; no transport or identity-chain story on its own | Its shape can inform `tctx.allowed`, but not the carrier |
| **AAuth or WIMSE AIMS** | Designed for agents | Drafts unsettled; AAuth is an individual draft | Watch item; revisit when drafts settle |

## Consequences

**Positive.**

- One decision point (Cedar) in every mode; the JWT is only a carrier.
- Expiry and revocation are data operations, cheap and auditable.
- The cross-host format reuses IETF vocabulary (Txn-Token, RFC 8693 `act`, DPoP), which eases IdP and SIEM integration and gives audit rows the full user → agent → sandbox chain.

**Negative.**

- Two representations must stay equivalent. The JWT→entity materialiser is security-critical parsing and must be fuzzed.
- Txn-Tokens are a draft. Claim names or semantics may change before RFC, which would need a version field and migration.
- DPoP key management inside CI sandboxes, and SPIFFE issuance, are not specified in the record; SPIFFE is background knowledge.
- Sub-agent attenuation is unavailable until Biscuit (or an equivalent) lands. Until then, a sub-agent gets its own broker-issued grant rather than an attenuated child.

**Follow-up work.**

- Specify [[Internal Grant JWT]] with a version claim.
- DPoP proof verification with replay protection (`jti` cache).
- A property test that materialised entities never exceed `tctx`.
- A design spike on membrane-style revocation for sub-agents.

## Revisit triggers

- Sub-agent or map-reduce delegation becomes a milestone requirement, which forces the Biscuit decision and the phase-2 versus phase-3 conflict.
- Transaction Tokens advance to RFC with changed claims, or `draft-ietf-wimse-aims` settles on a different agent carrier.
- A single trust domain no longer holds, for example a grant crossing to a third-party gateway. The Txn-Token scope is one trust domain.

## Invariants and components affected

- **Upholds** [[I1 No Secrets in the Sandbox]] (laptop sandboxes hold sentinels only; the cross-host grant is sender-constrained and useless off-host) and [[I7 Reject Foreign Credentials]] (a grant not issued by this broker's tenant is rejected).
- **Upholds** [[I9 Hash-Chained Audit Outside the Sandbox]] (`sub`, `act` and `txn` feed the attribution fields).
- **Weakens none.**
- Components: [[Policy Engine and Entity Builder]], the `grant` crate ([[Internal Grant JWT]]), [[Netguard Ingress]].

## How it connects

- implements:: [[Internal Grant JWT]]
- implements:: [[Broker Cedar Schema]]
- depends-on:: [[Transaction Tokens and Agent Auth Drafts]]
- depends-on:: [[DPoP and mTLS-Bound Tokens]]
- depends-on:: [[RFC 8693 Token Exchange]]
- contrasts-with:: [[Macaroons and Biscuit]]
- contrasts-with:: [[Cloud Sandbox Runtimes]]
- motivated-by:: [[Object Capabilities]]
- motivated-by:: [[Revocable Sub-Agent Delegation]]
- delivered-by:: [[M3 CI Identity and MCP]]

## Implications for the build

- M2: model `Task` and credential bindings as entities from the start, even while the laptop needs no JWT.
- M3: the GitHub Action exchanges runner OIDC for a session grant; the CI broker issues and verifies the JWT.
- Keep `crates/grant` independent of `policy`, so the carrier can change without touching decision code.

## Open questions

- Biscuit phase (2 or 3): a report conflict ([[Open Questions and Unverified Claims]]).
- DPoP versus mTLS with a SPIFFE SVID for the CI sidecar; SPIFFE details are background only.
- Revocation semantics for in-flight upstream tokens when a grant is revoked mid-session. No agent paper evaluates revocation; Miller's caretakers and membranes give the model ([erights.org](http://www.erights.org/talks/thesis/)).
- The current revisions of `draft-ietf-wimse-aims` and the Txn-Token draft.

## Sources

- https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08
- https://www.rfc-editor.org/rfc/rfc8693
- https://www.rfc-editor.org/rfc/rfc9449
- https://www.rfc-editor.org/rfc/rfc8705
- https://www.rfc-editor.org/rfc/rfc9396
- https://docs.runloop.ai/docs/devboxes/agent-gateways
- https://github.com/runloopai/api-client-ts/issues/839
- https://doc.biscuitsec.org/getting-started/introduction.html
- https://research.google.com/pubs/archive/41892.pdf
- https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/
- https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol
- http://www.erights.org/talks/thesis/
- Report: "The internal grant", schema sketch, interfaces (macOS sentinel `Proxy-Authorization`), deployment modes, later phases, decision table row "Grant representation". Research note 03 Q1 inferences, research note 02 Q1.
