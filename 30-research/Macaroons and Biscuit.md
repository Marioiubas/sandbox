---
title: "Macaroons and Biscuit"
aliases: ["Macaroons", "Biscuit", "Attenuable Tokens"]
type: concept
section: research
tags: [sandbox/research, concept, topic/credentials, topic/identity, milestone/phase2, milestone/phase3, evidence/conflict, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Attenuable bearer tokens: Macaroons (chained HMAC caveats, third-party discharge) and Biscuit (public-key signed, offline attenuation, Datalog caveats); deferred to later phases for sub-agent delegation."
related: ["[[Object Capabilities]]", "[[ADR-008 Grant Representation as Entities and Txn-Token JWT]]", "[[Internal Grant JWT]]", "[[Revocable Sub-Agent Delegation]]", "[[MVP Plan]]", "[[DPoP and mTLS-Bound Tokens]]", "[[Transaction Tokens and Agent Auth Drafts]]", "[[Design Patterns for Securing LLM Agents]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[Open Questions and Unverified Claims]]", "[[Broker Cedar Schema]]", "[[Progent]]", "[[I3 Probabilistic Components Only Narrow]]"]
sources: ["https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/macaroons-cookies-contextual-caveats-decentralized-authorization-cloud/", "https://research.google.com/pubs/archive/41892.pdf", "https://doc.biscuitsec.org/getting-started/introduction.html", "https://github.com/eclipse-biscuit/biscuit/blob/master/SPECIFICATIONS.md", "https://passthesalt.ubicast.tv/videos/2021-biscuit-pubkey-signed-token-with-offline-attenuation-and-datalog-authz-policies/", "https://docs.runloop.ai/docs/devboxes/agent-gateways", "http://www.erights.org/talks/thesis/"]
---

# Macaroons and Biscuit

Macaroons and Biscuit are bearer tokens that any holder can **attenuate** (add restrictions to) without talking to the issuer, but never widen. They are the token-shaped form of [[Object Capabilities]]. The MVP does not use them: grants live as Cedar entities in the broker and cross hosts as a Transaction-Token-shaped JWT. Biscuit is reserved for sub-agent delegation in a later phase, and the report is inconsistent about which phase.

## Macaroons (NDSS 2014)

**Citation.** Birgisson, Politz, Erlingsson, Taly, Vrable, Lentczner, "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud", NDSS 2014 ([NDSS](https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/macaroons-cookies-contextual-caveats-decentralized-authorization-cloud/); [PDF](https://research.google.com/pubs/archive/41892.pdf)).

**Mechanism.** Macaroons are bearer credentials built from chained HMACs, so any holder can append caveats (attenuate) but never remove them. Third-party caveats require a *discharge macaroon* from a named third party before the token verifies ([NDSS 2014](https://research.google.com/pubs/archive/41892.pdf)).

Illustrative structure (background construction; check against the paper before implementing):

```text
m0 = { id, caveats: [],            sig: HMAC(root_key, id) }
m1 = { id, caveats: [c1],          sig: HMAC(m0.sig, c1) }        # holder attenuates
m2 = { id, caveats: [c1, c2(3P)],  sig: HMAC(m1.sig, c2) }        # third-party caveat
verify(m2, discharge(c2)) at the issuer, which holds root_key
```

Two consequences matter for the broker. Verification needs the **root secret**, so every verifier is as trusted as the issuer. And third-party caveats give a clean hook for "someone else must sign off", which maps onto human approval.

## Biscuit

**Mechanism.** Biscuit (Eclipse Biscuit) is a public-key-signed token that supports offline attenuation, with authorization policies written in a Datalog dialect ([Biscuit intro](https://doc.biscuitsec.org/getting-started/introduction.html); [specification](https://github.com/eclipse-biscuit/biscuit/blob/master/SPECIFICATIONS.md); [Pass the SALT 2021 talk](https://passthesalt.ubicast.tv/videos/2021-biscuit-pubkey-signed-token-with-offline-attenuation-and-datalog-authz-policies/)). Each appended block can only add checks; the verifier evaluates facts, rules and checks together.

The research inference (research note 02, Q1) is that Biscuit suits agents better than Macaroons for two reasons:

1. **Public-key verification** lets a tool adapter verify a token without holding the root secret.
2. **Datalog caveats can encode argument constraints**, the same thing [[Progent]] does in JSON Schema.

Proposed caveat set from the research (inference, not an evaluated design): tool, resource ID, argument constraints, expiry, max-uses, session ID, and an "integrity=trusted-only" flag. Macaroon-style third-party caveats map onto a "human approval discharge".

## Why the MVP does not use them

The report's decision on grant representation ([[ADR-008 Grant Representation as Entities and Txn-Token JWT]]): Cedar entities inside the broker on a single laptop; a Transaction-Token-shaped, DPoP-bound JWT once the sandbox and broker sit on different hosts (CI sidecar, gateway mode); Biscuit later. The alternatives rejected were "Macaroons or Biscuit from day one" and "opaque handles only". The rationale: standards-aligned now, and offline attenuation is needed only for sub-agents.

On one laptop nothing token-shaped needs to leave the broker: the sandbox holds a per-session sentinel, and expiry and revocation are data updates. Across hosts the [[Internal Grant JWT]] carries `sub`, a nested `act` chain, `txn`, and a `tctx` with the task's repo, branch prefix, allowed method/host/path tuples and trifecta labels, sender-constrained with DPoP ([[DPoP and mTLS-Bound Tokens]]); see [[Transaction Tokens and Agent Auth Drafts]]. Runloop's "devbox-bound" gateway tokens rest on the same idea ([Runloop](https://docs.runloop.ai/docs/devboxes/agent-gateways)).

> [!warning] Conflict
> The report's internal-grant section says "Biscuit tokens are deferred to phase 2, for sub-agent delegation", while its later-phases paragraph lists "Biscuit-based sub-agent delegation" in **phase 3**. Tracked in [[Open Questions and Unverified Claims]]. Until an ADR settles it, treat Biscuit as not before phase 2 and not required before phase 3; [[MVP Plan]] owns the schedule.

> [!question] Unverified
> The record found no peer-reviewed paper that applies Macaroons or Biscuit to LLM agent tool calls with an evaluation. The research calls this open space, "not confirmed exhaustively".

## Adopt / Improve / Add

- **Adopt:** The attenuation discipline itself, now: every grant the broker holds can only be narrowed without consent, which is the same invariant as [[Progent]]'s monotonic confinement and [[I3 Probabilistic Components Only Narrow]] extended to tokens. Adopt Biscuit, not Macaroons, as the future delegation format, for public-key verification and Datalog caveats.
- **Improve:** **Proposal:** when Biscuit arrives, derive its first block mechanically from the Cedar grant entities (repo, branch prefix, method/path tuples, expiry, session) so the token and the Cedar policy cannot drift, and run the same SymCC narrowing check on the derived sub-grant.
- **Add:** **Proposal:** third-party-caveat-style "approval discharge": a sub-agent grant that includes a write-class action is inert until the approval UI signs a discharge showing the authority diff ([[Fatigue-Resistant Approval Interfaces]]). Pair with caretaker revocation from Miller's model ([erights.org](http://www.erights.org/talks/thesis/)) so the parent session can cut off every derived token.

## How it connects

- part-of:: [[Object Capabilities]]
- contrasts-with:: [[Internal Grant JWT]]
- decided-by:: [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]
- depends-on:: [[DPoP and mTLS-Bound Tokens]]

[[Revocable Sub-Agent Delegation]] is the open problem this token family would serve; the [[Design Patterns for Securing LLM Agents]] Map-Reduce workers are its first customer. The grant data that a Biscuit would be derived from lives in the [[Broker Cedar Schema]].

## Implications for the build

- MVP (M0 to M4): do not add a Biscuit or Macaroon dependency. Grants are Cedar entities; the cross-host form is the Txn-Token-shaped JWT.
- Keep the grant model attenuation-friendly: every field of a grant should have an obvious "narrower" direction (fewer hosts, shorter expiry, tighter path prefix, fewer methods), so a future token block can express it.
- Write an ADR when the phase question is resolved, and update [[MVP Plan]] and ADR-008 to match.

## Open questions

- Phase 2 or phase 3 for Biscuit sub-agent delegation (report conflict).
- Current state and maturity of Biscuit's Rust library: not in the record; verify before adopting.
- How a Biscuit-held sub-grant interacts with already-minted upstream tokens (the upstream token cannot be attenuated offline; only the broker's grant can).

## Sources

- Macaroons, [NDSS 2014](https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/macaroons-cookies-contextual-caveats-decentralized-authorization-cloud/); [PDF](https://research.google.com/pubs/archive/41892.pdf)
- Biscuit, [introduction](https://doc.biscuitsec.org/getting-started/introduction.html); [specification](https://github.com/eclipse-biscuit/biscuit/blob/master/SPECIFICATIONS.md); [Pass the SALT 2021](https://passthesalt.ubicast.tv/videos/2021-biscuit-pubkey-signed-token-with-offline-attenuation-and-datalog-authz-policies/)
- [Runloop agent gateways](https://docs.runloop.ai/docs/devboxes/agent-gateways)
- Miller, [erights.org](http://www.erights.org/talks/thesis/)
