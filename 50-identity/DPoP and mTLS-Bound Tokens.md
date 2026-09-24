---
title: "DPoP and mTLS-Bound Tokens"
aliases: ["DPoP", "RFC 9449", "RFC 8705", "Sender-Constrained Tokens"]
type: "standard"
section: "identity"
summary: "Sender-constrained tokens (DPoP RFC 9449 via cnf.jkt; mTLS RFC 8705 via cnf.x5t#S256) that make a stolen token useless without the key; used to bind the internal grant to the issuing sandbox."
tags: [sandbox/identity, standard, topic/credentials, topic/tls, control/task-tok, control/cred-out, boundary/tb3, invariant/i1, milestone/phase2]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
related: ["[[Internal Grant JWT]]", "[[Netguard Ingress]]", "[[Transaction Tokens and Agent Auth Drafts]]", "[[I1 No Secrets in the Sandbox]]", "[[Architecture Overview]]", "[[Cloud Sandbox Runtimes]]", "[[Open Questions and Unverified Claims]]", "[[Tech Stack]]", "[[I6 Single Canonicaliser]]", "[[M1 Secrets Outside]]"]
---

# DPoP and mTLS-Bound Tokens

Sender-constrained tokens bind an access token to a key the legitimate holder possesses, so a stolen token is useless without that key. DPoP (RFC 9449, 2023) binds via a per-request signed `DPoP` proof JWT and a `cnf.jkt` thumbprint in the token; mTLS-bound tokens (RFC 8705, 2020) bind via the client certificate's hash in `cnf.x5t#S256`. The broker uses them to bind its internal grant to the issuing sandbox when sandbox and broker are on different hosts, so a leaked grant or sentinel cannot be replayed from elsewhere.

## DPoP (RFC 9449)

- The client sends a `DPoP` HTTP header carrying a signed JWT proof per request, with claims `htm` (HTTP method), `htu` (HTTP URI), `iat` and `jti`; the access token is bound through `cnf.jkt`, the thumbprint of the client's public key ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)).
- The resource server checks that the proof's key matches `cnf.jkt`, that `htm`/`htu` match the actual request, that `iat` is fresh and that `jti` has not been seen (replay).
- From the RFC text, not extracted in the record (confirm before coding): the proof header has `typ: dpop+jwt` and embeds the public `jwk`; an `ath` claim carries a hash of the access token when a token is presented; the token type in `Authorization` is `DPoP` rather than `Bearer`; servers can supply a `DPoP-Nonce`.

Illustrative proof payload (claim names from the record):

```json
{ "htm": "POST", "htu": "https://broker.internal/egress", "iat": 1790000123, "jti": "5c1f…" }
```

## mTLS-bound tokens (RFC 8705)

- The token carries `cnf.x5t#S256`, the SHA-256 thumbprint of the client certificate; the resource server compares it with the certificate presented in the TLS handshake ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)).
- Binding happens at the transport layer, so there is no per-request signature, but both hops must terminate mutual TLS with the same certificate.

## Choosing between them

| Aspect | DPoP | mTLS-bound |
|---|---|---|
| Binding | application-layer signature per request | TLS client certificate |
| Works through TLS-terminating intermediaries | yes | no (binding lost at termination) |
| Replay defence | `jti` + `iat` (+ nonce) | TLS session |
| Key distribution | one keypair per sandbox, generated in the sandbox | certificate issuance per sandbox (e.g. a SPIFFE X.509-SVID) |
| Cost | one signature per request | one handshake per connection |

## How the broker uses it

**Proposal** (report internal-grant paragraph).

- **Single host (laptop, MVP):** nothing token-shaped leaves the broker; the sandbox holds a per-session sentinel and the grant lives as Cedar entity data. On macOS any local process can reach a loopback port, so the data plane authenticates each session with a sentinel `Proxy-Authorization` value; leaking it grants nothing beyond that session's policy, and only on that host. No DPoP is needed here.
- **Cross host (CI sidecar, cloud gateway mode):** the grant travels as a Transaction-Token-shaped JWT with `"cnf": { "jkt": "<DPoP key thumbprint>" }`, sender-constrained with DPoP, or with mTLS using a SPIFFE SVID, so a leaked grant is useless outside the issuing sandbox ([[Internal Grant JWT]]).
- **Upstream:** tokens stay bearer where providers require it, but they never leave the broker (research note 03 inference).
- **Precedent:** Runloop's "devbox-bound" gateway tokens are opaque tokens useless outside the issuing devbox, with the real credential injected server-side ([Runloop](https://docs.runloop.ai/docs/devboxes/agent-gateways)). A token-invalidation bug on suspend/resume in Runloop's client shows the lifecycle edge to test ([issue #839](https://github.com/runloopai/api-client-ts/issues/839)).

### Where the key lives

The DPoP private key must be inside the sandbox (the sandbox is the sender), which seems to contradict [[I1 No Secrets in the Sandbox]]. It does not: the key is a per-session, sandbox-generated key that authorizes nothing except "this sandbox's own policy, via this broker", exactly like a sentinel. It is not an upstream secret. **Proposal:** generate it inside the sandbox at start (or in the launcher and pass it via an inherited fd, never env or argv), register its thumbprint with the broker in `session.start`, and destroy it at session end.

> [!question] Unverified
> SPIFFE/SPIRE (X.509-SVID, JWT-SVID, node and workload attestation) are treated as background knowledge, not cited facts, in the record ([[Open Questions and Unverified Claims]]). Verify before choosing mTLS-with-SVID over DPoP.

## Verdict for the broker

**Proposal.**

- **Use it for:** binding cross-host grants (CI sidecar, gateway mode) to the issuing sandbox; DPoP by default because it survives the broker's own TLS termination.
- **Don't use it for:** the single-host laptop path (sentinels suffice); upstream providers that only accept bearer tokens.
- **How we integrate it.** In `crates/grant`: DPoP proof verification (ES256 or EdDSA; JOSE crate choice unverified, [[Tech Stack]]), a `jti` replay cache bounded by the grant TTL, `htu` compared against the *canonical* URL from [[I6 Single Canonicaliser]], and `cnf.jkt` checked against the key registered at `session.start`. [[Netguard Ingress]] rejects requests whose proof fails before any policy evaluation.

## How it connects

- part-of:: [[Internal Grant JWT]] (`cnf.jkt` binding)
- depends-on:: [[Netguard Ingress]] (proof checked at ingress)
- depends-on:: [[Transaction Tokens and Agent Auth Drafts]] (grant shape it binds)
- implements:: [[I1 No Secrets in the Sandbox]] (leaked grants are useless off-host)
- depends-on:: [[Architecture Overview]] (cross-host deployment modes)
- example-of:: [[Cloud Sandbox Runtimes]] (Runloop devbox-bound tokens)

## Implications for the build

- Phase 2 (gateway and CI-sidecar modes); M1's "a sentinel copied off-host is useless" is satisfied on a single host by binding sentinels to the session and host ([[M1 Secrets Outside]]).
- Tests when added: replayed proof (same `jti`) rejected; proof for a different `htu` or `htm` rejected; grant presented with another key rejected; clock skew bounds explicit.

## Open questions

- SPIFFE/SPIRE details and the full RFC 9449 header requirements must be read from primary sources ([[Open Questions and Unverified Claims]]).

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
