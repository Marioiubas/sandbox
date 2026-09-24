---
title: "Transaction Tokens and Agent Auth Drafts"
aliases: ["Transaction Tokens", "Txn-Token", "AAuth", "WIMSE", "draft-ietf-wimse-aims"]
type: "standard"
section: "identity"
summary: "Transaction Tokens (draft-08: minutes-long JWTs with txn, sub, scope, req_wl and immutable tctx in a Txn-Token header) and the unsettled agent drafts (draft-klrc-aiagent-auth replaced by draft-ietf-wimse-aims; AAuth draft-10 with HTTP Message Signatures)."
tags: [sandbox/identity, standard, topic/identity, topic/credentials, control/task-tok, boundary/tb3, boundary/tb4, milestone/phase2, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
related: ["[[Internal Grant JWT]]", "[[RFC 8693 Token Exchange]]", "[[DPoP and mTLS-Bound Tokens]]", "[[Okta Cross App Access]]", "[[Entra Agent ID]]", "[[ADR-008 Grant Representation as Entities and Txn-Token JWT]]", "[[Open Questions and Unverified Claims]]", "[[Tech Stack]]"]
---

# Transaction Tokens and Agent Auth Drafts

Transaction Tokens (draft-ietf-oauth-transaction-tokens-08, 2 March 2026) are minutes-long JWTs that carry the calling identity (`sub`), a transaction ID (`txn`), a `scope`, the requesting workload (`req_wl`) and an optional immutable transaction context (`tctx`) between workloads inside one trust domain, in a `Txn-Token` header. They are the shape the broker's cross-host internal grant copies. Agent-specific IETF work is moving but unsettled: draft-klrc-aiagent-auth was adopted by WIMSE and replaced by `draft-ietf-wimse-aims`, and AAuth (draft-10, August 2026) binds agents to signing keys and signs every request.

## Transaction Tokens (draft-08)

From [draft-ietf-oauth-transaction-tokens-08](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08):

| Claim | Status | Meaning |
|---|---|---|
| `txn` | required | transaction identifier |
| `sub` | required | the principal on whose behalf the transaction runs |
| `scope` | required | what the transaction may do |
| `aud` | required | the trust domain |
| `iat`, `exp` | required | lifetime "on the order of minutes or less" |
| `req_wl` | required | the requesting workload |
| `tctx` | optional | **immutable** transaction context |
| `rctx` | optional | requester context |

- **Issuance:** an RFC 8693 token exchange with `requested_token_type=urn:ietf:params:oauth:token-type:txn_token`; `audience` (the trust domain) and `scope` are required ([draft-08](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08)); see [[RFC 8693 Token Exchange]].
- **Transport:** the `Txn-Token` HTTP header, not `Authorization` ([draft-08](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08)). That leaves `Authorization` free for the upstream credential the broker attaches.
- **Companions:** the individual draft "Transaction Tokens for Agents" (draft-oauth-transaction-tokens-for-agents-04, earlier draft-araut-…) ([datatracker](https://datatracker.ietf.org/doc/html/draft-oauth-transaction-tokens-for-agents-04)) and a BCP draft ([datatracker](https://datatracker.ietf.org/doc/draft-oauth-transactiontokens-bcp)). Their contents were not extracted in the record.

### The broker's grant in this shape

**Proposal; not compiled** (copied verbatim from the report's internal-grant section; see [[Internal Grant JWT]]):

```json
{
  "iss": "https://broker.example/tenant/acme",
  "aud": "broker:acme",
  "sub": "okta|00u1abc",
  "act": { "sub": "agent:claude-code@2.1.x", "act": { "sub": "spiffe://acme/sandbox/7f3c" } },
  "txn": "task-01J9...",
  "scope": "task",
  "tctx": {
    "repo": "github.com/acme/web",
    "branch_prefix": "agent/",
    "allowed": [
      { "method": "GET",  "host": "api.github.com", "path": "/repos/acme/web/**" },
      { "method": "POST", "host": "api.github.com", "path": "/repos/acme/web/pulls" }
    ],
    "labels": { "untrusted_input": false, "sensitive_read": false }
  },
  "iat": 1790000000, "exp": 1790000900,
  "cnf": { "jkt": "<DPoP key thumbprint>" }
}
```

Notes on fit: `exp − iat` = 900 s (15 minutes); `act` nests user → agent → sandbox per RFC 8693; `cnf.jkt` sender-constrains it ([[DPoP and mTLS-Bound Tokens]]); the sketch has no `req_wl`, which draft-08 lists as required, so a conformant implementation must add it (**Proposal:** `req_wl` = the sandbox's workload identity). On a single laptop none of this leaves the broker; the grant is Cedar entity data ([[ADR-008 Grant Representation as Entities and Txn-Token JWT]]).

## Agent-specific drafts

| Draft | Status (per record) | What it does | Broker stance |
|---|---|---|---|
| draft-klrc-aiagent-auth-03 (Kasselman, Lombardo/Amazon, Rosomakho/Zscaler, Campbell/Ping, Steele/OpenAI, Parecki) | last rev 2026-07-06; adopted by WIMSE, **replaced by `draft-ietf-wimse-aims`** (AI Identity Management System) | composes WIMSE, SPIFFE, OAuth, token exchange and Txn-Tokens, adds HITL and observability; no new protocols ([datatracker](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/); [WG repo](https://github.com/ietf-wg-wimse/draft-ietf-wimse-aims)) | track; the broker already composes the same pieces |
| AAuth, draft-hardt-oauth-aauth-protocol-10 | individual, Aug 2026 | agents identified as `aauth:local@domain`, bound to a signing key; every request signed with RFC 9421 HTTP Message Signatures, credential in a `Signature-Key` header; token types `aa-agent+jwt` (Agent Provider), `aa-resource+jwt` (resource; carries agent id and key thumbprint), `aa-auth+jwt` (Person Server or Access Server, bound via `cnf`); resources return an `AAuth-Requirement` header to trigger consent; optional "missions" (scoped, natural-language-described authorization contexts logged by the Person Server); no pre-registration, no bearer tokens ([datatracker](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol); [aauth.dev](https://www.aauth.dev/)) | watch; an `AAuth-Requirement` challenge would map onto the broker's step-up path |
| draft-oauth-ai-agents-on-behalf-of-user-02 (Dissanayaka) | **expired** individual draft, last rev 2025-08-25 | `requested_actor`, `actor_token`, `act` for agent OBO ([datatracker](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/)) | do not build on it |
| draft-ni-wimse-ai-agent-identity-02 | individual | "WIMSE Applicability for AI Agents" ([datatracker](https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/)) | background |

> [!question] Unverified
> The current revision and contents of `draft-ietf-wimse-aims` were not fetched; only the adoption and rename are confirmed ([[Open Questions and Unverified Claims]]).

## Why the broker aligns with Txn-Tokens now

- The report's decision: "Standards-aligned now; offline attenuation needed only for sub-agents" (grant representation row), with Biscuit deferred ([[ADR-008 Grant Representation as Entities and Txn-Token JWT]]).
- Txn-Tokens solve exactly the broker's cross-host problem (propagate who and what inside one trust domain, short-lived, immutable context) and reuse RFC 8693 issuance, so no new protocol is invented.
- The agent drafts are converging on the same components (token exchange, workload identity, Txn-Tokens), so aligning with them now minimises later churn.

## Verdict for the broker

**Proposal.**

- **Use it for:** the cross-host grant format (CI sidecar, gateway mode): Txn-Token claims plus `act` plus `cnf.jkt`, in a `Txn-Token` header on the sandbox→broker hop.
- **Don't use it for:** upstream credentials (upstreams never see it); the single-host MVP path; building on expired or individual drafts.
- **How we integrate it.** `crates/grant`: JWT issue and verify (JOSE crate unverified, [[Tech Stack]]), required-claim validation per draft-08 including `req_wl`, `tctx` treated as immutable (any change means a new token), `exp − iat` ≤ 900 s, and conversion of `tctx.allowed` into Cedar entities through the canonicaliser.

## How it connects

- part-of:: [[Internal Grant JWT]]
- depends-on:: [[RFC 8693 Token Exchange]] (issuance)
- depends-on:: [[DPoP and mTLS-Bound Tokens]] (sender constraint)
- contrasts-with:: [[Okta Cross App Access]] (IdP-issued assertion grant, not an internal token)
- contrasts-with:: [[Entra Agent ID]] (vendor OBO flow)
- decided-by:: [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]

## Implications for the build

- Only gateway and CI-sidecar modes need it (phase 2). Keep the grant type behind the `grant` crate so the representation can change without touching adapters.
- Fuzz the JWT parser and claim validator.
- Re-check the draft revision (and wimse-aims) before freezing the wire format ([[Open Questions and Unverified Claims]]).

## Open questions

- Current revisions of draft-ietf-oauth-transaction-tokens, wimse-aims and the agents companion draft.
- Whether `req_wl` semantics fit a sandbox identity without SPIFFE.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
