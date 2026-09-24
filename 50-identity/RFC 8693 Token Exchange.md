---
title: "RFC 8693 Token Exchange"
aliases: ["Token Exchange"]
type: "standard"
section: "identity"
summary: "OAuth token exchange with subject_token, actor_token and nested act claims for delegation; the standard way for the broker to swap user plus agent credentials for an audience-specific downstream token instead of forwarding the IdP token."
tags: [sandbox/identity, standard, topic/credentials, topic/identity, topic/mcp, control/task-tok, control/cred-out, boundary/tb4, milestone/m3, milestone/phase3]
status: verified
confidence: high
milestone: M3
created: 2026-09-24
updated: 2026-09-24
related: ["[[Transaction Tokens and Agent Auth Drafts]]", "[[Okta Cross App Access]]", "[[Entra Agent ID]]", "[[Internal Grant JWT]]", "[[Just-in-Time Credential Minting]]", "[[Credential Injector and Issuers]]", "[[MCP Authorization Spec]]", "[[DPoP and mTLS-Bound Tokens]]", "[[GitHub App Installation Tokens]]", "[[AWS STS Session Policies]]", "[[Core Trait Contracts]]", "[[Tech Stack]]", "[[M3 CI Identity and MCP]]"]
---

# RFC 8693 Token Exchange

RFC 8693 (2020) defines an OAuth grant in which a client presents one token (the `subject_token`, optionally with an `actor_token`) to an authorization server and receives a different token for a named audience, resource and scope. Delegation is expressed with a nested `act` claim, and `may_act` says who is allowed to act for the subject. It is the standard way for the broker to turn "this user, via this agent, in this sandbox" into an audience-specific downstream token instead of forwarding the user's IdP token, and it is the transport for Transaction Tokens and for Okta's ID-JAG.

## Request

`POST` to the authorization server's token endpoint with form parameters ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)):

| Parameter | Required | Meaning |
|---|---|---|
| `grant_type` | yes | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | yes | the token representing the party on whose behalf the request is made (the user) |
| `subject_token_type` | yes | a token-type URI for it |
| `actor_token` | no | the token representing the acting party (the agent or broker) |
| `actor_token_type` | with `actor_token` | its type URI |
| `resource` | no | target service URI (RFC 8707 semantics) |
| `audience` | no | logical name of the target service |
| `scope` | no | requested scope |
| `requested_token_type` | no | the token type wanted back |

Illustrative request (parameter names from the RFC; values are examples; token-type URIs such as `…:token-type:jwt` and `…:token-type:access_token` are defined in the RFC but were not extracted in the record):

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<user access or ID token from Okta/Entra>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&actor_token=<broker/agent client assertion>
&actor_token_type=urn:ietf:params:oauth:token-type:jwt
&resource=https://mcp.example.com/
&scope=issues:read
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
```

## Response

Per the RFC text (not extracted in the research record; confirm against the RFC): a JSON body with `access_token`, `issued_token_type`, `token_type`, and optionally `expires_in`, `scope` and `refresh_token`.

## Delegation claims

- **`act`** (actor): identifies the party currently acting; it can nest to record a chain, with the outermost `act` being the most recent actor ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)).
- **`may_act`**: placed in a subject token to name who may act on the subject's behalf ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)).

The broker's internal grant already uses the nested shape (Proposal; see [[Internal Grant JWT]]):

```json
"sub": "okta|00u1abc",
"act": { "sub": "agent:claude-code@2.1.x",
         "act": { "sub": "spiffe://acme/sandbox/7f3c" } }
```

That is user → agent → sandbox, readable by any RFC 8693-aware resource server.

## Where the broker uses it

| Use | Direction | Result | Status |
|---|---|---|---|
| Transaction Token issuance | broker → internal token service | `requested_token_type=urn:ietf:params:oauth:token-type:txn_token`, with `audience` (trust domain) and `scope` required | draft-08 ([draft-ietf-oauth-transaction-tokens-08](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08)); see [[Transaction Tokens and Agent Auth Drafts]] |
| ID-JAG (Okta Cross App Access) | client → enterprise IdP | an ID-JAG JWT whose audience is the resource's AS, then redeemed with an RFC 7523 jwt-bearer grant | [WorkOS](https://workos.com/blog/id-jag-cross-app-access); see [[Okta Cross App Access]] |
| SaaS/MCP downstream tokens | broker → resource AS | audience-bound token for one upstream | **Proposal** (phase 3 "SaaS token exchange") |
| Entra OBO | agent identity → Entra | Entra uses `jwt-bearer` with `requested_token_use=on_behalf_of`, not RFC 8693 parameters | [Microsoft Learn](https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow); see [[Entra Agent ID]] |

The expired individual draft `draft-oauth-ai-agents-on-behalf-of-user-02` proposed `requested_actor`, `actor_token` and `act` for agent OBO (last revision 2025-08-25) ([datatracker](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/)); do not build on it.

## Why exchange instead of forwarding

- MCP forbids token passthrough: clients "MUST NOT send tokens to the MCP server other than ones issued by the MCP server's authorization server", and servers "MUST NOT accept or transit any other tokens" ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)). The 2025 security best practices cite control circumvention, broken audit trails and use of the server as an exfiltration proxy ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)).
- Research-note inference: the broker must *not* forward the user's Okta/Entra token to MCP servers; it should exchange it (ID-JAG/XAA or RFC 8693) for an audience-specific token. The handoff contract makes this non-negotiable ("never forwards a user's IdP token as-is to an upstream or MCP server").
- "Delegation chains inherit the broadest permission unless actively narrowed" ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)); the exchange is the narrowing point, so always request the smallest `scope` and a single `resource`.

## Sharp edges

- The RFC defines the envelope, not the policy: whether an AS honours `actor_token`, `may_act` or narrow `scope` is AS-specific.
- A token obtained by exchange is still a bearer token unless the AS binds it (see [[DPoP and mTLS-Bound Tokens]]); keep it in broker memory only.
- Nested `act` chains are informational to most resource servers; authorization decisions remain the broker's.

## Verdict for the broker

**Proposal.**

- **Use it for:** minting audience-specific downstream tokens from a user's IdP session (never forwarding the IdP token); issuing Transaction-Token-shaped grants across hosts; the ID-JAG first leg.
- **Don't use it for:** GitHub or AWS, which have their own minting APIs ([[GitHub App Installation Tokens]], [[AWS STS Session Policies]]); anything where the target AS does not support it.
- **How we integrate it.** `issuers/oauth_exchange` in `crates/creds` implementing `CredentialIssuer { kind: "oauth_exchange" }` ([[Core Trait Contracts]]); an OAuth client library for form encoding and JWT client assertions (crate choice unverified, [[Tech Stack]]); per-upstream `resource` and minimal `scope` from the Cedar grant; results cached per scope digest, zeroized on session end.

## How it connects

- depends-on:: [[Transaction Tokens and Agent Auth Drafts]] (Txn-Tokens are obtained via exchange)
- depends-on:: [[Okta Cross App Access]] (ID-JAG first leg is an exchange)
- contrasts-with:: [[Entra Agent ID]] (Entra OBO uses jwt-bearer instead)
- part-of:: [[Internal Grant JWT]] (nested `act` chain)
- implements:: [[Just-in-Time Credential Minting]]
- delivered-by:: [[Credential Injector and Issuers]] (`oauth_exchange` issuer)
- implements:: [[MCP Authorization Spec]] (token passthrough ban)

## Implications for the build

- Test: the user's IdP token never appears in any upstream request header or body (scan broker egress in e2e).
- Phase 3 lists "SaaS token exchange"; M3 needs only OIDC device login and runner-OIDC exchange ([[M3 CI Identity and MCP]]).

## Open questions

- Which target SaaS authorization servers accept `actor_token` is not in the record.
- Response parameter details must be confirmed from the RFC text.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
