---
title: "MOC Identity"
aliases: []
type: moc
section: identity
tags: [sandbox/identity, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "No upstream token can say 'this repo, this path, this method, 15 minutes': provider downscoping limits, IETF vocabulary, enterprise IdP flows, MCP authorization and the two credential patterns (sentinel swap, minting)."
related: ["[[GitHub App Installation Tokens]]", "[[AWS STS Session Policies]]", "[[GCP Credential Access Boundaries]]", "[[RFC 8693 Token Exchange]]", "[[RFC 9396 Rich Authorization Requests]]", "[[DPoP and mTLS-Bound Tokens]]", "[[Transaction Tokens and Agent Auth Drafts]]", "[[Okta Cross App Access]]", "[[Entra Agent ID]]", "[[MCP Authorization Spec]]", "[[Sentinel Swap Pattern]]", "[[Just-in-Time Credential Minting]]", "[[MOC Architecture]]", "[[Credential Injector and Issuers]]", "[[Internal Grant JWT]]", "[[ADR-005 Mint Credentials Per Task]]"]
sources: []
---

# MOC Identity

> No upstream token can say 'this repo, this path, this method, 15 minutes': provider downscoping limits, IETF vocabulary, enterprise IdP flows, MCP authorization and the two credential patterns (sentinel swap, minting).

No upstream token can say "this repo, this path, this method, 15 minutes". The broker therefore holds a coarse upstream credential, mints or downscopes it per task wherever the provider allows, and enforces method, path and time on every request itself. The IETF supplies the vocabulary for carrying task scope and the user-to-agent-to-sandbox identity chain; enterprise IdPs (Okta, Entra) plug in at task start and the broker narrows immediately.

Two credential patterns matter: the commodity [[Sentinel Swap Pattern]] (static secret swapped at egress) and the differentiating [[Just-in-Time Credential Minting]].

## Native provider downscoping stops short of the promise

| Target | Finest native scope | Lifetime | Who enforces the rest |
|---|---|---|---|
| [[GitHub App Installation Tokens]] | up to 500 repos, per-category read/write; no branch or path | 1 hour | broker: ref (git smart-HTTP), path, API verb |
| GitHub fine-grained PAT | per repo and permission; no branch or path | up to unlimited | broker; avoid PATs for agents |
| [[AWS STS Session Policies]] | session policy intersected with the role; tags; `SourceIdentity` | 900 s to 43,200 s (1 h chained) | mostly native; broker compiles the session policy |
| [[GCP Credential Access Boundaries]] | Cloud Storage only, <=10 rules, CEL prefix conditions | short-lived | broker for every other service |
| Static SaaS API keys | none | long-lived | the broker's method/path allowlist *is* the scope |

(Table condensed from the report's native-downscoping section.)

## Credential patterns

- [[Sentinel Swap Pattern]] — Per-session sentinel values stand in for secrets inside the sandbox and are swapped for real credentials only on egress to permitted hosts; the placeholder pattern eight products ship in 2026 and this design's static-credential fallback.
- [[Just-in-Time Credential Minting]] — Mint short-lived, audience-bound upstream credentials per task scope digest just before forwarding (GitHub App, STS, OAuth exchange), obtain the user-delegated token from Okta/Entra at task start and narrow it at once; static swap only where providers cannot mint.

## Provider-native downscoping

- [[GitHub App Installation Tokens]] — Installation tokens scoped to up to 500 repos and per-category read/write permissions with a 1-hour TTL and no branch or path scope (omitted fields inherit the whole installation); why fine-grained PATs (possibly unlimited lifetime) are avoided for agents.
- [[AWS STS Session Policies]] — AssumeRole with an inline session policy (<=2,048 chars plus up to 10 ARNs) intersected with the role, 900 s-43,200 s lifetime (1 h when chaining), 50 tags and SourceIdentity in CloudTrail; the best native story, compiled by the broker.
- [[GCP Credential Access Boundaries]] — GCP downscoped tokens: at most 10 rules of availableResource, inRole permission ceilings and CEL prefix conditions, Cloud Storage only; every other GCP service falls back to proxy enforcement.

## IETF vocabulary

- [[RFC 8693 Token Exchange]] — OAuth token exchange with subject_token, actor_token and nested act claims for delegation; the standard way for the broker to swap user plus agent credentials for an audience-specific downstream token instead of forwarding the IdP token.
- [[RFC 9396 Rich Authorization Requests]] — authorization_details arrays of typed objects (locations, actions, datatypes, identifier, privileges): the only standard OAuth structure that can say actions=[GET] on a path, with per-type semantics the broker must interpret.
- [[DPoP and mTLS-Bound Tokens]] — Sender-constrained tokens (DPoP RFC 9449 via cnf.jkt; mTLS RFC 8705 via cnf.x5t#S256) that make a stolen token useless without the key; used to bind the internal grant to the issuing sandbox.
- [[Transaction Tokens and Agent Auth Drafts]] — Transaction Tokens (draft-08: minutes-long JWTs with txn, sub, scope, req_wl and immutable tctx in a Txn-Token header) and the unsettled agent drafts (draft-klrc-aiagent-auth replaced by draft-ietf-wimse-aims; AAuth draft-10 with HTTP Message Signatures).

## Enterprise identity

- [[Okta Cross App Access]] — Identity Assertion JWT Authorization Grant (ID-JAG, XAA, MCP extension SEP-990): exchange the user's identity at the IdP for an ID-JAG that the resource AS redeems after admin policy checks; plus Okta Agent SSO (Aug 2026).
- [[Entra Agent ID]] — Microsoft Entra Agent ID on-behalf-of: a blueprint obtains T1 via client credentials, the agent identity redeems the user token with requested_token_use=on_behalf_of; no interactive /authorize, admin pre-authorization only; GA.

## MCP

- [[MCP Authorization Spec]] — The 2026-07-28 MCP revision: remote servers are OAuth 2.1 resource servers (RFC 9728 metadata, mandatory RFC 8707 resource parameter, audience validation, token-passthrough ban, CIMD over DCR, RFC 9207 iss checks, insufficient_scope step-up) while stdio servers 'retrieve credentials from the environment'; plus the 2025-06-18 security best practices.

## How this section connects

- The patterns are implemented by [[Credential Injector and Issuers]] and recorded in [[ADR-005 Mint Credentials Per Task]].
- The cross-host grant format built from this vocabulary is [[Internal Grant JWT]] ([[ADR-008 Grant Representation as Entities and Txn-Token JWT]]).
- MCP handling (remote client, stdio sentinels, `insufficient_scope` step-up) lives in [[MCP Guard]].
- Identity-centric competitors without an egress sandbox are in [[Agent Identity Brokers]]; see [[MOC Architecture]] for where tokens live.
