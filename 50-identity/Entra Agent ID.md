---
title: "Entra Agent ID"
aliases: ["Entra OBO", "Microsoft Entra Agent ID"]
type: "standard"
section: "identity"
summary: "Microsoft Entra Agent ID on-behalf-of: a blueprint obtains T1 via client credentials, the agent identity redeems the user token with requested_token_use=on_behalf_of; no interactive /authorize, admin pre-authorization only; GA."
tags: [sandbox/identity, standard, topic/identity, topic/credentials, control/task-tok, boundary/tb4, milestone/m3, milestone/phase3]
status: verified
confidence: high
milestone: phase3
created: 2026-09-24
updated: 2026-09-25
related: ["[[Okta Cross App Access]]", "[[RFC 8693 Token Exchange]]", "[[Just-in-Time Credential Minting]]", "[[M3 CI Identity and MCP]]", "[[Control Plane and Policy Bundles]]", "[[MVP Plan]]", "[[MCP Authorization Spec]]"]
---

# Entra Agent ID

Microsoft Entra Agent ID gives agents their own directory identities, created from an agent identity **blueprint**, and supports an on-behalf-of (OBO) flow in which the agent identity redeems a user's token for a downstream token. The blueprint first obtains a token T1 with client credentials, then the agent identity calls `/token` with the `jwt-bearer` grant, T1 as its client assertion, the user token as the assertion, and `requested_token_use=on_behalf_of`. Agent identities cannot run interactive `/authorize`, and consent comes only from admin pre-authorization. Entra Agent ID is GA. The broker uses this flow at task start in Microsoft tenants, narrows the result and keeps it outside the sandbox.

## The three-step OBO flow

From [Microsoft Learn](https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow):

**Step 1: blueprint gets T1 (client credentials).**

```text
grant_type       = client_credentials
scope            = api://AzureADTokenExchange/.default
fmi_path         = <agent identity app id>
client_assertion = <managed-identity federated identity credential (FIC)>
```

**Step 2: agent identity redeems the user token (OBO).**

```text
grant_type          = urn:ietf:params:oauth:grant-type:jwt-bearer
client_assertion    = T1
assertion           = <user token Tc>
requested_token_use = on_behalf_of
scope               = <downstream resource scopes>
```

(The `scope` line is standard OBO usage; the record lists the other parameters explicitly.)

**Step 3: Entra validates the linkage.**

| Check | Failure |
|---|---|
| Tc `aud` equals the blueprint client ID | `AADSTS50013` |
| T1 `azp` equals the blueprint | rejected |
| T1 `sub` resolves to the child agent identity | rejected |

Constraints ([Microsoft Learn](https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow)):

- Agent identities **cannot** run interactive `/authorize`; it fails with `AADSTS82014`.
- Consent comes by **admin pre-authorization only**.
- Permission inheritance goes through `InheritDelegatedPermissions`.

## What the linkage buys

- The user token must have been issued *to the blueprint* (Tc `aud`), so an agent cannot redeem arbitrary user tokens it scraped elsewhere.
- T1 proves the agent identity belongs to that blueprint, so a rogue client with a stolen user token cannot impersonate the agent.
- The downstream token is a normal Entra access token for the requested resource: bearer, short-lived, audience-bound.

## Status and context

- Entra Agent ID is GA; Okta Agent SSO (Aug 2026) and Cross App Access form the other enterprise path ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)).
- Windows 11's agent workspace notes that Entra/MSA identity for agents was "coming soon" as of November 2025 ([Microsoft Learn: agentic security](https://learn.microsoft.com/en-us/windows/security/book/operating-system-agentic-security)).
- Same residual problem as Okta: "Delegation chains inherit the broadest permission unless actively narrowed" ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)). `InheritDelegatedPermissions` makes this concrete: an agent can inherit whatever the user delegated unless the broker narrows the requested scopes.

## How the broker uses it

**Proposal** (report "Enterprise identity plugs in at task start"; phase 3 "Entra Agent ID registration").

1. Each broker deployment (or each agent profile) is registered as an agent identity under an org-owned blueprint; the blueprint's FIC is backed by a managed identity or workload identity outside the sandbox.
2. `broker login` obtains the user token Tc with the blueprint as audience (OIDC device login, M3).
3. At task start, `brokerd` runs steps 1–2 for each downstream resource the Cedar grant names, requesting the **smallest** scope set, never `.default` over the user's full delegation.
4. The token lives only in broker memory, keyed by scope digest, and is attached at egress; it is never forwarded as-is to MCP servers ([[MCP Authorization Spec]]).
5. Audit rows carry the Entra subject, the agent identity ID and the task ID.

Because agent identities cannot use `/authorize`, all consent is admin-side, which suits a fleet product: the CISO pre-authorizes the broker's agent identities once, and per-task narrowing happens in Cedar.

## Verdict for the broker

**Proposal.**

- **Use it for:** user-delegated tokens to Microsoft Graph and Entra-protected APIs in Microsoft tenants; binding every task to an Entra subject.
- **Don't use it for:** non-Microsoft upstreams (GitHub, AWS) unless they federate with Entra; interactive consent flows (not supported); inheriting the user's full delegation.
- **How we integrate it.** An `entra_obo` mode of the `oauth_exchange` issuer in `crates/creds` (phase 3) that performs the two token calls with the documented parameters, maps `AADSTS50013` and `AADSTS82014` to explicit `broker why` explanations, and returns an `Issued` credential. Blueprint and agent-identity configuration live in the control plane ([[Control Plane and Policy Bundles]]).

## How it connects

- contrasts-with:: [[Okta Cross App Access]] (IdP-issued assertion grant)
- contrasts-with:: [[RFC 8693 Token Exchange]] (Entra uses jwt-bearer OBO instead)
- implements:: [[Just-in-Time Credential Minting]] (identity binding at task start)
- delivered-by:: [[M3 CI Identity and MCP]] (OIDC device login to Entra dev tenant)
- delivered-by:: [[MVP Plan]] (phase 3 Entra Agent ID registration)
- depends-on:: [[Control Plane and Policy Bundles]]

## Implications for the build

- M3: OIDC device login to an Entra dev tenant; audit rows carry subject and groups.
- Phase 3 tests: mismatched Tc audience yields a clear denial; the OBO token never appears in the sandbox; requested scopes equal the Cedar grant's scopes.

## Open questions

- How Entra Agent ID identities map to per-task scopes at scale (one identity per agent profile vs per task) is not in the record.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.

## Build log

- 2026-09-25: OIDC device login is built generically ([[ADR-034 Device Login as Built]]); the Entra dev-tenant run (and group overage handling) is not.
