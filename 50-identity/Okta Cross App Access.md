---
title: "Okta Cross App Access"
aliases: ["ID-JAG", "XAA", "Cross App Access", "SEP-990", "Okta Agent SSO"]
type: "standard"
section: "identity"
summary: "Identity Assertion JWT Authorization Grant (ID-JAG, XAA, MCP extension SEP-990): exchange the user's identity at the IdP for an ID-JAG that the resource AS redeems after admin policy checks; plus Okta Agent SSO (Aug 2026)."
tags: [sandbox/identity, standard, topic/identity, topic/credentials, topic/mcp, control/task-tok, boundary/tb1, boundary/tb4, milestone/m3, milestone/phase3, evidence/unverified]
status: verified
confidence: medium
milestone: phase3
created: 2026-09-24
updated: 2026-09-25
related: ["[[Entra Agent ID]]", "[[RFC 8693 Token Exchange]]", "[[MCP Authorization Spec]]", "[[Just-in-Time Credential Minting]]", "[[M3 CI Identity and MCP]]", "[[MVP Plan]]", "[[Agent Identity Brokers]]", "[[Control Plane and Policy Bundles]]", "[[Open Questions and Unverified Claims]]"]
---

# Okta Cross App Access

Cross App Access (XAA) is Okta's name for the Identity Assertion JWT Authorization Grant (ID-JAG): a client exchanges the user's enterprise identity at the IdP for a signed ID-JAG whose audience is the target resource's authorization server, and that AS redeems it for a short-lived access token after the IdP has applied admin policy. It became the MCP enterprise-managed authorization extension (SEP-990) with the 2025-11-25 spec. Okta Agent SSO (24 August 2026) additionally registers agents in Universal Directory. The broker uses ID-JAG at task start to get a user-delegated token without an interactive consent screen, narrows it at once, and never lets it into the sandbox.

## The flow

From [WorkOS](https://workos.com/blog/id-jag-cross-app-access) and [oauth.net XAA](https://oauth.net/cross-app-access/) (draft name `draft-ietf-oauth-identity-assertion-authz-grant`, -04 cited December 2025):

1. **Exchange at the IdP.** The client performs an RFC 8693 token exchange at the enterprise IdP, presenting the user's identity (for example an ID token from SSO), and receives an **ID-JAG**: a signed JWT whose audience is the resource's authorization server.
2. **Admin policy at the IdP.** Before issuing, the IdP applies admin policy: the client→app allowlist, scopes and user eligibility.
3. **Redeem at the resource AS.** The client presents the ID-JAG with an RFC 7523 `jwt-bearer` grant at the resource AS, which issues a short-lived access token.

```text
user SSO session ──(1) RFC 8693 exchange──▶ Okta (IdP)
                                            │ (2) admin policy: client→app allowlist, scopes, user
                  ◀──────── ID-JAG ─────────┘
broker ──(3) grant_type=jwt-bearer, assertion=ID-JAG──▶ resource AS ──▶ short-lived access token
```

The exact `requested_token_type` URN for ID-JAG and the claim set of the ID-JAG are defined by the draft and were not extracted in the record; read them from the current draft revision before implementing.

- Okta developer posts from August 2026 show OIDC requesting-app and resource-app integration for XAA ([Okta developer blog, 24 Aug 2026](https://developer.okta.com/blog/2026/08/24/xaa-oidc-resource)); Okta introduced XAA in September 2025 ([Okta developer blog, 3 Sep 2025](https://developer.okta.com/blog/2025/09/03/cross-app-access)).
- ID-JAG is an MCP authorization extension (SEP-990), introduced with the 2025-11-25 spec revision alongside CIMD ([Den Delimarsky](https://den.dev/blog/mcp-november-authorization-spec/); [WorkOS](https://workos.com/blog/id-jag-cross-app-access)); see [[MCP Authorization Spec]].

## Why it matters for agents

- It removes the per-app interactive OAuth consent dance: the enterprise admin decides centrally which clients may reach which apps for which users.
- Okta Agent SSO (24 Aug 2026) registers agents in Universal Directory with short-lived tokens; Cross App Access was adopted as MCP's Enterprise-Managed Authorization extension; Entra Agent ID is GA ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)).
- The residual gap: "Delegation chains inherit the broadest permission unless actively narrowed", and "Only 34% of organizations apply human-grade controls to agents" ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)). Narrowing is precisely the broker's job.

## How the broker uses it

**Proposal** (report "Enterprise identity plugs in at task start").

1. `broker login` performs OIDC device login to Okta; the broker caches the user's session (identity only) outside the sandbox. Audit rows carry the IdP subject and groups ([[M3 CI Identity and MCP]]).
2. At task start, for each upstream the task needs, the broker obtains the *user-delegated* token via ID-JAG (or Entra OBO for Microsoft tenants, see [[Entra Agent ID]]).
3. It **narrows immediately**: request only the scopes the Cedar grant needs, a single `resource`; where the upstream supports further downscoping (STS session policy, GitHub repository selection), apply it.
4. It caches the result only in broker memory, keyed by scope digest; it never enters the sandbox and is never forwarded as-is to an MCP server ([[RFC 8693 Token Exchange]]; [[MCP Authorization Spec]]).
5. At session end it drops the tokens.

In the phased plan, M3 delivers OIDC device login to Okta/Entra dev tenants; phase 3 adds ID-JAG/XAA and Entra Agent ID registration ([[MVP Plan]]).

## Sharp edges

- ID-JAG only works for resource apps whose AS supports the grant; GitHub and AWS use their own minting APIs, so ID-JAG mainly serves SaaS and remote MCP servers.
- Admin policy at the IdP is coarse (app, scope, user); it does not express repo, path or method. The broker's Cedar grant remains the tighter bound.
- The draft revision was still moving in the record's window.

## Verdict for the broker

**Proposal.**

- **Use it for:** obtaining user-delegated tokens for SaaS and remote MCP servers in Okta tenants, without per-app interactive consent; binding every task to an IdP subject.
- **Don't use it for:** GitHub or AWS credentials; forwarding the resulting token into the sandbox or to a different audience; relying on IdP policy for fine-grained scope.
- **How we integrate it.** An `oauth_exchange` issuer mode in `crates/creds` (phase 3) that performs the two legs (RFC 8693 at Okta, then `jwt-bearer` at the resource AS) and returns an `Issued` credential; identity binding (`User` entity with `idp`, `subject`, groups via SCIM) lives in `brokerd` and the control plane ([[Control Plane and Policy Bundles]]).

## How it connects

- contrasts-with:: [[Entra Agent ID]] (Microsoft's OBO equivalent)
- depends-on:: [[RFC 8693 Token Exchange]] (first leg)
- part-of:: [[MCP Authorization Spec]] (SEP-990 extension)
- implements:: [[Just-in-Time Credential Minting]] (identity binding at task start)
- delivered-by:: [[M3 CI Identity and MCP]] (OIDC device login)
- delivered-by:: [[MVP Plan]] (phase 3 ID-JAG/XAA)
- competes-with:: [[Agent Identity Brokers]] (Keycard, Aembit, Arcade build on the same flows)
- depends-on:: [[Control Plane and Policy Bundles]] (OIDC/SCIM identity feed)

## Implications for the build

- M3 test: audit rows carry the Okta subject and groups for every decision.
- Phase 3 test: the ID-JAG and the redeemed token never appear in sandbox env, files or egress to any host except the intended AS and resource.

## Open questions

- Current ID-JAG draft revision (−04 cited Dec 2025) and the full MCP ext-auth extension list as of 2026-07-28 ([[Open Questions and Unverified Claims]]).

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.

## Build log

- 2026-09-25: step 1 of the integration (OIDC device login, identity only) is built generically ([[ADR-034 Device Login as Built]]); the Okta tenant run and ID-JAG are not.
