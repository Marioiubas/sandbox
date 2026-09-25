---
title: "ADR-034 Device Login as Built"
aliases: ["ADR-034"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/identity, invariant/i1, invariant/i4, invariant/i9, milestone/m3]
status: built
confidence: medium
created: 2026-09-25
updated: 2026-09-25
summary: "`broker login` runs the OIDC device flow (RFC 8628) through brokerd against the `[identity.login]` issuer (discovery endpoints on the issuer's host, public or pinned addresses, verified TLS); the ID token is verified (RS256, exact issuer, audience = client ID, expiry), its subject and groups name every new session and audit row, and groups become Cedar `Group` parents of the `User`. Identity and refresh token live in daemon memory only (the daemon stays up while a login is held); refresh rotates tokens; `required` refuses sessions without a login. Keychain persistence is not built."
related: ["[[M3 CI Identity and MCP]]", "[[ADR-031 CI Identity as Built]]", "[[Okta Cross App Access]]", "[[Entra Agent ID]]", "[[Broker CLI and Daemon]]", "[[Audit Recorder and Event Schema]]", "[[I1 No Secrets in the Sandbox]]", "[[I4 Repo Policy Only Narrows]]", "[[MOC Decisions]]"]
sources: ["https://www.rfc-editor.org/rfc/rfc8628"]
superseded_by: 
---

# ADR-034 Device Login as Built

> On a laptop, the session is the person who signed in: the IdP vouches for the subject and groups, and the broker keeps that proof in memory, never in the sandbox or on disk.

## Status

built (2026-09-25, M3); verified against a stand-in identity provider. The Okta and Entra runs (D2) need their dev tenants.

## Context

[[M3 CI Identity and MCP]] asks for `broker login` with OIDC device login to Okta and Entra, tokens cached "in brokerd memory and keychain", audit rows carrying the IdP subject and groups (D2), and no IdP token forwarded as-is (D7). [[ADR-031 CI Identity as Built]] already verifies OIDC identity tokens for CI. The device flow's details were checked against RFC 8628 on 2026-09-25: `device_code`, `user_code`, `verification_uri`, `expires_in` required, `interval` defaulting to 5 s; the `urn:ietf:params:oauth:grant-type:device_code` grant; `authorization_pending`, `slow_down` (+5 s for all later requests), `access_denied`, `expired_token`; the `device_authorization_endpoint` metadata name; users should check the displayed code matches.

## Decision

1. **Configuration** (user or org policy; repository policy may not contain `[identity]` at all): `[identity.login]` with `issuer`, `client_id` (a public client), `scopes` (must include `openid`; default `openid profile offline_access`), `groups_claim` (default `groups`), `addrs` (pinned addresses), `required`, `max_age` (default 12 h, at most 7 d).
2. **Flow** (`brokerd::login`, messages parsed by `grant::device`): discovery document from the issuer (its `issuer` must match; the device, token and key endpoints must be on the issuer's host); device authorization; polling at the server's interval, honouring `slow_down`; `access_denied` and `expired_token` end the flow with nobody signed in. Requests go through `brokerd::fetch`: canonical host, broker resolution to public addresses only (or the pinned addresses, never metadata or link-local), verified TLS with the user's extra roots.
3. **Verification**: the ID token must verify with the issuer's RS256 key (one key-set refetch on an unknown `kid`), name the configured issuer exactly, carry the client ID as audience and be unexpired. Groups are the string members of the configured claim (at most 200, deduplicated).
4. **State**: the verified identity, the refresh token (if issued) and the endpoints live in daemon memory only. The daemon does not idle-exit while a login is held. At each session start an ID token within 120 s of expiry is refreshed (rotated refresh tokens are kept); a refresh that fails, or names another subject, signs the user out. `broker logout` forgets everything.
5. **Attribution**: a CI identity token (ADR-031) wins; otherwise the login names the session (`User` = subject, `idp` = issuer, parents = `Group` entities), and every audit row carries `enduser` and `enduser_groups` (OCSF `actor.user.groups`). Without a login, sessions are the local user, unless `required`, which refuses the launch.
6. **Never forwarded**: no IdP token or code enters the sandbox, the audit log, an upstream or an MCP server; the access token is discarded unread.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Persist the refresh token in the OS keychain (the plan) | The broker reaches the keychain through `security` / `secret-tool`; on macOS writing a value that way puts it in the process arguments, visible to other local users. Memory only until the broker uses the keychain API directly. |
| Run the flow in the CLI and hand tokens to the daemon | The daemon must refresh anyway; keeping all IdP traffic and tokens in one process is simpler to audit. |
| Trust endpoints on any host the discovery document names | A tampered document could point the broker elsewhere; same-host endpoints and public-only resolution bound it. |
| Fall back silently to the local user when a login expires | Allowed only when `required` is off; with `required` the launch is refused. |

## Consequences

- Laptop sessions are attributable to IdP subjects and groups; Cedar policies (org or repository layer) can require group membership.
- A daemon restart or reboot means signing in again.
- **Not built:** keychain persistence; Okta/Entra runs (need tenants; Entra's group overage claim is not resolved); ID-JAG/XAA and token exchange for upstreams ([[Okta Cross App Access]], phase 3).

## Invariants affected

Upholds I1 (no IdP token in the sandbox), I4 (repository policy cannot configure identity) and I9 (attribution on every row). Weakens none.

## Relationships

- decided-by:: M3 build
- extends:: [[ADR-031 CI Identity as Built]]
