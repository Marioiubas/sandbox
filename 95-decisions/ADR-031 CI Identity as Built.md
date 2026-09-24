---
title: "ADR-031 CI Identity as Built"
aliases: ["ADR-031"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/identity, platform/ci, invariant/i1, invariant/i9, milestone/m3]
status: built
confidence: medium
created: 2026-09-25
updated: 2026-09-25
summary: "A CI runner's OIDC token (requested by the GitHub Action) is passed to `broker run` out of band, verified by brokerd against `[[identity.oidc]]` issuers with keys from OIDC discovery, `jwks_url` or `jwks_file` (RS256 only, exact issuer and audience, expiry), and names the session's principal and every audit row; the token never reaches the agent or any upstream; a token that does not verify refuses the launch. Grant JWT/DPoP and IdP device login are not built."
related: ["[[M3 CI Identity and MCP]]", "[[Internal Grant JWT]]", "[[Audit Recorder and Event Schema]]", "[[Broker CLI and Daemon]]", "[[I1 No Secrets in the Sandbox]]", "[[I5 Config Outside Writable Mounts]]", "[[Amazon Q Extension Compromise]]", "[[MOC Decisions]]"]
sources: ["https://docs.github.com/en/actions/concepts/security/openid-connect", "https://docs.github.com/en/actions/reference/security/oidc", "https://token.actions.githubusercontent.com/.well-known/openid-configuration"]
superseded_by: 
---

# ADR-031 CI Identity as Built

> In CI the session is the workflow run: the runner's OIDC token names it, the broker verifies it, and neither the token nor the job's secrets reach the agent.

## Status

built (2026-09-25, M3 step 3).

## Context

[[M3 CI Identity and MCP]] asks for a GitHub Action that runs agents under the broker with the runner's OIDC token as the identity source (D1), audit rows attributed to the identity (D2 for CI), and no identity token forwarded (D7). GitHub documents the issuer `https://token.actions.githubusercontent.com`, RS256 tokens, the `id-token: write` permission and the `ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN` request with an `audience` parameter ([OIDC concepts](https://docs.github.com/en/actions/concepts/security/openid-connect), [reference](https://docs.github.com/en/actions/reference/security/oidc)); the live discovery document names the key set at `/.well-known/jwks` and only RS256 (checked 2026-09-25).

## Decision

1. **Verification** (`code/crates/grant`): a strict compact-JWS parser (three unpadded base64url parts, object header with a string `alg`, object payload, 16 KiB bound) and RS256 verification with `ring`; `none`, HMAC and every other algorithm are refused before any key is used. An identity token must name a configured issuer exactly, carry the configured audience, be unexpired (60 s leeway on `exp`, `nbf`, `iat`), have a non-empty `sub`, and verify with the issuer's key selected by `kid`.
2. **Trust** comes only from user or org policy: `[[identity.oidc]] issuer`, `audience`, and optionally `jwks_url` or `jwks_file` (a file in the config directory, for air-gapped setups); repository policy may not contain `[identity]`. Keys come from OIDC discovery by default (the document's `issuer` must match), are fetched by the broker (`brokerd::fetch`: canonical host, broker resolution, public addresses only, verified TLS, bounded bodies) and cached for an hour, with one refetch when a cached set lacks the token's `kid`.
3. **Transport**: the GitHub Action requests the token for its `audience` and passes it to `broker run` as `BROKER_IDENTITY_TOKEN`; the CLI moves it into `StartParams.identity_token` (a redacting wrapper) and removes it from the environment it forwards. The daemon verifies it before assembling policy. A token that does not verify, or a token with no configured issuer, refuses the launch.
4. **Attribution**: the session's `User` principal is the token's `sub` with `idp` = the issuer (Cedar can test `principal.owner.idp`); every row's `enduser` is the `sub`; `session.start` records the issuer, subject and claims (repository, ref, workflow, run ID, …). The token itself is not logged.
5. **The Action** (`code/integrations/github-action/action.yml`): removes the token `actions/checkout` persists in `.git/config`, requests the OIDC token, runs `broker run -- /bin/sh -c <command>`. Broker binaries must be installed outside the workspace (the broker refuses binaries inside a writable mount, I5).
6. **D1 fixture** (`code/tests/e2e/ci_untrusted_issue/`) runs in CI (`ci-mode` job): an attacker-authored issue asks for the environment, `.git/config` and a job secret; the scripted agent checks runner tokens and the job secret are absent from its environment, the checkout token is gone, and a hex-passed canary is nowhere in the environment, `/proc`, the workspace, home or `/tmp`; then the audit log must name this run's `repo:<owner>/<repo>:…` subject and run ID.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Put the token in the agent's environment for the agent to present | The token would be a secret inside the sandbox (I1). |
| Fall back to the local user when the token fails | Silent misattribution; fail closed instead. |
| Trust any issuer that serves valid keys | Identity must come from policy-named issuers only. |
| Keep `actions/checkout`'s persisted token | The agent could read and use it; the broker brokers git credentials. |

## Consequences

- CI sessions are attributable to a workflow run; policies can distinguish CI from laptops by `principal.owner.idp`.
- **Not built:** the Txn-Token grant JWT and DPoP binding ([[Internal Grant JWT]], needed only when sandbox and broker run on separate hosts), OIDC device login to Okta and Entra (D2 needs the dev tenants), groups beyond the token's claims, and identity inheritance by pinned MCP server sessions (their rows use the local user; the agent session's `mcp.connect` row carries the identity).

## Invariants affected

Upholds I1 (no identity token or job secret in the agent tree), I5 (binaries and trust configuration outside writable mounts) and I9 (attribution on every row). Weakens none.

## Relationships

- decided-by:: M3 build
- motivated-by:: [[M3 CI Identity and MCP]], [[Amazon Q Extension Compromise]]

## Build log

- 2026-09-25: created and built. Code: `code/crates/grant/src/{jwt,oidc}.rs`, `code/crates/brokerd/src/{fetch,identity}.rs`, `code/crates/brokerd/src/session.rs`, `code/crates/brokerd/src/session/assemble.rs`, `code/crates/brokerd/src/proto.rs` (`Redacted`), `code/crates/broker-cli/src/cmd/run.rs`, `code/crates/policy/src/config.rs` (`[identity]`), `code/integrations/github-action/`, `code/tests/e2e/ci_untrusted_issue/`, `.github/workflows/ci.yml` (`ci-mode`). Tests: `grant::jwt::tests::*`, `grant::oidc::tests::a_runner_token_verifies_and_everything_else_is_refused`, `m3_identity::{a_runner_token_attributes_the_session_and_never_reaches_the_agent, a_token_that_does_not_verify_refuses_the_launch}`; fuzz target `jwt` (5.7 M runs locally); the `ci-mode` job for D1 with the real runner token.
