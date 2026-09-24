---
title: "I7 Reject Foreign Credentials"
aliases: ["Foreign Credential Rejection"]
type: concept
section: architecture
tags: [sandbox/architecture, concept, invariant/i7, topic/credentials, topic/tls, control/cred-out, control/egress, boundary/tb4, milestone/m1]
status: built
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "The proxy strips every client-supplied Authorization, x-api-key, cookie and Proxy-Authorization header and rejects any credential it did not issue."
related: ["[[Claude Cowork Allowed-Domain Abuse]]", "[[TLS Termination and Per-Session CA]]", "[[Credential Injector and Issuers]]", "[[Conformance Probe Matrix]]", "[[M1 Secrets Outside]]", "[[Policy Miner Safeguards]]", "[[I1 No Secrets in the Sandbox]]", "[[Sentinel Swap Pattern]]", "[[Registry and LLM API Adapters]]", "[[Audit Recorder and Event Schema]]", "[[Vercel Sandbox]]", "[[L1 Conformance Suite]]", "[[ADR-004 Selective TLS Termination with Per-Session CA]]"]
sources: ["https://www.anthropic.com/engineering/how-we-contain-claude", "https://vercel.com/docs/sandbox/concepts/firewall"]
milestone: M1
code: ["code/crates/creds/src/foreign.rs"]
---

# I7 Reject Foreign Credentials

> The proxy strips every client-supplied Authorization, x-api-key, cookie and Proxy-Authorization header and rejects any credential it did not issue.

## Statement

**Proposal.** On every request that takes the L7 path ([[TLS Termination and Per-Session CA]]):

1. Every credential-bearing field supplied by the client is removed before forwarding: `Authorization`, `Proxy-Authorization`, `x-api-key`, `Cookie`, plus any adapter-declared credential location (for example a provider-specific API-key header or query parameter declared by [[Registry and LLM API Adapters]]).
2. If any such field contained a value that is **not** a valid sentinel issued for this session and bound to this destination, the request is **rejected** (not merely stripped), the connection is closed with a broker error, and a `foreign_credential` audit event is written.
3. If the value is a valid session sentinel, it is removed and the [[Credential Injector and Issuers|issuer]] attaches the real (minted or static) credential only after all Cedar requests allow, including `credential.use`.

The only credentials that ever reach an upstream through the broker are ones the broker attached.

## Rationale

- **Claude Cowork.** An attacker-planted API key in a mounted file was used against the allowlisted `api.anthropic.com` to exfiltrate data. Anthropic's fix: a MITM proxy that "only passes requests carrying the VM's own provisioned session token; an attacker-embedded key is rejected" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). See [[Claude Cowork Allowed-Domain Abuse]].
- **Allowlists alone are insufficient.** An allowed domain plus an attacker's own credential is an exfiltration channel to the attacker's account. Research note 03 calls the "sentinel-only" rule "essential".
- **Learning would bake it in.** A learned rule allowing `api.anthropic.com` would not have stopped the Cowork exfiltration (report), which is why [[Policy Miner Safeguards]] exclude requests that carried a foreign credential.
- **Pass-through without credential is the wrong default.** Vercel's matchers "never block": a request that does not match passes unchanged, just without the credential ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)). See [[Vercel Sandbox]].

## How it is enforced

**Proposal.**

- The L7 pipeline in `l7` runs a fixed order: parse, canonicalise, classify, **strip and check credentials**, authorize, inject, re-originate. Step 5 of the report's L7 list is this invariant.
- The sentinel store in `creds` answers `is_valid(session, value, dest_host) -> bool` in constant time. Sentinels are bound to a session and an issuer's `allowed_hosts`.
- On macOS, the loopback `Proxy-Authorization` sentinel authenticates the session to the broker and is consumed by netguard; it is never forwarded ([[Netguard Ingress]]).
- Redirects: on any cross-origin hop, attached credentials are dropped, and the new hop is re-evaluated as a fresh request.
- Audit: every rejection records the header name, destination and session, never the value ([[Audit Recorder and Event Schema]]).

## Scope limit: L4 passthrough

On the L4 fast path the broker cannot see headers, so I7 cannot be checked there. **Proposal.** Hosts on the pinned-client passthrough list receive no credential injection, and the org ceiling should route any host that accepts API-key authenticated writes through the L7 path. The residual risk (a foreign key used on an L4-only host) must be documented in the shipped threat model and tracked as an open question.

## Minimal test

**Proposal.** Probe category 1 of the [[Conformance Probe Matrix]], `tests/conformance/foreign_cred`:

- plant a canary API key in a repo file; have the sandboxed process call an allowed L7 host (an echo server standing in for an LLM API) with `x-api-key: <canary>`: expect rejection, an audit row with reason `foreign_credential`, and zero bytes reaching the echo server;
- send a valid sentinel for a *different* session: rejected;
- send a valid sentinel to a host outside the issuer's `allowed_hosts`: rejected by the `credential.use` forbid;
- send a cookie header to a GitHub API host: stripped and rejected.

This is the [[M1 Secrets Outside]] acceptance criterion "an attacker-planted API key sent to an allowed host is rejected" and part of [[L1 Conformance Suite]].

## What would violate it

- Stripping foreign `Authorization` but forwarding the request anyway (turns the rejection into silent success and hides the attempt).
- Forwarding client cookies "for session continuity".
- Treating a well-formed but unknown bearer token as acceptable because the host is allowlisted.
- Credential locations in query strings or bodies that an adapter does not declare.

## How it connects

- motivated-by:: [[Claude Cowork Allowed-Domain Abuse]]
- contrasts-with:: [[Vercel Sandbox]]
- depends-on:: [[TLS Termination and Per-Session CA]]
- depends-on:: [[Credential Injector and Issuers]]
- implements:: [[Sentinel Swap Pattern]]
- part-of:: [[I1 No Secrets in the Sandbox]]
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[L1 Conformance Suite]]
- delivered-by:: [[M1 Secrets Outside]]
- decided-by:: [[ADR-004 Selective TLS Termination with Per-Session CA]]

## Implications for the build

- Keep the credential-location list per adapter in code with tests; new adapters must declare theirs.
- The check must precede any logging of headers so that raw foreign values are never written anywhere.
- Error responses returned to the sandbox must not echo the rejected value.

## Open questions

- How to detect credentials embedded in bodies (JSON fields, form posts) for arbitrary APIs without an adapter; the record covers headers and adapter-known locations only.
- Whether to reject or strip on first-party hosts that set cookies legitimately during a session (for example registry web flows); default reject.

## Sources

- https://www.anthropic.com/engineering/how-we-contain-claude
- https://vercel.com/docs/sandbox/concepts/firewall
- Report: invariant I7, L7 step 5, M1 acceptance, probe category 1, learning-loop mitigations; research note 03 Q3 inference.

## Build log

- 2026-09-24: built in `creds::foreign` (called before authorization on every terminated request). Canonical test `b4_i7_planted_key_to_allowed_host_is_rejected` (planted `x-api-key`, Bearer, Basic and cookie to the allowed host: 403 `foreign_credential`, nothing reaches the upstream, `broker why` explains); property tests `random_values_are_foreign`, `strip_removes_every_credential_header`; fuzz target `foreign`.
