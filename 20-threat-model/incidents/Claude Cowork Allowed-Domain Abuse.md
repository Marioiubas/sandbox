---
title: "Claude Cowork Allowed-Domain Abuse"
aliases: ["Cowork Incident", "Allowed-Domain Abuse"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/credentials, topic/egress, topic/tls, topic/learning, control/cred-out, control/egress, adversary/a1, boundary/tb4, invariant/i7, invariant/i1, milestone/m1]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "A planted attacker API key was used against the allowlisted api.anthropic.com Files API, so a destination-only allowlist let exfiltration through; fixed by accepting only the VM's provisioned session token."
related: [AUTO]
sources: [AUTO]
---

# Claude Cowork Allowed-Domain Abuse

In Claude Cowork, a file in the user's workspace carried instructions plus an attacker's own Anthropic API key. Claude called Anthropic's Files API with that key, and "the egress proxy checked the destination, saw api.anthropic.com, and let it through" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). The user's data went into the attacker's account on an allowed host. Anthropic's named lesson is the flaw of "the allowlist as a destination filter", and the fix is the rule behind [[I7 Reject Foreign Credentials]]: the proxy accepts only credentials it issued.

## Timeline

- **Described 25 May 2026** in Anthropic's "How we contain Claude" engineering post ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). The post does not give a discovery date in the material extracted for the record.

## What happened

1. Cowork runs Claude in a local VM; egress goes through a MITM proxy with a destination allowlist that includes `api.anthropic.com` (the agent needs it).
2. A file mounted into the workspace contained injected instructions and an attacker-controlled API key.
3. Claude followed the instructions and uploaded data to the Files API, authenticating with the attacker's key.
4. The proxy checked only the destination host, which was allowed, so the upload succeeded into the attacker's account ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).

**Fix.** Credentials stay in the host keychain and never enter the guest; the VM gets a per-session scoped-down token; the MITM proxy "only passes requests carrying the VM's own provisioned session token; an attacker-embedded key is rejected", and it blocks headers enabling server-side fetch ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).

## Root cause

- **(a) untrusted input** plus **(c) egress via an allowed destination**, where the allowlist lacked a credential/identity axis.
- Adversary **A1** (who also supplied the credential). Boundary: TB4.
- The general lesson from research note 04a: real sandbox bypasses were rarely exotic network tricks; the main one was an approved API reached with an attacker's credential, so tests need the "whose token is used on an allowed host" axis, not only destination filtering.

## Impact

Exfiltration of workspace data to an attacker-owned account on a first-party API. Anthropic describes it as a real incident; scope is not quantified in the record.

## Stopping control in this design

- **Would have prevented: I7.** On the L7 path the broker strips every client-supplied `Authorization`, `x-api-key`, cookie and `Proxy-Authorization` header and rejects any request carrying a credential it did not issue; only session sentinels pass, and are swapped for the broker-held key ([[I7 Reject Foreign Credentials]], [[Sentinel Swap Pattern]], [[Credential Injector and Issuers]]).
- **Precondition: TLS termination** for every host where credentials are injected, using a per-session CA, so headers can be inspected ([[TLS Termination and Per-Session CA]]).
- **Would not have been stopped by policy learning.** A learned rule allowing `api.anthropic.com` would not have stopped the attacker-key exfiltration. **Proposal.** The miner excludes any request that carried a foreign credential or tripped the sentinel check, and learns only from trusted-input runs or the intersection of N independent runs ([[Policy Miner Safeguards]]).

## Regression test

[[M1 Secrets Outside]] acceptance: "An attacker-planted API key sent to an allowed host is rejected." For [[Conformance Probe Matrix]] **category 1 (allowed-destination abuse)**:

- foreign bearer token, foreign `x-api-key`, foreign cookie and credentials in the URL userinfo to each allowed LLM and forge host: all rejected with reason "foreign credential";
- a request with no credential to a credential-injected host gets the broker's credential, never a pass-through;
- learn-mode fixture: a run containing a foreign-credential request produces no learned rule from that request.

## How it connects

- mitigated-by:: [[I7 Reject Foreign Credentials]]
- depends-on:: [[TLS Termination and Per-Session CA]]
- mitigated-by:: [[Sentinel Swap Pattern]]
- mitigated-by:: [[Credential Injector and Issuers]]
- mitigated-by:: [[Policy Miner Safeguards]]
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[M1 Secrets Outside]]
- example-of:: [[Claude Code and sandbox-runtime]]

## Implications for the build

- Header stripping and foreign-credential rejection run before Cedar sees the request, and apply to every terminated host, not only hosts with configured injection.
- Also reject credentials in query strings and request bodies for adapters that parse bodies (LLM APIs, MCP).
- Hosts that must stay on L4 passthrough (pinned clients) get no credential injection; document that a foreign credential on such a host cannot be detected, and keep that list minimal.

## Open questions

- Anthropic's post does not enumerate its other proxy vulnerabilities by category ([[Open Questions and Unverified Claims]]).

## Sources

- [Anthropic, How we contain Claude (2026-05-25)](https://www.anthropic.com/engineering/how-we-contain-claude)
