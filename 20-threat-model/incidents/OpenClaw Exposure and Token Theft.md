---
title: "OpenClaw Exposure and Token Theft"
aliases: ["CVE-2026-25253", "OpenClaw"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/credentials, topic/isolation, control/iso, control/cred-out, adversary/a6, boundary/tb3, invariant/i8, evidence/secondary]
status: verified
confidence: low
created: 2026-09-24
updated: 2026-09-24
summary: "21,639 OpenClaw instances were publicly exposed and CVE-2026-25253 let an unvalidated gatewayUrl steal the Control UI token, disable the sandbox and reach host RCE (Jan 2026): the opportunistic-scanner (A6) case."
related: [AUTO]
sources: [AUTO]
---

# OpenClaw Exposure and Token Theft

OpenClaw's Control UI trusted an unvalidated `gatewayUrl` parameter and sent its authentication token to whatever URL it named. Whoever received the token could disable the agent's sandbox and reach remote code execution on the host. At the same time Censys counted 21,639 OpenClaw instances publicly exposed on the internet ([Adversa AI](https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/)). It is the opportunistic-scanner (A6) case, and it shows that a sandbox whose policy can be switched off with a token the agent or a web page can obtain is not a boundary.

## Timeline

- **30 Jan 2026**: CVE-2026-25253 (CVSS 8.8) fixed in OpenClaw 2026.1.29 ([Adversa AI](https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/), citing [GHSA-g8p2-7wf7-98mq](https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq)).
- **31 Jan 2026**: Censys counts 21,639 publicly exposed instances ([Censys](https://censys.com/blog/openclaw-in-the-wild-mapping-the-public-exposure-of-a-viral-ai-assistant)).

> [!question] Unverified
> Details come via the Adversa aggregator; the GHSA itself was not fetched. Other OpenClaw CVEs it names (CVE-2026-24763, CVE-2026-25157, CVE-2026-22708) are not verified.

## What happened

1. The Control UI accepted a `gatewayUrl` parameter without validation.
2. It sent its auth token to that URL, so a crafted link delivered the token to an attacker.
3. With the token, the attacker could reconfigure the agent, including disabling its sandbox.
4. With the sandbox off, agent actions became host code execution ([Adversa AI](https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/)).

In the same weeks, the Moltbook agent social network exposed a Supabase key in client-side JavaScript with RLS disabled, giving read and write access to 1.5M agent API tokens, 35,000+ emails and 4,060 private DMs, and letting anyone rewrite posts other agents consume ([Wiz](https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys)). Malicious ClawHub skills targeted the same ecosystem ([[ClawHavoc Malicious Skills]]).

## Root cause

- **(f) enforcement-layer flaw / (b) credential exposure**: a bearer token leaked to an untrusted endpoint, and the sandbox could be switched off by whoever held that token.
- Exposure: control planes reachable from the internet.
- Adversary **A6** (opportunistic scanner). Boundary: the control channel was reachable from outside the trust zone.

## Impact

Token theft, sandbox disablement and host RCE on vulnerable, exposed instances.

## Stopping control in this design

- **Would have prevented: control plane unreachable from the agent and the network.** **Proposal.** The endpoint control API is JSON-RPC over a per-user Unix socket (mode 0600, peer credentials checked); the sandbox cannot reach it (seccomp blocks new `AF_UNIX` sockets, SBPL denies the path) and it is never bound to a network port ([[Broker CLI and Daemon]]).
- **Would have prevented: policy not changeable from inside.** No token, flag or setting available to the agent or a web page can disable isolation, egress or brokering ([[I8 No Flag Disables Isolation]]); policy changes arrive as signed bundles or local user action.
- **Would have contained: ISO + CRED-OUT.** Bot and API tokens are held by the broker, not in files the agent or a skill can read.

## Regression test

- **Category 9 (proxy bypass / host services)**: from inside the sandbox, attempts to connect to the control socket, to localhost services on the host and to any broker admin endpoint all fail.
- **I8 matrix**: no environment variable, config file in the workspace or request to the data plane can change isolation or egress for the running session.
- **Exposure check**: `brokerd` opens no listening TCP port on non-loopback interfaces; `broker doctor` verifies it.

## How it connects

- example-of:: [[Adversary Classes]]
- mitigated-by:: [[Broker CLI and Daemon]]
- mitigated-by:: [[I8 No Flag Disables Isolation]]
- part-of:: [[Threat Model Overview]]

## Implications for the build

- The macOS data plane uses a loopback port, which any local process can reach; authenticate each session with a sentinel `Proxy-Authorization` value, and make sure that value grants nothing beyond that session's policy.
- The phase-2 control plane authenticates devices with mTLS and never exposes endpoint policy mutation over an unauthenticated channel.

## Open questions

- Secondary aggregation only; unverified sibling CVEs ([[Open Questions and Unverified Claims]]).

## Sources

- [Adversa AI, OpenClaw security](https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/)
- [GHSA-g8p2-7wf7-98mq](https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq) (not fetched)
- [Censys](https://censys.com/blog/openclaw-in-the-wild-mapping-the-public-exposure-of-a-viral-ai-assistant)
- [Wiz, Moltbook](https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys)
