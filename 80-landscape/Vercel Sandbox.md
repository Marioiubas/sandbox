---
title: "Vercel Sandbox"
aliases: ["Vercel"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/egress, topic/tls, topic/dns, topic/credentials, platform/cloud]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Firecracker sandbox with a host firewall that transparently redirects TCP and DNS, SNI-matches without termination, terminates only transform/forwardURL domains with a per-sandbox CA; matchers never block, which this broker rejects."
related: ["[[ADR-006 Deny Unmatched L7 Requests]]", "[[ADR-004 Selective TLS Termination with Per-Session CA]]", "[[TLS Termination and Per-Session CA]]", "[[Broker DNS Resolver]]", "[[Topology-Forced Egress]]", "[[Architecture Overview]]", "[[Red-Team Plan]]", "[[Firecracker]]", "[[Cloud Sandbox Runtimes]]", "[[Gap Analysis]]", "[[Hostname Canonicaliser]]", "[[Internal Grant JWT]]", "[[Conformance Probe Matrix]]", "[[Product Thesis]]", "[[ADR-009 Broker-Only DNS Resolution]]", "[[Sentinel Swap Pattern]]"]
sources: ["https://vercel.com/docs/sandbox/concepts/firewall", "https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox", "https://vercel.com/blog/vercel-sandbox-is-now-generally-available", "https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/", "https://fly.io/learn/ai-sandbox-pricing/", "https://vercel.com/blog/one-million-dollar-hacker-challenge-for-vercel-sandbox"]
---

# Vercel Sandbox

> Firecracker sandbox with a host firewall that transparently redirects TCP and DNS, SNI-matches without termination, terminates only transform/forwardURL domains with a per-sandbox CA; matchers never block, which this broker rejects.

## What it is

Vercel's cloud sandbox for running agent and user code, generally available since January 2026 ([Vercel](https://vercel.com/blog/vercel-sandbox-is-now-generally-available)). It runs Firecracker microVMs ([MarkTechPost](https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/); [[Firecracker]]). Its network firewall is the best-documented cloud implementation of selective TLS termination with credential brokering. The key sources are a blog post of 11 Aug 2026 and docs updated 16 Sep 2026.

- **Licence:** closed. AWS BYOC is in private beta ([MarkTechPost](https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/)).
- **Pricing:** $0.128 per active CPU-hour, as checked on 10 Sep 2026 ([Fly.io](https://fly.io/learn/ai-sandbox-pricing/)).

## Architecture teardown

### Isolation and topology

The firewall runs on the host, outside the microVM, and "transparently redirects outbound TCP and DNS traffic… while preserving original destination" ([Vercel blog](https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox)). This is the cloud form of [[Topology-Forced Egress]]: the guest does not need to honour any proxy variable.

### TLS: selective termination

- Ordinary allowed domains are SNI-matched **without** TLS termination.
- Only domains with `transform` (credential brokering) or `forwardURL` (request proxying) rules are terminated, using "a certificate authority unique to the sandbox", created just in time and disposed at stop. "The credential never enters the microVM."
- The CA is mounted into the guest's system store with standard env vars set; a custom CA bundle must trust it.

Sources: [Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall); [Vercel blog](https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox). This is the same L4-by-default, L7-where-needed split the broker adopts ([[ADR-004 Selective TLS Termination with Per-Session CA]], [[TLS Termination and Per-Session CA]]).

### Rules and matchers

- Domain and CIDR rules, updated live without restart; for example `sandbox.update({networkPolicy:'deny-all'})`.
- Matchers work on `path`, `method`, `queryString` and `headers`, with `exact`, `startsWith` or RE2 `regex`. First match wins.
- **Matchers never block.** A request that matches no rule passes unchanged, just without the credential. Restricting paths requires a no-match `forwardURL` to your own proxy.

Source: [Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall).

### `forwardURL` and sandbox identity

A `forwardURL` receives `vercel-forwarded-host/scheme/port/path` headers and a `vercel-sandbox-oidc-token`. Its `aud` is the forwardURL, and it carries `team_id`, `project_id`, `sandbox_id` and `sandbox_name` claims ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)).

### Documented pitfalls

From [Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall):

1. **Domain fronting** (SNI ≠ Host), mitigated by pinning `Host` with `transform`.
2. **`subnets.allow` (raw-IP CIDR rules) bypasses SNI rules and leaves DNS open.**
3. **A catch-all `*` lets SNI-less traffic such as SSH pass unbrokered.**
4. **No brokering on Postgres** (SNI-filterable but not brokerable).

## Strengths

- Transparent, host-side topology; DNS is redirected, not trusted.
- Selective termination that preserves pinned clients and saves CPU.
- A per-sandbox, short-lived CA.
- An OIDC token asserting sandbox identity to downstream services.
- Unusually candid documentation of its own pitfalls.
- A public security challenge: Vercel runs a $1M hacker challenge for its sandbox (per the [blog title](https://vercel.com/blog/one-million-dollar-hacker-challenge-for-vercel-sandbox); terms not reviewed).

## Weaknesses (versus this thesis)

- **Cloud-only and closed.** Not usable on laptops or in self-hosted CI.
- **Allow-if-unmatched semantics.** Method and path rules decorate requests with credentials instead of authorizing them. An agent can still POST anywhere on an allowed domain.
- **Static credentials in `transform`.** No per-task minting.
- **Pitfalls 2-4 are footguns** a neutral broker should make impossible.

## What we reuse and what we reject

| Vercel behaviour | Broker decision |
|---|---|
| Host-side transparent redirect of TCP and DNS | Adopt: topology, not env vars |
| SNI match without termination for plain allowed hosts | Adopt: the L4 fast path |
| Per-sandbox JIT CA, disposed at stop | Adopt: per-session CA ([[TLS Termination and Per-Session CA]]) |
| Matchers never block | **Reject:** unmatched L7 requests on an inspected host are denied ([[ADR-006 Deny Unmatched L7 Requests]]) |
| `subnets.allow` bypasses SNI and leaves DNS open | **Reject:** deny IP-literal CONNECTs by default; the broker resolves DNS ([[Broker DNS Resolver]], [[ADR-009 Broker-Only DNS Resolution]], [[Hostname Canonicaliser]]) |
| Catch-all `*` passes SSH unbrokered | **Reject:** deny SSH and SNI-less protocols by default |
| Domain fronting mitigated by `transform` Host pinning | Adopt a stronger form: require CONNECT target = SNI = `Host`/`:authority` |
| `vercel-sandbox-oidc-token` | Interoperate: identity source for remote-sandbox gateway mode ([[Architecture Overview]]) |
| $1M public challenge | Precedent for the public red-team ring ([[Red-Team Plan]]) |

**Proposal (phase 2):** In remote-sandbox gateway mode, point Vercel's `forwardURL` at the broker. The broker validates the `vercel-sandbox-oidc-token`, maps the sandbox to a task grant ([[Internal Grant JWT]]), and applies its own deny-by-default L7 policy and minting.

## How we differentiate

Deny-by-default L7 authorization within allowed domains, minting per task, laptop and CI coverage, and one policy across Vercel, other clouds and local agents ([[Gap Analysis]]).

## How it connects

- competes-with:: [[Product Thesis]] (in cloud sandboxes only)
- depends-on:: [[Firecracker]]
- example-of:: [[Topology-Forced Egress]]
- example-of:: [[Sentinel Swap Pattern]] (via `transform`)
- Precedent for: [[ADR-004 Selective TLS Termination with Per-Session CA]]
- contrasts-with:: [[ADR-006 Deny Unmatched L7 Requests]] (matchers never block)
- contrasts-with:: [[Broker DNS Resolver]]
- evaluated-by:: [[Conformance Probe Matrix]] (its pitfalls become probes in categories 4, 5 and 7)
- Precedent for: [[Red-Team Plan]]
- Grouped with: [[Cloud Sandbox Runtimes]]

## Implications for the build

- Turn each documented pitfall into a permanent probe: raw-IP CONNECT, SSH on port 22 under a broad allow, SNI ≠ Host, and a request on an L7 host matching no rule (must deny, not pass).
- Write the per-session CA into the sandbox trust bundle only; never the host store (CLAUDE.md non-negotiable).

## Open questions

- Does Vercel's OIDC token include enough context (user, repo) for task-scoped minting, or only sandbox identity?
- How does the firewall handle QUIC? Not in the record.

## Sources

- [Vercel docs: firewall](https://vercel.com/docs/sandbox/concepts/firewall)
- [Vercel blog: a sandbox without a network boundary](https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox)
- [Vercel blog: GA](https://vercel.com/blog/vercel-sandbox-is-now-generally-available)
- [Vercel blog: $1M hacker challenge](https://vercel.com/blog/one-million-dollar-hacker-challenge-for-vercel-sandbox)
- [MarkTechPost, Aug 2026](https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/)
- [Fly.io: AI sandbox pricing](https://fly.io/learn/ai-sandbox-pricing/)
