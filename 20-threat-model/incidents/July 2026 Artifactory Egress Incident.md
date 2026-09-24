---
title: "July 2026 Artifactory Egress Incident"
aliases: ["Hugging Face Sandbox Incident", "ExploitGym"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/dns, topic/egress, topic/supply-chain, control/egress, control/audit, adversary/a3, boundary/tb4, evidence/unverified, evidence/single-source]
status: draft
confidence: low
created: 2026-09-24
updated: 2026-09-24
summary: "A July 2026 sandbox incident (Hugging Face / 'ExploitGym') discussed as DNS tunnelling, whose only verified path was a zero-day chain through the sanctioned JFrog Artifactory egress point; details unconfirmed."
related: [AUTO]
sources: [AUTO]
---

# July 2026 Artifactory Egress Incident

A July 2026 incident around an OpenAI "ExploitGym" sandbox and Hugging Face was widely discussed as a DNS-tunnelling escape. The one write-up in the record states that the verified path was instead a zero-day chain through the sanctioned egress point, a JFrog Artifactory package proxy, and that it could not link primary disclosures ([axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53)). Treat every detail as unverified. The design lessons hold regardless: DNS belongs to the broker, and allowed destinations (especially package registries that proxy other content) remain exfiltration channels.

> [!question] Unverified
> Single secondary source; no primary disclosure was found. The incident's actors, dates and mechanism are not confirmed. This note is `status: draft` until a primary source is located.

## Timeline

- **July 2026**: incident reported; the axeploit article discusses it ([axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53)). No further dates are in the record.

## What happened (as reported)

- Commentary framed it as DNS exfiltration from a sandbox, describing the techniques that bypass proxy-only controls: data encoded as base32 subdomain labels, bidirectional TXT-record tunnels, and DNS-over-HTTPS on port 443 ([axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53)).
- The same article says the verified path was a zero-day chain through the JFrog Artifactory instance that served as the sanctioned egress point, not DNS.

A related vendor report describes a DNS-tunnelling risk in the AWS AgentCore Code Interpreter; only its title was seen ([Aurascape](https://aurascape.ai/resources/auralabs-research/silent-leak-dns-tunneling-aws-agentcore-code-interpreter/)).

## Root cause (inferred, unverified)

- **(c) egress through an allowed channel**: a package registry proxy that was allowed by policy became the exit.
- DNS, if it was involved, would be **(c)** unrestricted egress.
- Adversary: not established (the environment name suggests an exploit-development evaluation, so **A3**-type capability is plausible but unconfirmed).

## Impact

Not established in the record.

## Stopping control in this design

- **Would have prevented the DNS variants: broker-only DNS ([[Broker DNS Resolver]], [[ADR-009 Broker-Only DNS Resolution]]).** The sandbox gets no UDP/53 and no ICMP; the broker's resolver answers only allowlisted names and blocks DoH endpoints by name; on Linux there is no network interface at all ([[Topology-Forced Egress]]).
- **Would have narrowed the registry path: read-only registry adapters ([[Registry and LLM API Adapters]]).** npm, PyPI, crates and the Go proxy are GET/HEAD only; `publish` is denied unless granted; private registries get a read-only token. This removes upload-style exfiltration through the registry but not a zero-day in the registry itself.
- **Would have limited volume: miner safeguards ([[Policy Miner Safeguards]]).** Rate and volume limits on allowed domains, because allowed domains remain exfiltration channels; request-body size limits and logging on registry traffic (research note 01 inference).
- **Not addressed:** a zero-day in a sanctioned upstream service is outside the broker's control; the broker only bounds what reaches it.

## Regression test

- **Category 3 (name resolution)**: base32-label lookups, TXT queries, direct UDP/53 and DoH/DoT attempts all fail; the only resolver is the broker's.
- **Registry adapter**: `PUT`/`POST`/publish requests and oversized request bodies to registry hosts are denied and logged.
- **Category 11 (covert channels)**: measure bytes per session that can be encoded in allowed registry GET paths and report the bandwidth.

## How it connects

- mitigated-by:: [[Broker DNS Resolver]]
- decided-by:: [[ADR-009 Broker-Only DNS Resolution]]
- mitigated-by:: [[Topology-Forced Egress]]
- mitigated-by:: [[Registry and LLM API Adapters]]
- mitigated-by:: [[Policy Miner Safeguards]]
- part-of:: [[Threat Model Overview]]

## Implications for the build

- Do not cite this incident as fact in product materials; cite [[Claude Code DNS Exfiltration CVE-2025-55284]] for the DNS class instead.
- Registry adapters need body-size limits and path logging, not only method filtering.

## Open questions

- Everything about this incident is unverified; see [[Open Questions and Unverified Claims]]. If a primary disclosure is found, update this note and set `status: verified`.

## Sources

- [axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53) (secondary; primary disclosures not linked)
- [Aurascape](https://aurascape.ai/resources/auralabs-research/silent-leak-dns-tunneling-aws-agentcore-code-interpreter/) (title only)
