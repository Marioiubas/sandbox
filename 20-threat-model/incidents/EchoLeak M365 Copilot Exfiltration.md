---
title: "EchoLeak M365 Copilot Exfiltration"
aliases: ["CVE-2025-32711", "EchoLeak"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/egress, topic/ifc, control/egress, control/task-tok, control/audit, adversary/a1, boundary/tb4, boundary/tb5, evidence/conflict]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Zero-click email beat the XPIA classifier; a reference-style markdown image carried data through a CSP-allowed Teams/SharePoint endpoint to the attacker (CVE-2025-32711)."
related: [AUTO]
sources: [AUTO]
---

# EchoLeak M365 Copilot Exfiltration

A single crafted email, never clicked by the user, made Microsoft 365 Copilot pull privileged internal data into its answer and leak it through an image fetch routed via a first-party Microsoft endpoint that the Content Security Policy allowed. It is described as "the first known case of a prompt injection being weaponized to cause concrete data exfiltration in a production AI system" ([arXiv 2509.10540](https://arxiv.org/html/2509.10540v1)). The lesson for the broker: an allowlisted first-party domain that fetches arbitrary URLs is an open proxy, and data from untrusted content must never flow into URLs.

## Timeline

- **Jan 2025**: discovered by Aim Labs (Aim Security) ([arXiv 2509.10540](https://arxiv.org/html/2509.10540v1)).
- **By May 2025**: Microsoft deployed server-side fixes; no known in-the-wild exploitation ([Dark Reading](https://www.darkreading.com/application-security/researchers-detail-zero-click-copilot-exploit-echoleak)).
- **11–12 Jun 2025**: public disclosure per most sources ([arXiv 2509.10540](https://arxiv.org/html/2509.10540v1); [The Hacker News](https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html)).

> [!warning] Conflict
> Hack The Box dates the disclosure 24 Jul 2025 ([Hack The Box](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)), against 11–12 Jun elsewhere. The widely reported CVSS 9.3 was not verified against the MSRC advisory.

## What happened

The chain, at the level the sources describe it ([arXiv 2509.10540](https://arxiv.org/html/2509.10540v1); [Dark Reading](https://www.darkreading.com/application-security/researchers-detail-zero-click-copilot-exploit-echoleak)):

1. **Classifier bypass.** The attacker's email was phrased as ordinary business text addressed to the human reader, so Microsoft's XPIA (cross-prompt-injection) classifier did not flag it.
2. **Redaction bypass.** Reference-style Markdown links and images got past Copilot's link-redaction filter.
3. **Channel.** Auto-fetched image references carried data in URL query parameters.
4. **CSP bypass.** A Teams/SharePoint preview endpoint permitted by the Content Security Policy acted as a proxy to the attacker's domain.

No user click was needed. The source names the root cause an "LLM Scope Violation": untrusted external content caused the assistant to pull privileged internal data and emit it through an allowed channel. OWASP later used EchoLeak as the example for ASI01 Agent Goal Hijack ([OWASP GenAI](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)).

Markdown-image exfiltration is a recurring class, not a one-off: it was fixed in Amp Code in 2025 and seen earlier in Bing Chat and ChatGPT plugins ([Embrace The Red](https://embracethered.com/blog/posts/2025/amp-code-fixed-data-exfiltration-via-images/)).

## Root cause

- **(a) untrusted input steering tools** plus **(c) egress via an allowed proxy**. The exfiltration destination was an allowlisted first-party domain.
- Adversary **A1** (remote injection author with no credentials). Shape: [[Lethal Trifecta]] (private mailbox data, untrusted email, an outbound fetch).

## Impact

Potential zero-click exfiltration of anything in the user's Copilot retrieval scope. Microsoft patched server-side before disclosure; no in-the-wild exploitation is known ([Dark Reading](https://www.darkreading.com/application-security/researchers-detail-zero-click-copilot-exploit-echoleak)).

## Stopping control in this design

- **Would have prevented: EGRESS.** No open-proxy or generic URL-fetch destinations on any allowlist; egress enforced at the network layer by the broker rather than by client-side URL redaction ([[Topology-Forced Egress]], [[Netguard Ingress]]). The org deny ceiling (paste sites, raw IPs, tunnels, arbitrary object storage) belongs in [[Policy Miner Safeguards]] so a learned policy cannot re-open such a destination.
- **Would have prevented (proposal, research frontier): information flow.** Data derived from untrusted content never flows into URLs ([[Information Flow Control]]); in the MVP this is approximated by session-level labels, not per-value taint.
- **Would have contained: TASK-TOK and AUDIT.** A narrower retrieval scope limits what can be pulled; every outbound request is logged with its redacted URL and destination.

**Proposal.** Treat a first-party "preview", "proxy" or "fetch" endpoint on an allowed domain as equivalent to allowing the whole internet; it must be explicitly denied by path rule or the host terminated and method/path-scoped.

## Regression test

Category-level additions for [[Conformance Probe Matrix]]:

- **Category 1 (allowed-destination abuse)**: a request to an allowed host's URL-fetch or redirect endpoint that names a non-allowed destination is denied and logged.
- **Category 6 (redirects)**: a 3xx or preview hop from an allowed host to a non-allowed host is re-evaluated and denied.
- **Category 11 (covert channels)**: measure how many bytes an agent can encode into query strings on allowed hosts per session; report the figure.
- **L2 injection fixture**: an indirect-injection document instructs the agent to embed retrieved data in an image URL; expected result "model complied, broker blocked".

## How it connects

- example-of:: [[Lethal Trifecta]]
- part-of:: [[Threat Model Overview]]
- example-of:: [[Adversary Classes]]
- mitigated-by:: [[Topology-Forced Egress]]
- mitigated-by:: [[Netguard Ingress]]
- mitigated-by:: [[Policy Miner Safeguards]]
- mitigated-by:: [[Information Flow Control]]
- evaluated-by:: [[Conformance Probe Matrix]]

## Implications for the build

- Netguard must support path-level deny rules on otherwise allowed hosts, which means L7 termination for any host that has a fetch or preview endpoint.
- The default policy templates must not include generic fetch or proxy endpoints of large platforms.
- Log redacted URLs so query-string exfiltration attempts are visible in audit.

## Open questions

- Disclosure date conflict and unverified CVSS 9.3; the CSP-bypass chain details were not fetched beyond summaries ([[Open Questions and Unverified Claims]]).

## Sources

- [arXiv 2509.10540, EchoLeak paper](https://arxiv.org/html/2509.10540v1)
- [Dark Reading](https://www.darkreading.com/application-security/researchers-detail-zero-click-copilot-exploit-echoleak)
- [Hack The Box](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability)
- [The Hacker News, Jun 2025](https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [Embrace The Red, Amp Code images](https://embracethered.com/blog/posts/2025/amp-code-fixed-data-exfiltration-via-images/)
