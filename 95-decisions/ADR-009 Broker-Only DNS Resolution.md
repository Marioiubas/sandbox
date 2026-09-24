---
title: "ADR-009 Broker-Only DNS Resolution"
aliases: ["ADR-009"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/dns, topic/egress, control/egress, boundary/tb3, invariant/i6, invariant/i1, milestone/m0]
status: proposal
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Resolve all names in the broker; the sandbox has no UDP/53 or ICMP; reject filtered UDP/53 passthrough."
related: ["[[Broker DNS Resolver]]", "[[Claude Code DNS Exfiltration CVE-2025-55284]]", "[[sandbox-runtime SOCKS NUL-Byte Bypass]]", "[[Hostname Canonicaliser]]", "[[ADR-003 Topology-Enforced Egress]]", "[[July 2026 Artifactory Egress Incident]]", "[[Netguard Ingress]]", "[[I6 Single Canonicaliser]]", "[[I1 No Secrets in the Sandbox]]", "[[Conformance Probe Matrix]]", "[[L1 Conformance Suite]]", "[[Landlock]]", "[[Vercel Sandbox]]", "[[OpenAI Codex CLI]]", "[[M0 Contained Run]]", "[[Open Questions and Unverified Claims]]", "[[Risk Register]]", "[[MOC Decisions]]"]
sources: ["https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/", "https://advisories.gitlab.com/pkg/npm/@anthropic-ai/claude-code/CVE-2025-55284/", "https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/", "https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/", "https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53", "https://vercel.com/docs/sandbox/concepts/firewall", "https://github.com/anthropic-experimental/sandbox-runtime", "https://github.com/openai/codex/issues/22387", "https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o", "https://docs.kernel.org/userspace-api/landlock.html", "https://aurascape.ai/resources/auralabs-research/silent-leak-dns-tunneling-aws-agentcore-code-interpreter/"]
superseded_by:
---

# ADR-009 Broker-Only DNS Resolution

> Resolve all names in the broker; the sandbox has no UDP/53 or ICMP; reject filtered UDP/53 passthrough.

## Status

Proposed (2026-09-24). Delivered by [[M0 Contained Run]], whose acceptance criteria include DNS TXT probes and 100% denial of conformance category 3. Mark `built` when [[Broker DNS Resolver]] ships with those tests passing.

## Context

DNS is an egress channel in its own right: the query name is the payload, and it leaves the host before any HTTP proxy sees a byte.

- **CVE-2025-55284.** Claude Code before v1.0.4 auto-approved `ping`, `nslookup`, `host` and `dig` as read-only commands. An indirect prompt injection in an analysed file could make the agent read `.env` and encode the secrets into DNS lookups to an attacker domain. The fix moved those commands behind approval; the advisory scores it CVSS 7.1 ([Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/); [GitLab advisory](https://advisories.gitlab.com/pkg/npm/@anthropic-ai/claude-code/CVE-2025-55284/)). The root cause was classifying commands by name while DNS stayed an unmonitored channel ([[Claude Code DNS Exfiltration CVE-2025-55284]]).
- **Parser differentials.** In the sandbox-runtime SOCKS NUL-byte bypass, `attacker.example\x00.google.com` passed a JavaScript suffix check and then resolved to the attacker host through libc ([Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)). The fix date conflicts: 27 March 2026 per Penligent, 1 April per the researcher, with roughly 5.5 months of versions at risk ([Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/); [[sandbox-runtime SOCKS NUL-Byte Bypass]]). Whenever the thing that checks a name and the thing that resolves it are different parsers, they can disagree.
- **Tunnelling vectors.** Base32 subdomain labels, TXT-record tunnels and DoH over 443 were described around a July 2026 sandbox incident. The same article says the verified path was a JFrog Artifactory zero-day chain through the sanctioned egress point, not DNS, and it could not link primary disclosures ([axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53)). See [[July 2026 Artifactory Egress Incident]]; its details are unverified. A DNS-tunnelling risk in AWS AgentCore Code Interpreter was also reported by a vendor (title only, not fetched: [Aurascape](https://aurascape.ai/resources/auralabs-research/silent-leak-dns-tunneling-aws-agentcore-code-interpreter/)).
- **Incumbent pitfalls.** Vercel documents that a raw-IP CIDR allow rule bypasses SNI checks and leaves DNS open ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)). srt's Windows alpha states that "DNS resolution bypasses the fence" ([srt](https://github.com/anthropic-experimental/sandbox-runtime)). An open Codex issue asks for allowlisted DNS resolution inside the Linux sandbox ([openai/codex#22387](https://github.com/openai/codex/issues/22387)).
- **Kernel layers do not cover it yet.** Landlock network rules are TCP-port rules from ABI 4; UDP (ABI 10) is documented but was still under review in June 2026, so it cannot be assumed in a released kernel ([kernel.org](https://docs.kernel.org/userspace-api/landlock.html); [[Landlock]]).

[[ADR-003 Topology-Enforced Egress]] already removes the sandbox's network interface. This ADR decides what happens to name resolution once it has.

## Decision

**Proposal.** The broker is the only resolver any sandboxed process can reach.

1. The sandbox has no route for UDP/53, DoT (TCP/853) or ICMP. On Linux the empty network namespace has no interface; on macOS the Seatbelt profile allows outbound traffic only to the broker's localhost port.
2. Names are resolved **inside the proxy** for CONNECT and SOCKS5 requests, after the [[Hostname Canonicaliser]] accepts the name and policy admits the host.
3. For the transparent path only, a stub resolver on the namespace loopback forwards `(name, qtype)` over the broker channel to the policy resolver. The stub never talks to any other resolver.
4. The policy resolver answers only allowlisted, canonical names. It answers only A and AAAA and refuses everything else. **A non-admissible name never produces an upstream query**, because the query itself would be the exfiltration.
5. DoH endpoints are blocked by name at host admission. IP-literal CONNECTs are denied unless a grant names the literal.
6. Every connection is matched on the canonical name **and** on an address the broker itself resolved for that name in this session. Link-local, metadata (169.254.169.254) and RFC 1918 answers are dropped unless granted.
7. Refused queries are logged with the name reduced to its registrable domain plus an entropy score (details in [[Broker DNS Resolver]]).

**Testable as:** conformance category 3 ("no path except the broker resolver") and category 4 ("policy applied to the resolved address") at 100% denial ([[Conformance Probe Matrix]]; [[L1 Conformance Suite]]). An authoritative test server that logs every query receives **zero** queries for non-allowlisted names across the whole suite.

## Alternatives considered

| Alternative | Pros | Cons | Why rejected |
|---|---|---|---|
| **Filtered UDP/53 passthrough**: let the sandbox send DNS to one allowed resolver, as the netns design that drops "everything except traffic destined for Proxy (TCP) and DNS (UDP)" does ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)) | Zero client breakage; `dig` and `nslookup` keep working | A recursive resolver forwards the attacker-chosen name to the attacker's authoritative server, so the payload leaves anyway. Filtering by name at a second resolver recreates the check-versus-resolve parser differential | It is the CVE-2025-55284 channel with a filter bolted on |
| **Sandbox uses the host resolver** (the default without this decision) | Nothing to build | Unmediated; srt's Windows alpha shows the consequence | Fails the containment requirement |
| **Allow DoH to a chosen provider** | Encrypted, TCP-only | Indistinguishable from HTTPS to the same host; the name is still sent upstream | Tunnels are exactly the concern |
| **Rely on Landlock UDP rules** | Kernel-enforced | ABI 10 not in a released stable kernel per the record | Unavailable; keep as an inner layer later |
| **Synthetic resolver by default** (answer allowed names with per-session sink IPs) | Hides real addresses; decouples the transparent path from SNI | More moving parts; compatibility unmeasured | Deferred to an option, not rejected (see Open questions) |

## Consequences

- **Easier:** one place decides both "may this name be looked up" and "may this address be dialled", which closes the CVE-2025-55284 class and the NUL-byte differential class together. The audit log sees every attempted lookup.
- **Harder:** tools that do their own DNS (`dig`, resolvers inside static binaries on the transparent path) fail or need the stub. That is fail-closed behaviour and acceptable.
- **Riskier:** the broker becomes a single point of availability for name resolution; an upstream resolver failure must return `SERVFAIL`, never fall back to the host resolver.
- **Residual:** allowed names remain covert channels (query timing, request counts). Conformance category 11 measures that bandwidth and does not claim it is zero. Tracked in [[Risk Register]].

## Revisit triggers

- A bypass in category 3 or 4, or a parser discrepancy between the stub and the canonicaliser, found by fuzzing or the bug bounty.
- Landlock ABI 10 lands in a stable kernel: add a UDP deny as a defence-in-depth layer, with no change to this decision.
- Encrypted ClientHello adoption grows enough to weaken SNI peeking; broker-owned DNS then becomes the main name signal on the L4 path.
- A legitimate, common developer tool proves to need record types other than A or AAAA.

## Invariants and components affected

- **Upholds [[I6 Single Canonicaliser]]:** resolution happens only on canonical names, and matching uses the broker-resolved address.
- **Upholds the egress half of [[I1 No Secrets in the Sandbox]]:** secrets that reach the agent's memory cannot leave through DNS.
- **Upholds I9:** refused lookups are logged outside the sandbox.
- **Weakens nothing.**
- Components: [[Broker DNS Resolver]], [[Hostname Canonicaliser]] and [[Netguard Ingress]] (all in `crates/netguard`), plus the launcher backends that must not create a UDP route.

## How it connects

- motivated-by:: [[Claude Code DNS Exfiltration CVE-2025-55284]]
- motivated-by:: [[sandbox-runtime SOCKS NUL-Byte Bypass]]
- motivated-by:: [[July 2026 Artifactory Egress Incident]] (unverified details)
- mitigates:: [[Claude Code DNS Exfiltration CVE-2025-55284]]
- depends-on:: [[ADR-003 Topology-Enforced Egress]]
- depends-on:: [[Broker DNS Resolver]]
- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[Netguard Ingress]]
- implements:: [[I6 Single Canonicaliser]]
- contrasts-with:: [[Vercel Sandbox]] (CIDR rules leave DNS open)
- contrasts-with:: [[OpenAI Codex CLI]] (allowlisted DNS still an open request)
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[L1 Conformance Suite]]
- delivered-by:: [[M0 Contained Run]]
- part-of:: [[MOC Decisions]]

## Implications for the build

- Start with in-proxy resolution in M0: CONNECT and SOCKS5 carry hostnames, so no stub is needed until the transparent listener ships.
- Give the stub's DNS parser a `cargo-fuzz` target from its first commit and feed its outputs through the same `canon_host` as every other ingress.
- Add the "zero upstream queries for non-allowlisted names" assertion to the L1 harness as a release blocker.
- `broker why` must explain a refused lookup the same way it explains a refused connection.

## Open questions

- Should synthetic answers be the Linux default, since they simplify transparent mode, or stay opt-in? No compatibility data is in the record.
- Which record types, if any, do real agent workloads need beyond A and AAAA? Measure in L3 runs.
- The July 2026 incident and the AgentCore DNS-tunnelling report are unverified ([[Open Questions and Unverified Claims]]); do not cite their DNS vectors as confirmed.

## Sources

- [Embrace The Red: Claude Code DNS exfiltration](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)
- [GitLab advisory: CVE-2025-55284](https://advisories.gitlab.com/pkg/npm/@anthropic-ai/claude-code/CVE-2025-55284/)
- [Aonan Guan: NUL-byte allowlist bypass](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)
- [Penligent: Claude Code sandbox bypass](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)
- [axeploit: the July 2026 sandbox incident](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53)
- [Vercel Sandbox firewall docs](https://vercel.com/docs/sandbox/concepts/firewall)
- [anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- [openai/codex#22387](https://github.com/openai/codex/issues/22387)
- [dev.to: kernel-level egress control](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)
- [kernel.org: Landlock](https://docs.kernel.org/userspace-api/landlock.html)
- [Aurascape: DNS tunnelling in AgentCore Code Interpreter](https://aurascape.ai/resources/auralabs-research/silent-leak-dns-tunneling-aws-agentcore-code-interpreter/) (title only)
- Report: decisions row "DNS" and "DNS belongs to the broker"; research notes 01 Q5, 03 Q4 and 04b Q1–Q2.
