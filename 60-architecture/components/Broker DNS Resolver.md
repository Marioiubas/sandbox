---
title: "Broker DNS Resolver"
aliases: ["DNS Policy Resolver"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/dns, topic/egress, control/egress, boundary/tb3, invariant/i6, milestone/m0]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Broker-owned name resolution: no UDP/53 or ICMP from the sandbox, names resolved inside the proxy or by a namespace stub forwarding only to the policy resolver, which answers only allowlisted names and blocks DoH endpoints; IP-literal CONNECTs denied by default."
related: ["[[ADR-009 Broker-Only DNS Resolution]]", "[[Claude Code DNS Exfiltration CVE-2025-55284]]", "[[July 2026 Artifactory Egress Incident]]", "[[Hostname Canonicaliser]]", "[[Netguard Ingress]]", "[[Conformance Probe Matrix]]", "[[Vercel Sandbox]]", "[[OpenAI Codex CLI]]", "[[I6 Single Canonicaliser]]", "[[Topology-Forced Egress]]", "[[Policy Engine and Entity Builder]]", "[[Audit Recorder and Event Schema]]", "[[L1 Conformance Suite]]", "[[M0 Contained Run]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/", "https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53", "https://vercel.com/docs/sandbox/concepts/firewall", "https://github.com/openai/codex/issues/22387", "https://github.com/anthropic-experimental/sandbox-runtime", "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices"]
milestone: M0
---

# Broker DNS Resolver

> Broker-owned name resolution: no UDP/53 or ICMP from the sandbox, names resolved inside the proxy or by a namespace stub forwarding only to the policy resolver, which answers only allowlisted names and blocks DoH endpoints; IP-literal CONNECTs denied by default.

## Responsibility

The DNS policy resolver in `crates/netguard` ("canonicaliser, DNS policy resolver, CONNECT/SOCKS5/transparent ingress" in [[Repository Layout]]). It makes name resolution a capability the broker grants rather than an ambient service the sandbox uses. Two paths:

1. **In-proxy resolution.** CONNECT and SOCKS5 carry hostnames; the proxy resolves them itself after canonicalisation and policy, so the sandbox never sends a DNS packet.
2. **Namespace stub.** For clients that resolve before connecting (the transparent path), a stub resolver in the sandbox's namespace forwards queries only to the broker's policy resolver over the broker channel. The policy resolver answers only allowlisted names.

**It must never:** forward a query for a non-allowlisted name upstream (the query itself is the exfiltration); answer record types other than those needed for connections; resolve names that did not pass the canonicaliser; let DoH, DoT or UDP/53 leave the sandbox.

## Why it exists

- **CVE-2025-55284.** Claude Code auto-approved `ping`, `nslookup`, `host` and `dig`; an indirect prompt injection could make the agent read `.env` and encode secrets in DNS lookups to an attacker domain ([Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)). See [[Claude Code DNS Exfiltration CVE-2025-55284]]. The lesson is to treat DNS as an egress capability enforced at the network layer, not to classify commands by name.
- **DNS tunnelling vectors.** Base32 subdomain labels, TXT tunnels and DoH over 443 were described around a July 2026 sandbox incident whose verified path was actually a zero-day chain through the sanctioned Artifactory egress point; its details remain unconfirmed ([axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53)). See [[July 2026 Artifactory Egress Incident]].
- **Raw-IP rules leave DNS open.** Vercel documents that a raw-IP CIDR allow rule bypasses SNI checks and leaves DNS open ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)); see [[Vercel Sandbox]].
- **Demand exists.** An open Codex issue asks for allowlisted DNS resolution inside the Linux sandbox ([openai/codex#22387](https://github.com/openai/codex/issues/22387)); see [[OpenAI Codex CLI]].
- **Incumbent gap.** srt's Windows alpha documents that "DNS resolution bypasses the fence" ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).

## Interface

**Proposal; not compiled.**

```rust
pub struct ResolveRequest { pub session: SessionId, pub name: CanonicalHost, pub qtype: QType }
pub enum QType { A, AAAA }                         // everything else is refused

pub enum ResolveOutcome {
    Addrs { addrs: Vec<std::net::IpAddr>, ttl: std::time::Duration },
    Refused { reason: DnsDeny },                    // not in policy, DoH endpoint, bad class
}

#[async_trait::async_trait]
pub trait PolicyResolver: Send + Sync {
    async fn resolve(&self, req: ResolveRequest) -> ResolveOutcome;
}
```

Stub wire protocol (**Proposal**): the namespace stub accepts standard DNS over UDP on the namespace's loopback only, parses the question with a strict parser, and forwards `(name bytes, qtype)` over the broker channel; the broker returns an answer or `REFUSED`. The stub never talks to any other resolver.

Config keys (**Proposal**, org or user scope):

```toml
[dns]
mode = "in_proxy"              # "in_proxy" (default) | "stub" (Linux transparent path)
synthetic_answers = false      # optional: answer allowed names with per-session synthetic IPs
deny_doh_names = ["policy:doh-endpoints"]   # org-maintained list, blocked by name
max_ttl_secs = 60
```

## Internal design

**Proposal.**

1. The query name arrives as bytes and goes through `canon_host`; rejects are logged and answered `REFUSED`.
2. The resolver asks the policy engine whether the name is admissible for this session (the same host-admission check used for connections, [[Policy Engine and Entity Builder]]). Non-admissible → `REFUSED`, logged; **no upstream query is made**.
3. Admissible names are resolved by the broker's own upstream resolver. Every returned address is classified (`classify_addr`); link-local, metadata (169.254.169.254) and RFC 1918 answers are dropped unless granted, which also blocks DNS-rebinding to internal addresses.
4. The resolved set is cached per session with a clamped TTL and recorded, so [[Netguard Ingress]] can require that a transparent connection's original destination is one the broker resolved for that name.
5. Optional synthetic mode (research note 01: "a synthetic resolver returning a sink IP is optional"): answer allowed names with addresses from a per-session synthetic pool and keep the map synthetic-IP → canonical name; the proxy resolves the real address itself at connect time. This hides real addresses and makes the transparent path independent of SNI.
6. DoH endpoints are blocked by name at host admission; DoT and UDP/53 have no route (no UDP from the netns).

IP-literal CONNECTs bypass resolution and are therefore denied by default; a grant must name the literal explicitly.

## State

Per-session answer cache and name↔address map; counters of refused queries (a burst of refused, high-entropy names is a tunnelling signal worth an audit flag).

## Failure modes and fail-closed behaviour

- Upstream resolver failure: `SERVFAIL` to the stub, connection denied in-proxy; never fall back to the host's resolver on behalf of the sandbox.
- Stub crash: the sandbox cannot resolve; in-proxy CONNECT still works.
- Malformed DNS packet at the stub: dropped and logged.

## Security considerations

- The query name is the payload in DNS exfiltration, so the non-allowlisted path must not touch the network at all, including negative-cache lookups against upstream.
- Record types: only A and AAAA; TXT, NULL, CNAME-chains to non-allowlisted names and ANY are refused (CNAME targets are re-checked against policy).
- DNS rebinding: addresses are re-classified on every resolution and pinned per connection ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) name DNS-rebinding TOCTOU as an SSRF vector).
- IPv6: AAAA answers only when IPv6 egress is proxied; otherwise refused.

## Performance budget

Cached answers in microseconds; cold resolutions dominated by upstream latency and counted in the new-connection budget (new terminated connection p50 ≤15 ms, [[L4 Product Metrics]]).

## Invariants upheld

[[I6 Single Canonicaliser]] (resolution only on canonical names; match on the broker-resolved address) and the egress half of [[I1 No Secrets in the Sandbox]] (secrets cannot leave through DNS).

## Test plan

- Conformance category 3 of [[Conformance Probe Matrix]]: direct UDP/53 to public resolvers, DoH to known endpoints, DoT on 853, data encoded in query names, DNS TXT exfil probes; "No path except the broker resolver". M0 acceptance includes the DNS TXT probe ([[M0 Contained Run]]).
- Category 4: names that resolve to link-local, metadata or RFC 1918 addresses are refused.
- Unit: stub DNS parser (fuzzed), qtype filtering, CNAME re-checking.
- Integration: an authoritative test server logs every query it receives; after the suite, it must have received zero queries for non-allowlisted names.

## Dependencies

An async DNS resolver crate and a DNS message parser (not selected in the record); `tokio`.

## How it connects

- mitigates:: [[Claude Code DNS Exfiltration CVE-2025-55284]]
- mitigates:: [[July 2026 Artifactory Egress Incident]]
- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[Policy Engine and Entity Builder]]
- part-of:: [[Netguard Ingress]]
- part-of:: [[Topology-Forced Egress]]
- contrasts-with:: [[Vercel Sandbox]]
- contrasts-with:: [[OpenAI Codex CLI]]
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[L1 Conformance Suite]]
- delivered-by:: [[M0 Contained Run]]
- decided-by:: [[ADR-009 Broker-Only DNS Resolution]]

## Implications for the build

- In-proxy resolution is enough for CONNECT and SOCKS5 in M0; the stub is needed only with the transparent listener.
- Log refused queries with the name redacted to its registrable domain plus a label-entropy score, so tunnelling attempts are visible without writing the exfiltrated bytes into the audit log.

## Open questions

- Whether synthetic answers should be the default on Linux (simplifies transparent mode) or opt-in.
- The July 2026 incident details are unverified ([[Open Questions and Unverified Claims]]); do not cite its DNS vectors as confirmed.

## Sources

- https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/
- https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53
- https://vercel.com/docs/sandbox/concepts/firewall
- https://github.com/openai/codex/issues/22387
- https://github.com/anthropic-experimental/sandbox-runtime
- https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- Report: "DNS belongs to the broker"; research notes 01 Q5 item 4, 03 Q4 and 05 section 1A.
