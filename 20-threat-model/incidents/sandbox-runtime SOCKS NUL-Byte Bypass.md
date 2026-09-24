---
title: "sandbox-runtime SOCKS NUL-Byte Bypass"
aliases: ["NUL-Byte Bypass", "Parser Differential"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/egress, topic/dns, control/egress, control/audit, adversary/a1, boundary/tb3, invariant/i6, milestone/m0, milestone/m4, evidence/conflict, evidence/single-source]
status: verified
confidence: low
created: 2026-09-24
updated: 2026-09-24
summary: "attacker.example\\x00.google.com passed the JavaScript suffix check but libc resolved it to the attacker host: a parser differential in the SOCKS5 filter, silently fixed ~Apr 2026 with no CVE."
related: [AUTO]
sources: [AUTO]
---

# sandbox-runtime SOCKS NUL-Byte Bypass

A hostname such as `attacker.example\x00.google.com` passed sandbox-runtime's JavaScript suffix/wildcard allowlist check (it "ends with" an allowed domain), but when the proxy resolved it, libc truncated the string at the NUL byte and resolved `attacker.example` instead ([Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)). Two parsers disagreed about what the hostname was, and the permissive one made the decision. This parser differential is the direct motivation for [[I6 Single Canonicaliser]]: one canonicaliser that rejects what it cannot canonicalise, and matching on the address the broker itself resolved.

## Timeline

- **20 Oct 2025**: Claude Code network sandbox GA (v2.0.24), start of the researcher's affected range.
- **~27 Mar or 1 Apr 2026**: silently fixed in sandbox-runtime 0.0.43 / Claude Code 2.1.90.
- **20 May 2026**: publicly disclosed by researcher Aonan Guan, who reports Anthropic closed the HackerOne report as a duplicate and issued no advisory or CVE ([Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)).

> [!warning] Conflict
> Penligent dates the srt fix 27 Mar 2026, with Claude Code fixed across 2.1.88–2.1.90, and estimates ~5.5 months of versions at risk ([Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)). The researcher dates it 1 Apr 2026 and gives the affected range as Claude Code 2.0.24–2.1.89. The affected range is the researcher's claim; no vendor advisory exists.

## What happened

1. The sandboxed process sends a SOCKS5 CONNECT with a domain name containing an embedded NUL byte followed by an allowed suffix.
2. The SOCKS5 filter, written in JavaScript, checks the full string against the allowlist with a suffix/wildcard match; the string ends in an allowed domain, so it passes.
3. Resolution goes through libc, which treats the NUL as end of string and resolves only the attacker's part.
4. The proxy connects to the attacker host; data leaves the sandbox ([Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)).

The researcher's lesson: "A broken sandbox giving a false sense of safety is worse than none."

## Root cause

- **(f) parser differential in the enforcement layer**: the matcher and the resolver parsed the same bytes differently.
- The filter matched a string the client supplied rather than the destination the proxy actually connected to.
- Adversary **A1** (an injection can emit such a hostname) or **A3**. Boundary TB3. It was the second network-allowlist bypass of the same sandbox, after [[sandbox-runtime Empty Allowlist Bypass]].

## Impact

Exfiltration to arbitrary hosts from sandboxes that allowlisted any domain, for the affected versions (up to ~5.5 months per Penligent).

## Stopping control in this design

- **Would have prevented: one canonicaliser ([[Hostname Canonicaliser]], [[I6 Single Canonicaliser]]).** Every ingress mode (CONNECT, SOCKS5, transparent) feeds one canonicaliser that rejects NUL, CR/LF and `%` in hostnames, trailing dots, mixed IDNA forms, IP-literal encodings (decimal, octal, hex, IPv4-mapped IPv6), and link-local, metadata and RFC 1918 destinations unless explicitly granted. Non-LDH names are rejected, not "cleaned".
- **Would have prevented: match the resolved address.** The broker resolves the canonical name itself ([[Broker DNS Resolver]]) and policy matches both the canonical name and the resolved address; there is no second parser downstream.
- **Would have contained: topology + AUDIT.** The sandbox has no other route; the rejected hostname (escaped) is logged.

## Regression test

[[M0 Contained Run]] acceptance requires 100% denial of categories 3, 4, 5, 9 and 10 "including NUL-byte, CRLF, IDNA, IP-literal, 169.254.169.254 and DNS TXT probes". For [[L1 Conformance Suite]] and [[Conformance Probe Matrix]]:

- **Category 8 (parser differentials)**: hostnames with embedded NUL, CR/LF, `%`-encoding, trailing dots, userinfo, backslashes and mixed IDNA, submitted via CONNECT, SOCKS5 (domain and IP address types) and HTTP `Host`: all rejected.
- **Differential fuzzing**: the canonicaliser's output is compared with the resolver's interpretation and with client libraries (curl, requests/httpx, undici); release threshold 0 decision-changing discrepancies. `cargo-fuzz` target from day one, ≥24 h per target by [[M4 Harden and Ship]].
- **Public bypass corpus**: this probe is a named entry.

## How it connects

- mitigated-by:: [[I6 Single Canonicaliser]]
- mitigated-by:: [[Hostname Canonicaliser]]
- mitigated-by:: [[Broker DNS Resolver]]
- evaluated-by:: [[L1 Conformance Suite]]
- evaluated-by:: [[Conformance Probe Matrix]]
- example-of:: [[Claude Code and sandbox-runtime]]
- evaluated-by:: [[Risk Register]]

## Implications for the build

- The canonicaliser returns a typed `CanonicalHost`; no other code path may accept a raw hostname string for a policy decision or a connect.
- The SOCKS5 listener must handle all address types through the same canonicaliser; the transparent listener canonicalises SNI the same way.
- Anthropic's lesson that its custom proxy "repeatedly introduced vulnerabilities" applies to this team ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)): budget for fuzzing, a public corpus and external review of netguard.

## Open questions

- Fix date conflict and single-source affected range ([[Open Questions and Unverified Claims]]).

## Sources

- [Aonan Guan, second bypass write-up](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)
- [Penligent, Claude Code sandbox bypass](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)
- [Anthropic, How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude)
