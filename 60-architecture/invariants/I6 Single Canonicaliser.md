---
title: "I6 Single Canonicaliser"
aliases: ["Single Canonicaliser"]
type: concept
section: architecture
tags: [sandbox/architecture, concept, invariant/i6, topic/egress, topic/dns, control/egress, boundary/tb3, milestone/m0]
status: proposal
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "One canonicaliser for every hostname and path; match on the canonical name and on the broker-resolved address; reject what cannot be canonicalised."
related: ["[[Hostname Canonicaliser]]", "[[sandbox-runtime SOCKS NUL-Byte Bypass]]", "[[sandbox-runtime Empty Allowlist Bypass]]", "[[Broker DNS Resolver]]", "[[L1 Conformance Suite]]", "[[Cedar]]", "[[Risk Register]]", "[[Netguard Ingress]]", "[[Policy Engine and Entity Builder]]", "[[Claude Code Path and Command Injection CVEs]]", "[[Gemini CLI Prefix Allowlist Bypass]]", "[[Cursor DuneSlide Sandbox Escape]]", "[[Conformance Probe Matrix]]", "[[M0 Contained Run]]", "[[ADR-009 Broker-Only DNS Resolution]]"]
sources: ["https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/", "https://github.com/advisories/GHSA-9gqj-5w7c-vx47", "https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/", "https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md", "https://arxiv.org/abs/2405.17737"]
milestone: M0
---

# I6 Single Canonicaliser

> One canonicaliser for every hostname and path; match on the canonical name and on the broker-resolved address; reject what cannot be canonicalised.

## Statement

**Proposal.** There is exactly one function family that turns untrusted network names and paths into policy-visible values, in `netguard::canon` ([[Hostname Canonicaliser]]):

- `canon_host(&[u8]) -> Result<CanonicalHost, Reject>` for every hostname from any source (CONNECT authority, SOCKS5 domain, SNI, `Host`, `:authority`, redirect `Location`, git remote URLs, MCP server URLs, DNS stub queries);
- `canon_path(&[u8]) -> Result<CanonicalPath, Reject>` for HTTP request paths used in policy;
- filesystem paths used in fs grants go through the same normalisation rules in the policy compiler.

Every allow decision on a destination requires **both** the canonical name and the broker-resolved address to match policy. Input that cannot be canonicalised is rejected, never passed through. No other code may construct `CanonicalHost` or `CanonicalPath` (private constructor), and no other code may call a system resolver on sandbox-supplied names.

## Rationale

- **The NUL-byte parser differential.** `attacker.example\x00.google.com` passed sandbox-runtime's JavaScript suffix check and resolved to the attacker host through libc ([Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)); see [[sandbox-runtime SOCKS NUL-Byte Bypass]]. Two parsers disagreed; the fix is one parser plus matching the address the broker itself resolved.
- **Enforcement-layer bugs are the dominant failure class.** Empty-list semantics ([GHSA-9gqj-5w7c-vx47](https://github.com/advisories/GHSA-9gqj-5w7c-vx47)), naive path-prefix checks ([Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/)), prefix-matched command allowlists ([Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)) and symlink fallback appeared at least seven times in 13 months across four vendors (report). See [[sandbox-runtime Empty Allowlist Bypass]], [[Claude Code Path and Command Injection CVEs]], [[Gemini CLI Prefix Allowlist Bypass]] and [[Cursor DuneSlide Sandbox Escape]].
- **Custom proxies attract bugs.** Anthropic reports that its custom proxy "repeatedly introduced vulnerabilities" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)); the [[Risk Register]] mitigation is "Single canonicaliser; fuzzing; public corpus".
- **Cedar's proofs stop at the schema.** Cedar's guarantees "cover policy semantics, not the enforcement point", "hold only relative to the schema", and `like` patterns "are string patterns, not DNS semantics" (report; [cedar-lean](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)). If two code paths produce different strings for the same host, every SymCC proof is about the wrong thing. See [[Cedar]].

## How it is enforced

**Proposal.**

1. **Types.** `CanonicalHost` and `CanonicalPath` are newtypes with private fields; `ProtocolAdapter::claims` already takes `&CanonicalHost` ([[Core Trait Contracts]]). Entity construction in [[Policy Engine and Entity Builder]] accepts only these types for `Host`, `PathPrefix` and `Repo.host`.
2. **Rejection list.** NUL, CR/LF and `%` in hostnames; trailing dots; mixed IDNA forms; IP-literal encodings (decimal, octal, hex, IPv4-mapped IPv6); link-local, cloud-metadata (169.254.169.254) and RFC 1918 destinations unless explicitly granted (report, topology section).
3. **Resolve once, in the broker.** [[Broker DNS Resolver]] resolves the canonical name; the proxy connects to exactly the address it resolved and re-checks it against address policy, so a name that passes but resolves to a metadata IP is denied.
4. **Consistency.** On the L7 path, CONNECT target = SNI = `Host`/`:authority`, all compared as `CanonicalHost` ([[TLS Termination and Per-Session CA]]).
5. **Lint.** A CI lint (grep for `to_socket_addrs`, `getaddrinfo`, `lookup_host`, `url::Url::host_str` outside `netguard::canon`) fails the build.

## Minimal test

**Proposal.** The bypass corpus in `tests/bypass-corpus` (conformance categories 3, 4 and 8 in [[Conformance Probe Matrix]]): NUL-byte hosts, CRLF injection, IDNA and punycode mixes, trailing dots, userinfo and backslash URLs, decimal, octal and hex IPv4, IPv4-mapped IPv6, `169.254.169.254`, DNS rebinding, SOCKS4a and SOCKS5 hostname forms, CONNECT to IP literals. Every probe must be denied and logged with a reason, through every ingress mode. Differential fuzzing compares the canonicaliser's reading of URLs against curl, requests/httpx and undici in the HTTP Garden style ([arXiv 2405.17737](https://arxiv.org/abs/2405.17737)); zero decision-changing discrepancies is the [[L1 Conformance Suite]] threshold.

## What would violate it

- An adapter that re-parses `Host` or a git URL with its own code.
- Suffix matching on raw strings before canonicalisation.
- Passing a sandbox-supplied name to libc or any system resolver.
- Allowing a name without checking the resolved address (or vice versa).
- A "lenient" mode that forwards unparseable names.

## How it connects

- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[Broker DNS Resolver]]
- part-of:: [[Netguard Ingress]]
- motivated-by:: [[sandbox-runtime SOCKS NUL-Byte Bypass]]
- motivated-by:: [[sandbox-runtime Empty Allowlist Bypass]]
- motivated-by:: [[Claude Code Path and Command Injection CVEs]]
- mitigates:: [[Risk Register]]
- evaluated-by:: [[L1 Conformance Suite]]
- evaluated-by:: [[Conformance Probe Matrix]]
- delivered-by:: [[M0 Contained Run]]
- decided-by:: [[ADR-009 Broker-Only DNS Resolution]]

## Implications for the build

- Write `netguard::canon` and its `cargo-fuzz` and `proptest` targets in week one; every other network component depends on its types.
- Publish the bypass corpus; it is a credibility asset (report) and an external bug-bounty input ([[L1 Conformance Suite]]).
- Path canonicalisation for HTTP must decide explicitly how percent-encoding and dot-segments are handled and reject ambiguous forms.

## Open questions

- Exact IDNA processing rules (UTS 46 variant, which mixed forms count as "mixed") are not specified in the record.
- Whether IPv6 destinations should be allowed at all when proxied; research note 01 suggests blocking IPv6 unless proxied.

## Sources

- https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/
- https://github.com/advisories/GHSA-9gqj-5w7c-vx47
- https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/
- https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack
- https://www.anthropic.com/engineering/how-we-contain-claude
- https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md
- https://arxiv.org/abs/2405.17737
- Report: invariant I6, canonicaliser paragraph, Cedar limits, L1 thresholds; research notes 04b Q1 and 05 section 4.

## Build log

- 2026-09-24: tests: canonicaliser unit and property tests, `bypass_corpus_denied_with_reason_through_every_ingress_mode`, `i6_bypass_corpus_end_to_end`, `connect_and_socks5_agree`, `cat04_ip_literals_and_encodings`, the lint `lint_single_canonicaliser.rs`, and the `canon` fuzz target. Name and resolved address are both matched; SNI is compared as `CanonicalHost`.
