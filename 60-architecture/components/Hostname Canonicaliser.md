---
title: "Hostname Canonicaliser"
aliases: ["Canonicaliser"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/egress, topic/dns, control/egress, invariant/i6, boundary/tb3, milestone/m0]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-25
summary: "The single canonicaliser: reject NUL, CR/LF and % in hostnames, trailing dots, mixed IDNA, IP-literal encodings, link-local, metadata (169.254.169.254) and RFC 1918 unless granted; match on canonical name and broker-resolved address; fuzzed and differential-tested."
related: ["[[I6 Single Canonicaliser]]", "[[sandbox-runtime SOCKS NUL-Byte Bypass]]", "[[Broker DNS Resolver]]", "[[Netguard Ingress]]", "[[L1 Conformance Suite]]", "[[Conformance Probe Matrix]]", "[[Policy Engine and Entity Builder]]", "[[Cedar]]", "[[Broker Cedar Schema]]", "[[Core Trait Contracts]]", "[[TLS Termination and Per-Session CA]]", "[[Git Smart-HTTP Adapter]]", "[[MCP Guard]]", "[[Risk Register]]", "[[Red-Team Plan]]", "[[M0 Contained Run]]", "[[M4 Harden and Ship]]", "[[Gemini CLI Prefix Allowlist Bypass]]", "[[Claude Code Path and Command Injection CVEs]]", "[[ADR-009 Broker-Only DNS Resolution]]"]
sources: ["https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/", "https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/", "https://arxiv.org/abs/2405.17737", "https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md", "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices", "https://www.anthropic.com/engineering/how-we-contain-claude"]
milestone: M0
code: ["code/crates/netguard/src/canon.rs", "code/crates/netguard/tests/lint_single_canonicaliser.rs", "code/tests/bypass-corpus/hosts.toml", "code/tests/fuzz/fuzz_targets/canon.rs", "code/crates/netguard/src/canon/addr.rs", "code/crates/netguard/src/canon/pattern.rs", "code/crates/netguard/src/canon/path.rs"]
---

# Hostname Canonicaliser

> The single canonicaliser: reject NUL, CR/LF and % in hostnames, trailing dots, mixed IDNA, IP-literal encodings, link-local, metadata (169.254.169.254) and RFC 1918 unless granted; match on canonical name and broker-resolved address; fuzzed and differential-tested.

## Responsibility

`netguard::canon`: the one place where untrusted bytes become policy-visible host and path values. It is the implementation of [[I6 Single Canonicaliser]]. Everything that names a destination calls it: [[Netguard Ingress]] (CONNECT authority, SOCKS5 domain, SNI, transparent original destination), [[TLS Termination and Per-Session CA]] (`Host`, `:authority`, redirect `Location`), protocol adapters (git remote URLs, API paths), [[MCP Guard]] (remote server URLs), the [[Broker DNS Resolver]] stub (query names) and the policy compiler (host patterns in `broker.toml` and Cedar entity data).

**It must never:** return a value for input it cannot canonicalise unambiguously; call a resolver; match by string suffix; be duplicated by any other crate.

## Why it exists

The sandbox-runtime SOCKS5 bypass: `attacker.example\x00.google.com` passed a JavaScript suffix check but libc truncated the name at the NUL and resolved the attacker host ([Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)); roughly 5.5 months of versions were at risk ([Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)). See [[sandbox-runtime SOCKS NUL-Byte Bypass]]. Parser and matcher bugs in the enforcement layer are the dominant failure class ([[Risk Register]]), and Cedar's proofs "hold only relative to the schema", with `like` being string matching, not DNS semantics ([cedar-lean](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md); [[Cedar]]).

## Interface

**Proposal; not compiled.**

```rust
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalHost { ascii: String, kind: HostKind }   // private fields
pub enum HostKind { Name { registrable: String }, V4(std::net::Ipv4Addr), V6(std::net::Ipv6Addr) }

#[derive(Debug)]
pub enum Reject {
    Empty, TooLong, ForbiddenByte(u8), TrailingDot, BadLabel, MixedIdna, IdnaRoundTrip,
    AmbiguousIpLiteral, MappedV6, NonCanonicalPath, EncodedSeparator, DotSegment,
}

pub fn canon_host(raw: &[u8]) -> Result<CanonicalHost, Reject>;
pub fn canon_path(raw: &[u8]) -> Result<CanonicalPath, Reject>;
pub fn classify_addr(ip: std::net::IpAddr) -> AddrClass;      // Public | Loopback | LinkLocal | Metadata | Private | Other
pub fn host_matches(pattern: &HostPattern, host: &CanonicalHost) -> bool; // label-boundary match
```

`HostPattern` is produced by the policy compiler from `broker.toml` (`host = "api.github.com"`, `host = "*.example.com"`) using the same function, so policy strings and runtime strings are canonical in the same way.

## Algorithm

**Proposal.** Reject early; normalise only where the result is unique.

1. **Bytes.** Reject empty input, input over 253 bytes, and any NUL, CR, LF, `%`, whitespace, `\`, `/`, `@`, `?` or `#` byte (the report lists NUL, CR/LF and `%`; the rest block userinfo and path confusion).
2. **Trailing dot.** Reject (report). No implicit root-label stripping.
3. **IP literals.** Accept only strict dotted-quad IPv4 (four decimal octets, no leading zeros) and bracketed IPv6. Reject every other numeric form: single decimal integers, hex (`0x7f.1`), octal (`0177.0.0.1`), short forms (`127.1`) and IPv4-mapped IPv6 (report: "IP-literal encodings (decimal, octal, hex, IPv4-mapped IPv6)"). Accepted literals become `HostKind::V4/V6` and are denied by default at policy time unless a grant names them (IP-literal CONNECTs are denied by default; [[Broker DNS Resolver]]).
4. **IDNA.** If any byte is non-ASCII, convert via one IDNA mapping to A-labels; reject input that mixes U-labels and A-labels, and reject A-labels (`xn--`) that do not round-trip (report: "mixed IDNA forms").
5. **Labels.** Lowercase ASCII; each label 1–63 bytes of letters, digits and hyphen, not starting or ending with a hyphen ("rejects non-LDH names", report incident table).
6. **Registrable domain.** Compute the registrable domain for the `Host` entity's `registrable` attribute ([[Broker Cedar Schema]]).

**Paths.** `canon_path` accepts origin-form paths only; decodes percent-escapes of unreserved characters; rejects encoded `/`, `\`, NUL and `.`; rejects `.` and `..` segments and backslashes rather than resolving them; keeps the query separately for adapters. Ambiguity is a reject, never a guess.

**Addresses.** After resolution, `classify_addr` marks loopback, link-local, cloud metadata (169.254.169.254) and RFC 1918 ranges; these are denied unless explicitly granted. The MCP security best practices name cloud metadata and DNS rebinding as SSRF risks ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)).

## Matching rule

A destination is admitted only if **both** hold:

- `host_matches(pattern, canonical_name)` for some allowed pattern (label-boundary matching: `*.example.com` matches `a.example.com`, never `evilexample.com` or `example.com.evil`);
- every address the broker resolved for that name, and the address actually dialled, is of an allowed class and (if the grant pins addresses) in the pinned set.

This "directly answers the NUL-byte parser differential, where a JavaScript suffix check and libc resolution disagreed" (report).

## State

None. Pure functions; the registrable-domain data set is compiled in.

## Failure modes

Every `Reject` becomes a deny with the variant as the audit reason. Panics are bugs: the fuzz harness treats a panic as a crash, and the function is wrapped so that a panic in production is a deny.

## Security considerations

- One implementation, no feature flags that change behaviour.
- The CONNECT host, SNI and `Host` header are compared as `CanonicalHost` values, never raw strings ([[TLS Termination and Per-Session CA]]).
- Adapters that parse URLs (git remotes, `Location` headers) must split scheme and authority with a strict parser and pass the authority bytes here; a lint forbids `url::Url::host_str()` outside this module.
- Canonicalisation of policy input at compile time means a policy author cannot write a pattern that is interpreted differently at runtime.

## Performance budget

Microseconds per call; it sits on every connection and must be negligible against the p50 ≤5 ms warm-connection budget.

## Invariants upheld

[[I6 Single Canonicaliser]] directly; supports [[I2 Fail-Closed Launch]]'s "unparseable input denies" rule.

## Test plan

- **Unit and corpus.** `tests/bypass-corpus`: NUL-byte hosts, CRLF, `%`-encoded hosts, IDNA and punycode mixes, trailing dots, userinfo and backslash URLs, decimal, octal and hex IPv4, IPv4-mapped IPv6, `169.254.169.254`, RFC 1918, SOCKS4a/5 hostname forms, CONNECT to IP literals, DNS rebinding (research note 05 testing list).
- **Property (`proptest`).** Idempotence (`canon(canon(x)) == canon(x)`), no accepted output contains a forbidden byte, pattern matching respects label boundaries, compile-time and runtime canonicalisation agree.
- **Fuzz (`cargo-fuzz`).** `canon_host`, `canon_path`; ≥24 h per target with no crashes before release ([[M4 Harden and Ship]]).
- **Differential.** HTTP Garden-style comparison of URL and host parsing against curl, requests/httpx and undici ([arXiv 2405.17737](https://arxiv.org/abs/2405.17737)); 0 decision-changing discrepancies ([[L1 Conformance Suite]]).
- **Conformance.** Categories 4 and 8 of [[Conformance Probe Matrix]], through every ingress mode ([[M0 Contained Run]]).
- **Red team.** White-box review in the human ring ([[Red-Team Plan]]).

## Dependencies

A UTS 46 IDNA implementation and a public-suffix data set (crates not selected in the record); `proptest`, `cargo-fuzz`.

## How it connects

- implements:: [[I6 Single Canonicaliser]]
- mitigates:: [[sandbox-runtime SOCKS NUL-Byte Bypass]]
- mitigates:: [[Risk Register]]
- depends-on:: [[Broker DNS Resolver]]
- part-of:: [[Netguard Ingress]]
- part-of:: [[Core Trait Contracts]]
- evaluated-by:: [[L1 Conformance Suite]]
- evaluated-by:: [[Conformance Probe Matrix]]
- delivered-by:: [[M0 Contained Run]]
- decided-by:: [[ADR-009 Broker-Only DNS Resolution]]

## Implications for the build

- First crate written in M0; the `CanonicalHost` type gates the rest of the network code.
- Publish the corpus; Anthropic's own lesson is that custom proxy components "repeatedly introduced vulnerabilities" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)), so external scrutiny is a feature.
- [[Policy Engine and Entity Builder]] must build `Host` and `PathPrefix` entities only from these types.

## Open questions

- Exact IDNA mapping (UTS 46 transitional or not) and how to treat emoji or confusable domains; not in the record.
- Whether to reject all IPv6 by default until proxied IPv6 is tested.
- How to handle legitimate hosts with underscores (rare for HTTPS); strict LDH rejects them.

## Sources

- https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/
- https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/
- https://arxiv.org/abs/2405.17737
- https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md
- https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- https://www.anthropic.com/engineering/how-we-contain-claude
- Report: canonicaliser rejection list and matching rule, tech-stack testing row, L1 thresholds; research notes 01 Q5, 04b Q1 and 05 sections 3.2 and 4.

## Implementation notes

- 2026-09-24: IDNA uses UTS 46 non-transitional mapping with STD3 rules and `Hyphens::CheckFirstLast` (idna 1.1.0), because `Hyphens::Check` rejects real-world names with `--` in positions 3-4 (for example CDN nodes). Non-ASCII label separators (U+3002, U+FF0E, U+FF61) are rejected rather than mapped, since parsers disagree on them.
- 2026-09-24: beyond the report's list, the canonicaliser also rejects `*`, `:` outside IPv6 brackets, bare brackets, and any control byte or DEL; single-label names (`localhost`) canonicalise and are left to policy.
- 2026-09-24: metadata addresses recognised by `classify_addr`: 169.254.169.254, 169.254.170.2 (ECS), 100.100.100.200 (Alibaba), 192.0.0.192 (Oracle), fd00:ec2::254 (AWS IPv6); NAT64 `64:ff9b::/96` and IPv4-mapped addresses are classified by their embedded IPv4.

## Build log

- 2026-09-24: built `netguard::canon` (`canon_host`, `canon_path`, `classify_addr`, `HostPattern`) in `code/crates/netguard/src/canon.rs`. Private fields on `CanonicalHost`/`CanonicalPath`; `CanonicalHost::from_ip` covers SOCKS5 binary addresses with the same mapped-IPv6 rule. Tests: unit tests plus proptest properties (idempotence on arbitrary bytes, LDH-only output, spliced forbidden bytes rejected, label-boundary wildcards, pattern/runtime agreement, safe paths); the public corpus `code/tests/bypass-corpus/hosts.toml` (36 cases) at canonicaliser level (`corpus_matches_the_canonicaliser`) and through CONNECT and SOCKS5 (`bypass_corpus_denied_with_reason_through_every_ingress_mode`, `i6_bypass_corpus_end_to_end`); the I6 lint `crates/netguard/tests/lint_single_canonicaliser.rs`; `cargo-fuzz` target `canon` (60 s smoke, 2.2M runs, no crash). Registrable domain from the compiled-in `psl` crate.
- 2026-09-25: files split to stay under 500 lines, no behaviour change: `canon.rs` keeps host canonicalisation; address classes moved to `canon/addr.rs`, host patterns to `canon/pattern.rs`, path canonicalisation to `canon/path.rs`, tests to `canon/tests.rs` and `canon/props.rs`. Still one canonicaliser (I6): child modules of `canon`, public API (`canon_host`, `canon_path`, `CanonicalHost`, `CanonicalPath`, `HostPattern`, `AddrClass`, `classify_addr`) unchanged; `lint_single_canonicaliser` passes.
- 2026-09-25 (M4): `canon_path` now checks each segment at up to three percent-decoding levels: no dot segment, also behind `;params` or an escape (Tomcat's `..;/`, `..%3B`, `..%253B`), no encoded separator (`%252F`), no look-alike of a dot or slash (full-width, division slash), and valid UTF-8 (no overlong `C0 AE`). Found by the category 8 differential test (`code/tests/conformance/tests/m4_differential.rs`): `/allowed/..;/secret` and `/allowed/%C0%AE%C0%AE/secret` passed under `paths = ["/allowed/**"]` although Tomcat-style or lenient servers would serve `/secret`. Unit cases in `canon::tests::paths`.
- 2026-09-25 (M4): third bypass, found by the new generated-input fuzz target `path_differential` in seconds: `/allowed/;;,..%25%255C../;/L;`. The segment check stopped decoding at a malformed escape (`%%5C`), while lenient servers keep the `%` and decode the rest, producing a backslash separator on the second round. The check's decoder is now lenient the same way; 4.4 M generated paths then stayed under the rule.
