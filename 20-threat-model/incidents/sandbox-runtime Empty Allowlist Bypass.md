---
title: "sandbox-runtime Empty Allowlist Bypass"
aliases: ["CVE-2025-66479"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/egress, topic/policy, control/egress, control/audit, adversary/a1, boundary/tb3, invariant/i2, invariant/i6, milestone/m0, milestone/m2]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "sandbox-runtime <0.0.16 treated an empty allowedDomains list as allow-all (CVE-2025-66479, GHSA-9gqj-5w7c-vx47)."
related: [AUTO]
sources: [AUTO]
---

# sandbox-runtime Empty Allowlist Bypass

Anthropic's `@anthropic-ai/sandbox-runtime` before 0.0.16 "fail[ed] to enforce network restrictions if the sandbox policy did not configure any allowed domains" ([GitHub Advisory](https://github.com/advisories/GHSA-9gqj-5w7c-vx47)). An empty allowlist, which a user would read as "nothing allowed", meant "everything allowed". It was rated Low, but it is the purest example of an unsafe default in the enforcement layer, and it is the reason this broker's schema semantics must be fail-closed and tested: empty lists deny.

## Timeline

- **4 Dec 2025**: CVE-2025-66479 / GHSA-9gqj-5w7c-vx47 published; patched in 0.0.16; CVSS 1.8; reported by Ben Drucker ([GitHub Advisory](https://github.com/advisories/GHSA-9gqj-5w7c-vx47)).
- Context: srt is Apache-2.0 and underpins Claude Code's sandbox, whose network sandbox went GA on 20 Oct 2025 (v2.0.24) ([Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)).

## What happened

- srt's network policy has `allowedDomains` and `deniedDomains` lists ([sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)).
- When `allowedDomains` was configured as empty, the proxy enforced no network restriction at all, instead of denying every destination ([GitHub Advisory](https://github.com/advisories/GHSA-9gqj-5w7c-vx47)).
- A user who configured "no network" therefore got full network access through the proxy.

## Root cause

- **(f) unsafe default in the enforcement layer**: empty-list semantics were "no filter" rather than "deny all".
- Adversary: any (the gap is exploitable by whatever runs in the sandbox; A1 via injection, A3 unprompted).
- Boundary TB3: the only path out was open.

## Impact

Unrestricted egress for sandboxes configured with an empty allowlist. The low CVSS reflects the configuration precondition, not the consequence when it applies.

## Stopping control in this design

- **Would have prevented: fail-closed schema semantics.** **Proposal.** In [[broker.toml Human Policy Layer]] and the compiled Cedar policy, absence of a permit is a deny: Cedar semantics guarantee "A request is allowed only if it is explicitly permitted" ([cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)). An empty `[[egress]]` list compiles to no permits, therefore deny-all ([[Policy Engine and Entity Builder]]).
- **Would have prevented: compiler validation.** The TOML→Cedar compiler rejects ambiguous constructs (for example an empty list where a wildcard is meant) instead of guessing.
- **Would have caught it in CI: SymCC gates.** `check_always_allows` on high-risk actions and a "deny rules stay live" gate catch a policy that permits everything ([[SymCC CI Gates]]).
- **Would have prevented a degraded launch: [[I2 Fail-Closed Launch]]** and [[I6 Single Canonicaliser]] (unknown or unparseable destinations deny).
- **AUDIT** of actual egress shows allow decisions that should not exist.

## Regression test

- **Schema tests**: an empty allowlist, a missing `[[egress]]` section, an empty `methods` list and an empty `refs` list each produce deny-all for that dimension; a property test asserts that removing any permit never increases the allowed set.
- **L1 category 9 (proxy bypass) and 1**: with an empty policy, every outbound probe is denied and logged ([[L1 Conformance Suite]], [[Conformance Probe Matrix]]).

## How it connects

- mitigated-by:: [[I2 Fail-Closed Launch]]
- mitigated-by:: [[I6 Single Canonicaliser]]
- mitigated-by:: [[broker.toml Human Policy Layer]]
- mitigated-by:: [[Policy Engine and Entity Builder]]
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[L1 Conformance Suite]]
- example-of:: [[Claude Code and sandbox-runtime]]
- evaluated-by:: [[Risk Register]]

See also the second srt bypass, [[sandbox-runtime SOCKS NUL-Byte Bypass]].

## Implications for the build

- Working rule from [[CLAUDE]]: empty lists deny, unknown hosts deny, unmatched L7 requests deny, unparseable input denies. Every config field that is a list gets an explicit empty-list test.
- `broker why` must explain a deny caused by an empty list as "no rule permits this", not as an error.

## Open questions

- None specific to this incident.

## Sources

- [GHSA-9gqj-5w7c-vx47](https://github.com/advisories/GHSA-9gqj-5w7c-vx47)
- [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- [Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)
- [cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)
