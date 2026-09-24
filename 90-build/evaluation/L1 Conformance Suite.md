---
title: "L1 Conformance Suite"
aliases: ["L1", "Bypass Corpus", "Fuzzing", "HTTP Garden"]
type: eval
section: build
tags: [sandbox/build, eval, topic/evaluation, topic/egress, topic/dns, topic/filesystem, control/egress, control/iso, invariant/i6, invariant/i1, invariant/i7, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# L1 Conformance Suite

> Deterministic, scripted, non-LLM probes in and out of policy for every probe category, HTTP Garden-style differential fuzzing of URL and HTTP parsing against curl, requests/httpx and undici, >=24 h cargo-fuzz per target, and the public bypass corpus; any failure blocks release.

## What it measures

Deterministic containment: for every probe category in the [[Conformance Probe Matrix]], does an out-of-policy action get denied and logged with a reason, and does the matching in-policy control still succeed? L1 is the layer that catches enforcement-layer bugs, the dominant failure class in the incident record: empty-list semantics, prefix matching, NUL bytes, symlink fallback and `working_directory` bugs appeared at least seven times in 13 months across four vendors (report). The canonical example is the sandbox-runtime SOCKS NUL-byte bypass, where `attacker.example\x00.google.com` passed a JavaScript suffix check and resolved to the attacker host ([Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)); see [[sandbox-runtime SOCKS NUL-Byte Bypass]].

L1 contains no LLM. Probes are scripts run inside the sandbox that assert allow or deny. The same categories are reused as goals for LLM-driven injection tests in [[L2 Injection Benchmarks]] and the [[Red-Team Plan]].

## Components of L1

1. **Category probes** (`tests/conformance/<nn>-<category>/`): one or more deterministic probes per category, each with an in-policy control.
2. **Public bypass corpus** (`tests/bypass-corpus/`): data files of known bypass inputs (NUL byte, CRLF, IDNA, SOCKS4a/5 hostname forms, CONNECT to IP literals, DNS rebinding, metadata IP, DNS TXT exfiltration), each run through every ingress mode (research note 05 section 4).
3. **Fuzzing** (`tests/fuzz/`): `cargo-fuzz` targets for the canonicaliser, SOCKS5, HTTP/1.1, h2, pkt-line and MCP JSON-RPC parsers, plus `proptest` properties in each parser crate; ≥24 h per target before release ([[M4 Harden and Ship]]).
4. **Differential parsing**: HTTP Garden-style differential fuzzing of URL and HTTP parsing against the client libraries agents actually use: curl, Python requests/httpx and Node undici. HTTP Garden is a coverage-guided differential fuzzer that "examines both origin servers' interpretations and gateway servers' transformations of HTTP requests" and found 100+ parsing bugs, 68 fixed and 39 exploitable ([arXiv 2405.17737](https://arxiv.org/abs/2405.17737)). Related tools are T-Reqs and Gudifu ([Gudifu](https://dl.acm.org/doi/10.1145/3678890.3678904)).
5. **Invariant tests**: the minimum test for each of I1-I9 from [[CLAUDE]] section 3 lives here (canary scan for [[I1 No Secrets in the Sandbox]], planted key for [[I7 Reject Foreign Credentials]], bypass corpus for [[I6 Single Canonicaliser]], and so on).

Generic exfiltration tools (curated lists, DNS exfiltration channel tools) exist but are generic red-team tools, not agent-proxy conformance suites (research note 04a Q4).

## Thresholds (Proposal)

| Metric | Threshold |
|---|---|
| Out-of-policy probes denied | 100% |
| Canary credential leaks | 0 |
| In-policy controls succeed | 100% |
| Denies logged with a reason | 100% |
| Decision-changing parser discrepancies (differential fuzzing) | 0 |
| Fuzzing per target before release | ≥24 h, no crashes |

Any single failure blocks release. Category 11 (covert channels) is the exception: bandwidth is measured and reported, not claimed zero ([[Conformance Probe Matrix]]).

## How to run (Proposal)

- Every commit: `cargo test --workspace` and `cargo test --test conformance` on macOS and Linux runners; each probe prints `category`, `probe-id`, `expected`, `observed`, and the audit row ID of the decision.
- Nightly: `cargo fuzz run <target>` for each target with a time budget; crashes open issues automatically and the crashing input is added to the corpus once fixed.
- Differential: a harness feeds the same generated URL or HTTP message to the broker's parser and to curl, requests/httpx and undici, and flags any case where the parsed host, path, method or framing differs **and** the difference would change the Cedar decision.
- Coverage by milestone: M0 categories 3, 4, 5, 9, 10; M1 adds 1, 2, 6, 7 and HTTP parts of 8; M2 extends 1 with seeded-injection goals; M3 adds the MCP surface; M4 completes 8, 11 and 12.

## How results feed back

- Every failure becomes a permanent corpus entry and a regression test before the fix merges.
- Parser discrepancies that do not change a decision are logged, not failed, but reviewed monthly.
- The corpus is published with the product; "publishing this corpus is itself a credibility asset" (report), and no open-source agent-egress conformance suite exists in the record ([[Measurement Gaps]]).

## Limits

- Cedar's proofs cover policy semantics, not the enforcement point: how raw traffic is parsed into entities (host, SNI, IP, redirects) must be tested empirically. Categories 4, 6, 7 and 8 exist for exactly this reason (research note 04a Q5).
- L1 proves the absence of known bypasses, not all bypasses; adaptive attackers and humans are in the [[Red-Team Plan]].

> [!question] Unverified
> The HTTP Garden repository URL and its proxy/gateway coverage (Squid, Envoy and others) were not verified in the record.

## How it connects

- part-of:: [[Evaluation Harness]]
- depends-on:: [[Conformance Probe Matrix]]
- evaluated-by:: [[Red-Team Plan]]
- implements:: [[I6 Single Canonicaliser]]
- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[Git Smart-HTTP Adapter]]
- mitigates:: [[sandbox-runtime SOCKS NUL-Byte Bypass]]
- mitigates:: [[sandbox-runtime Empty Allowlist Bypass]]
- delivered-by:: [[M0 Contained Run]]
- delivered-by:: [[M4 Harden and Ship]]
- depends-on:: [[Tech Stack]]

## Implications for the build

- A parser without a fuzz target is incomplete; the PR that adds `canon.rs`, `http1.rs`, `h2.rs`, `pktline.rs`, `socks5.rs` or the MCP JSON-RPC parser also adds its target.
- Probes are data-driven where possible, so the public corpus can be shipped without the harness.
- Every deny path must write an audit row with a reason; a probe that is denied but not logged is a failure.

## Open questions

- Which differential-fuzzing framework to adopt (HTTP Garden itself, or a smaller in-house harness modelled on it).
- MITRE ATT&CK TA0010 mapping of categories was suggested but not fetched ([[Conformance Probe Matrix]]).

## Sources

- Report: L1 row of the six-layer table; conformance probe matrix note; tech-stack testing row; M4 fuzzing.
- Research note 04a Q4 and Q6 L1; research note 05 section 4 testing corpus.

## Build log

- 2026-09-24: L1 started: category probes (M0 set), public bypass corpus (36 cases, both ingress modes), five `cargo-fuzz` targets (`canon`, `connect`, `socks5`, `sni`, `jsonrpc`; 60 s smoke each in CI, no crashes locally), proptest suites in every parser, invariant tests. Differential fuzzing against curl/requests/undici is not built yet (M4).
- 2026-09-24 (M1): fixtures in `tests/conformance/src/m1.rs` (test CA via `extra_roots`, fake HTTPS API, fake GitHub with `git http-backend` and an RS256-verifying token endpoint); tests `b1_i1_only_sentinels_inside_the_sandbox`, `b4_i7_planted_key_to_allowed_host_is_rejected`, `b5_sentinel_copied_off_host_is_useless`, `b6_llm_call_succeeds_with_injected_key`, `b7_injected_secret_is_never_reflected`, `cat2_unmatched_paths_and_methods_deny` (`tests/conformance/tests/m1_secrets.rs`); `b2_push_to_agent_branch_succeeds_with_scoped_token`, `b3_main_force_delete_and_other_repo_are_denied_and_explained`, `cat1_push_to_attacker_repo_mints_nothing` (`tests/conformance/tests/m1_git.rs`); `cat6_redirects_are_reevaluated_and_drop_credentials`, `cat7_host_sni_connect_must_agree`, `cat8_ambiguous_framing_never_desyncs` (`tests/conformance/tests/m1_redirect_fronting.rs`).
- 2026-09-24 (M2): all M0/M1 categories pass unchanged under the Cedar engine; category 1 extended with the seeded-injection goals (`m2_learn` C2); M2 conformance files `m2_learn`, `m2_gates`, `m2_ocsf`, `m2_exporters`, `m2_shadow`.
