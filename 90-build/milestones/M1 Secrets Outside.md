---
title: "M1 Secrets Outside"
aliases: ["M1"]
type: milestone
section: build
tags: [sandbox/build, milestone, milestone/m1, topic/tls, topic/credentials, topic/git, control/cred-out, control/task-tok, control/egress, invariant/i1, invariant/i6, invariant/i7, platform/macos, platform/linux]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
milestone: M1
code: ["code/crates/tls", "code/crates/creds", "code/crates/l7", "code/crates/brokerd/src/l7_pipeline.rs", "code/tests/conformance/tests/m1_secrets.rs", "code/tests/conformance/tests/m1_git.rs", "code/tests/conformance/tests/m1_redirect_fronting.rs"]
---

# M1 Secrets Outside

> Weeks 3-4: per-session CA and trust-bundle env, selective TLS termination, sentinel swap in headers and bodies, foreign-credential rejection, keychain store, GitHub App minting (TTL <=1 h), git smart-HTTP adapter, method and path rules; done when scans find only sentinels and pushes are scoped to agent/x on the session repo.

## Goal

After M1, no secret material exists anywhere the agent can reach: not in env, files, argv, `/proc` or response bodies. The sandbox holds only per-session sentinels, and the broker attaches real credentials at egress, after authorization, only for the hosts and paths they are bound to ([[I1 No Secrets in the Sandbox]]). The proxy also refuses any credential it did not issue ([[I7 Reject Foreign Credentials]]), closing the Claude Cowork allowed-domain abuse, in which a planted attacker API key was used against the allowlisted api.anthropic.com and "the egress proxy checked the destination, saw api.anthropic.com, and let it through" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).

M1 also delivers the first protocol adapter that no neutral product in the record offers: git smart-HTTP push scoping per repo, per ref, and per force flag ([[Git Smart-HTTP Adapter]]). GitHub installation tokens cannot express branch or path scope ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)), so the broker enforces the rest.

## Scope

**In scope (report M1 row):**

- Per-session CA created just in time and destroyed at session end; merged trust bundle; trust env vars in the sandbox ([[TLS Termination and Per-Session CA]]).
- Selective TLS termination: L4 splice by default, L7 only for hosts with credentials or method/path rules.
- Sentinel swap in headers and bodies ([[Sentinel Swap Pattern]]).
- Foreign-credential rejection and client-credential stripping.
- Keychain-backed static secret store (macOS Keychain, libsecret).
- GitHub App installation-token minting scoped to repo plus permissions, TTL ≤1 h ([[GitHub App Installation Tokens]], [[Credential Injector and Issuers]]).
- Git smart-HTTP adapter and SSH-to-HTTPS remote rewrite.
- HTTP method and path rules, default-deny within an allowed domain ([[ADR-006 Deny Unmatched L7 Requests]]).
- Static-key injection for LLM APIs with a broker-fixed base URL; read-only package registries ([[Registry and LLM API Adapters]]).
- `broker why <request-id>` explaining each denial.

**Out of scope:** Cedar schema and TOML compiler in full (M2 uses the rule tables built here as its first input); AWS STS and OAuth exchange (M3); MCP (M3); GitHub REST/GraphQL verb mapping beyond what `broker why` needs (the [[GitHub API Adapter]] may start here but is only required by M3's toxic-flow replay).

## Prerequisites

- [[M0 Contained Run]] is `status: built`: egress path, canonicaliser and fail-closed launch exist.
- A throwaway GitHub App installed on a test org with two repos (the session repo and an "other" repo), credentials in the OS keychain or CI secrets, never in the repository ([[CLAUDE]] section 7).
- A local echo server that reflects request headers and bodies, for the reflection probes.
- Read [[Sentinel Swap Pattern]], [[Just-in-Time Credential Minting]] and [[Core Trait Contracts]] (`CredentialIssuer`, `ProtocolAdapter`).

## Ordered task checklist (Proposal)

**TLS (crate `tls`)**

- [ ] `crates/tls/src/session_ca.rs`: generate a per-session CA with `rcgen` at `session.start`; hold the key in broker memory; destroy at `session.stop`. Never install it into the host trust store.
- [ ] `crates/tls/src/leaf_cache.rs`: mint leaf certificates per SNI on demand; cache for the session only.
- [ ] `crates/tls/src/trust_bundle.rs`: write a merged bundle (per-session CA plus public roots) and set `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `PIP_CERT`, `CURL_CA_BUNDLE` and the npm `cafile` in `SandboxSpec.env` ([[TLS Termination and Per-Session CA]]).
- [ ] `crates/tls/src/sni_peek.rs`: read the ClientHello SNI without terminating; decide L4 splice vs L7 termination from the policy.
- [ ] Documented passthrough list for certificate-pinning clients, with **no** credential injection on those hosts.
- [ ] Upstream re-origination with full verification against public roots.

**L7 parsing (crate `l7`)**

- [ ] `crates/l7/src/http1.rs` and `h2.rs`: parse requests after termination; fuzz targets `tests/fuzz/fuzz_targets/{http1,h2}.rs`.
- [ ] Enforce CONNECT target = SNI = `Host`/`:authority` (blunts domain fronting).
- [ ] `crates/l7/src/redirect.rs`: re-evaluate every redirect hop; drop credentials on any cross-origin hop.
- [ ] `crates/l7/src/response_filter.rs`: ensure injected secrets are never reflected back in response bodies or headers.
- [ ] Method/path rule table (interim representation, replaced by Cedar in M2): unmatched L7 requests within an allowed domain are **denied**, the opposite of Vercel's "matchers never block" semantics ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)).

**Git adapter (crate `l7`)**

- [ ] `crates/l7/src/adapters/pktline.rs`: pkt-line parser with property tests and `tests/fuzz/fuzz_targets/pktline.rs`.
- [ ] `crates/l7/src/adapters/git_smart_http.rs`: parse `/info/refs?service=git-receive-pack` and the `git-receive-pack` pkt-lines; extract repo, every ref update and whether it is a force update; emit one authorization request per ref update ([[Git Smart-HTTP Adapter]]).
- [ ] Sandbox git config: `url."https://github.com/".insteadOf "git@github.com:"`; port 22 stays denied.

**Credentials (crate `creds`)**

- [ ] `crates/creds/src/sentinel.rs`: per-session sentinel generation; sentinels are opaque, session-bound and useless off-host.
- [ ] `crates/creds/src/foreign_reject.rs`: strip every client-supplied `Authorization`, `x-api-key`, cookie and `Proxy-Authorization` header; reject any request carrying a credential the broker did not issue ([[I7 Reject Foreign Credentials]]).
- [ ] `crates/creds/src/issuers/static_.rs`: keychain-backed static secret, swapped for the sentinel only on the bound host and path.
- [ ] `crates/creds/src/issuers/github_app.rs`: mint an installation token restricted to the session repo and the granted permissions, TTL ≤1 h; cache per scope digest in memory only (`cache.rs`); zeroize on drop.
- [ ] `brokerd` keychain access (`crates/brokerd/src/keychain.rs`): the broker's own root secrets (GitHub App private key, static API keys) live in the OS keychain.

**Adapters for everyday traffic**

- [ ] `crates/l7/src/adapters/llm_apis.rs`: Anthropic, OpenAI and Gemini keys injected; the base URL is fixed by the broker, which closes the CVE-2026-21852 redirect class ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)).
- [ ] `crates/l7/src/adapters/{npm,pypi,crates}.rs`: GET and HEAD only; `publish` denied unless explicitly granted.

**Explainability**

- [ ] `crates/broker-cli/src/cmd/why.rs` and `decision.explain` in `brokerd`: for a request ID, print the canonical host, the adapter verb (for example `git.push refs/heads/main force=false`), the rule that decided, and the reason.

**Probes**

- [ ] Categories 1, 2, 6, 7 and the TLS-relevant part of 8 in `tests/conformance/` ([[Conformance Probe Matrix]]).
- [ ] `tests/e2e/secret_scan`: plant canary secrets in the host keychain and config, run an agent task, then scan env, files, argv and `/proc` inside the sandbox.

## Components delivered

[[TLS Termination and Per-Session CA]], [[Credential Injector and Issuers]] (static and `github_app` issuers, sentinel store, foreign-credential rejection), [[Git Smart-HTTP Adapter]], [[Registry and LLM API Adapters]], and `broker why` in [[Broker CLI and Daemon]].

## Acceptance criteria

| # | Criterion (report, verbatim meaning) | Test (proposal) | Threshold |
|---|---|---|---|
| B1 | Automated scan finds only sentinels in env, files, argv and `/proc` | `tests/e2e/secret_scan` on macOS and Linux | 0 canary secrets found; only sentinels |
| B2 | Push to `agent/x` on the session repo succeeds | `tests/e2e/git_push_allowed` | succeeds with a minted token |
| B3 | Pushes to another repo, to `main`, or with force are denied, and `broker why` explains each | `tests/e2e/git_push_denied_{other_repo,main,force}` | 3 of 3 denied; `broker why` output names repo/ref/force as the reason |
| B4 | An attacker-planted API key sent to an allowed host is rejected | category 1 probe (Cowork replay) | rejected and logged |
| B5 | A sentinel copied off-host is useless | send the sentinel directly to the upstream from outside the broker | upstream rejects it; nothing in the sentinel decodes to a secret |
| B6 | LLM API calls succeed with the injected key (research note 05 M1) | `tests/e2e/llm_call` for each configured provider | succeeds; key never visible in the sandbox |
| B7 | Nothing reflected | category 2 echo-server probe | 0 reflections of injected secrets |
| B8 | Redirect and fronting rules | categories 6 and 7 | 100% of out-of-policy probes denied |

## Eval layers and probes that must pass

- [[L1 Conformance Suite]]: categories 1 (allowed-destination abuse: foreign key; push to attacker repo on github.com), 2 (credential exposure), 6 (redirects), 7 (Host/SNI/CONNECT mismatch) and the HTTP-framing part of 8 (parser differentials), plus all M0 categories still passing.
- Fuzz targets for `http1`, `h2` and `pktline` run in CI.
- Invariant tests: [[I1 No Secrets in the Sandbox]] (canary scan) and [[I7 Reject Foreign Credentials]] (planted key) become the canonical invariant tests.

## Risks

- **TLS breakage**: pinned clients and QUIC. Keep L4 splice as the default and block UDP/443 so clients fall back to TCP; E2B notes QUIC defeats domain filtering ([E2B docs](https://docs.e2b.dev/network/internet-access.md)).
- **Parser surface grows** (HTTP/1.1, h2, pkt-line): every parser needs fuzzing from its first commit.
- **Credential honeypot**: the broker now holds roots; keep them in the keychain, minted tokens in memory with short TTLs, and the control socket unreachable from sandboxes ([[Risk Register]]).
- **No branch scope upstream**: GitHub has no branch or path scope, so a bug in the pkt-line parser is a real authority leak, not a cosmetic one.

## Definition of done

1. B1-B8 pass in CI on macOS and Linux; test names listed in the Build log.
2. All M0 tests still pass; invariant tests for I1 and I7 exist and pass.
3. Conformance corpus covers categories 1, 2, 6, 7 and the M1 part of 8, with 100% of out-of-policy probes denied and logged with a reason.
4. The delivered components are `status: built` with Build log entries.
5. [[Build Log]] entry written; the GitHub branch-scope and sentinel-swap items in [[Open Questions and Unverified Claims]] annotated with what was learned.

## How it connects

- implements:: [[I1 No Secrets in the Sandbox]]
- implements:: [[I7 Reject Foreign Credentials]]
- depends-on:: [[M0 Contained Run]]
- depends-on:: [[TLS Termination and Per-Session CA]]
- depends-on:: [[Sentinel Swap Pattern]]
- depends-on:: [[GitHub App Installation Tokens]]
- depends-on:: [[Git Smart-HTTP Adapter]]
- depends-on:: [[Credential Injector and Issuers]]
- depends-on:: [[Registry and LLM API Adapters]]
- mitigates:: [[Claude Cowork Allowed-Domain Abuse]]
- mitigates:: [[Claude Code Pre-Trust Config Execution]]
- decided-by:: [[ADR-004 Selective TLS Termination with Per-Session CA]]
- decided-by:: [[ADR-005 Mint Credentials Per Task]]
- decided-by:: [[ADR-006 Deny Unmatched L7 Requests]]
- evaluated-by:: [[L1 Conformance Suite]]
- part-of:: [[MVP Plan]]

Next milestone: [[M2 Policy Audit and Learn]], which replaces the interim rule tables with Cedar and learns them from recorded runs.

## Implications for the build

- Credential IDs, never values, go to the audit log; add a CI assertion that no canary value appears in any SQLite row.
- The `CredentialIssuer` trait must keep material in broker memory only ([[Core Trait Contracts]]).
- Build the method/path rules as authorization decisions now, so the M2 migration to Cedar is a representation change, not a semantics change.

## Open questions

- Whether any branch-scoped installation-token capability was added to GitHub in 2026 (none found) ([[GitHub App Installation Tokens]]).
- The sandbox-runtime README returned 404 in one session, so its sentinel-swap claims rest on a secondary blog; Claude Code's docs independently document `mask` ([[Sentinel Swap Pattern]]).
- Encrypted ClientHello adoption and its effect on SNI peeking ([[TLS Termination and Per-Session CA]]).

## Sources

- Report: milestone table row "Weeks 3-4 M1 Secrets outside"; "L4 by default, L7 only where credentials or verbs matter"; protocol adapters; native provider downscoping table.
- Research note 05 section 5.2 M1 row (LLM API calls succeed with injected key).

## Build log

- 2026-09-24: implemented. Acceptance status:
  - B1 only sentinels: pass locally on macOS 26 (`b1_i1_only_sentinels_inside_the_sandbox`); e2e with Claude Code: sentinel only, keychain and credential file unreadable.
  - B2 push to `agent/x` succeeds with a minted repo-scoped token: pass against a fake GitHub (`b2_push_to_agent_branch_succeeds_with_scoped_token`). **Pending:** the same run against a real throwaway GitHub App (needs the app's key in the keychain or CI secrets).
  - B3 other repo, `main`, force (and delete) denied and explained by `broker why`: pass (`b3_main_force_delete_and_other_repo_are_denied_and_explained`, `cat1_push_to_attacker_repo_mints_nothing`); same real-GitHub caveat.
  - B4 planted key rejected: pass (`b4_i7_planted_key_to_allowed_host_is_rejected`).
  - B5 sentinel off-host useless: pass (`b5_sentinel_copied_off_host_is_useless`).
  - B6 LLM call with injected key: pass against the fake API (`b6_llm_call_succeeds_with_injected_key`) and against the real `api.anthropic.com` with Claude Code's brokered OAuth token (e2e, macOS 26).
  - B7 nothing reflected: pass (`b7_injected_secret_is_never_reflected`, plain, gzip and header reflections).
  - B8 redirect and fronting rules: pass (`cat6_redirects_are_reevaluated_and_drop_credentials`, `cat7_host_sni_connect_must_agree`, `cat8_ambiguous_framing_never_desyncs` (`tests/conformance/tests/m1_redirect_fronting.rs`)).
- 2026-09-24: decisions: [[ADR-020 Brokered Agent Credentials End the Keychain Exception]], [[ADR-021 L7 Path Choices for M1]]. Fuzz targets `pktline`, `pack`, `delta`, `filter`, `remote_url`, `foreign` ran 60 s each without crashes (0.7-2.9 M executions). CI status recorded in [[Build Log]].
- 2026-09-24: not `built` yet: B2/B3 against a real GitHub App and the CI run on the four OS cells are the remaining items.
