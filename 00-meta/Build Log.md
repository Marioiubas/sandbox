---
title: "Build Log"
aliases: ["Changelog"]
type: meta
section: meta
tags: [sandbox/meta, meta, topic/build]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Chronological, append-only log Claude Code writes while building: date, milestone, what changed, notes updated, ADRs created, test status."
related: ["[[CLAUDE]]", "[[MVP Plan]]", "[[M0 Contained Run]]", "[[M1 Secrets Outside]]", "[[M2 Policy Audit and Learn]]", "[[M3 CI Identity and MCP]]", "[[M4 Harden and Ship]]", "[[Dashboard]]"]
sources: []
---

# Build Log

Append-only. One entry per work session, newest at the bottom. Never rewrite past entries; correct them with a new entry that links back. The current milestone is the first of [[M0 Contained Run]], [[M1 Secrets Outside]], [[M2 Policy Audit and Learn]], [[M3 CI Identity and MCP]], [[M4 Harden and Ship]] whose status is not `built` (see [[Dashboard]]).

## Entry template

Copy this block for each session:

```markdown
### YYYY-MM-DD: <short title>

- **Milestone:** [[M0 Contained Run]]
- **Goal of the session:** 
- **Built:** crates, modules, commands (with `code/...` paths)
- **Tests:** added / passing / failing (names); conformance probes added (category numbers)
- **Invariants touched:** I1-I9 affected and how each is still enforced
- **Notes updated:** [[...]] (status changes, Build log sections added)
- **ADRs created or changed:** [[ADR-0NN ...]]
- **Open questions resolved or raised:** link [[Open Questions and Unverified Claims]] entries
- **Next step:** 
```

## Milestone status

| Milestone | Status | Date built | Evidence (test run, commit) |
|---|---|---|---|
| [[M0 Contained Run]] | in progress: implemented; A1 verified on macOS 26 with Claude Code only | | CI run 35999705456 (commit 9a63853): 109 tests green on macOS 15/26 and Ubuntu 22.04/24.04 runners |
| [[M1 Secrets Outside]] | in progress: implemented; B1-B8 green in CI against local fakes on macOS 15/26 and Ubuntu 22.04/24.04; e2e with Claude Code's brokered login passes on macOS 26; real GitHub App run pending |  | CI run 36012256447 (commit 4c2a1ef): 190 tests and 11 fuzz targets green |
| [[M2 Policy Audit and Learn]] | not started |  |  |
| [[M3 CI Identity and MCP]] | not started |  |  |
| [[M4 Harden and Ship]] | not started |  |  |

## Proposed vocabulary additions

New tags or link verbs proposed during the build (see [[Vault Conventions]]):

- (none yet)

## Entries

### 2026-09-24: vault skeleton created

- **Milestone:** none (pre-build).
- **Built:** vault structure, `_manifest.json` (180 notes), [[CLAUDE]], [[00 Home]], all section MOCs, meta notes and templates. Content notes are being written by parallel writers from the manifest.
- **Next step:** Claude Code reads [[CLAUDE]] and starts [[M0 Contained Run]] once content notes are written.

### 2026-09-24: M0 contained run implemented

- **Milestone:** [[M0 Contained Run]] (in progress; not yet `built`).
- **Goal of the session:** build the M0 slice end to end and push the vault and code to `github.com/Marioiubas/sandbox`.
- **Built:** `code/` Cargo workspace (twelve crates plus `tests/conformance`); `netguard` (canonicaliser, broker DNS, CONNECT and SOCKS5 ingress, splice); `tls::sni_peek`; `policy` (fail-closed egress allowlist, address classes, pinned addresses, DoH deny list, built-in agent profiles); `launcher` (`macos-seatbelt`, `linux-native`, fs compiler, in-sandbox shim with pre-exec verification); `audit` (hash-chained SQLite); `brokerd` (ctl.sock with fd passing, sessions, write-ahead audit, L4 pipeline); `broker` CLI (`run`, `doctor`, `why`, `audit`, `daemon`); fuzz targets; CI workflow; `docs/threat-model.md`, `docs/policy-reference.md`; AppArmor profile for bwrap.
- **Tests:** 109 passing on macOS 26.5 and on Linux 6.12 (Docker, Ubuntu 24.04 userland, Landlock ABI 6); clippy `-D warnings` clean; fuzz targets `canon`, `connect`, `socks5`, `sni`, `jsonrpc` 60 s each without crashes. Conformance categories 3, 4, 5, 9, 10 added (category 7 enforced early on the L4 path). E2E `tests/e2e/fix_failing_test.sh claude` passes on macOS 26.
- **Invariants touched:** I2, I5, I6, I8, I9 have automated tests; I1 has an env/argv/proc canary test (full scan is M1) and is weakened for macOS `claude-code` sessions until M1 by ADR-016; I3, I4 and I7 have no code path yet (M1/M2).
- **Findings while building:** renaming `.git` and planting a `gitdir:` file bypassed hooks/config protection (closed, ADR-019); on Linux, missing protected files such as `.mcp.json` could be created (closed with placeholders); `session.start` was first logged after launch (made write-ahead, new `session.ready` event); Apple toolchain shims ignore `TMPDIR` (ADR-016); Claude Code's Bash tool needs `/tmp/claude-<uid>/<cwd-slug>` (profile variable); Docker's `/proc` masking stops bwrap from mounting procfs (probe now mirrors the launch).
- **Notes updated:** [[Hostname Canonicaliser]], [[Broker DNS Resolver]], [[Netguard Ingress]], [[Sandbox Launcher]], [[Broker CLI and Daemon]] set to `built`; build logs on [[Audit Recorder and Event Schema]], [[Core Trait Contracts]], [[Filesystem Control and Rollback]], [[Seatbelt]], [[bubblewrap]], [[Landlock]], [[seccomp-bpf]], [[Topology-Forced Egress]], the invariant notes, [[Tech Stack]], [[Repository Layout]], [[Conformance Probe Matrix]], [[L1 Conformance Suite]], [[M0 Contained Run]], [[Risk Register]] (R16, R17).
- **ADRs created:** [[ADR-016 macOS M0 Compatibility Exceptions]], [[ADR-017 Landlock Filesystem Layer Required]], [[ADR-018 seccomp Filter Shape for M0]], [[ADR-019 Mandatory Deny-Write List Additions]].
- **Open questions:** Landlock probe built (ABI 6 measured; ABI 10/11 still open); M0 crate pins recorded; macOS proxy-ignoring clients confirmed to fail closed. The I2 Landlock-degradation question is settled by ADR-017.
- **Next step:** get CI green on macOS 15/26 and Ubuntu 22.04/24.04; run the A1 e2e for Codex and on the Linux and macOS 15 cells; then mark M0 `built` and start [[M1 Secrets Outside]].

### 2026-09-24: M0 CI matrix green

- **Milestone:** [[M0 Contained Run]] (in progress).
- **Built:** CI fixes only: a Linux-only clippy lint in `brokerd`, and the AppArmor step now installs `packaging/apparmor/broker-bwrap` only when the userns gate is on (GitHub's Ubuntu 22.04 runner has AppArmor 3.x without `abi/4.0`).
- **Tests:** CI run 35999705456 (commit 9a63853): lint, fuzz smoke and 109 tests green on macOS 15, macOS 26, Ubuntu 22.04 (Landlock ABI 4) and Ubuntu 24.04 (Landlock ABI 7). The first run (35998906834) had already passed the tests on macOS 15/26 and Ubuntu 24.04.
- **Notes updated:** [[M0 Contained Run]], [[Landlock]], [[bubblewrap]], [[Open Questions and Unverified Claims]].
- **Next step:** A1 for Codex and for Claude Code on macOS 15 and Ubuntu (agent CLIs and credentials are not available on the runners); then mark M0 `built` and start [[M1 Secrets Outside]].

### 2026-09-24: M1 secrets outside implemented

- **Milestone:** [[M1 Secrets Outside]] (in progress; [[M0 Contained Run]] still has open A1 cells).
- **Goal of the session:** move every credential out of the sandbox: per-session CA and selective TLS termination, sentinels, foreign-credential rejection, GitHub App minting, git push scoping, method/path rules, response filtering.
- **Built:** `tls` (session CA, trust bundle, verified upstream client); `creds` (secrets, sentinels, foreign-credential inspection, static and `github_app` issuers, scope-digest cache); `l7` (head checks, response filter, git pkt-line / receive-pack / pack parsers and adapter, request classification); `policy` M1 keys (`protocol`, `methods`, `paths`, `allow`, `credential`, `passthrough`, `[issuers]`, `[tls]`, `${repo_remote}`) with `AllowedBinding`; `brokerd` L7 pipeline (`l7_pipeline.rs`, hyper 1.11) and per-session setup; `broker why` shows adapter verbs and credential IDs; built-in profiles broker the agents' own keys; conformance fixtures (test CA, fake API, fake GitHub with `git http-backend`), probes `tls-raw` and `secret-scan`; six fuzz targets.
- **Tests:** 190 passing on macOS 26.5 (unit, property, pipeline, M0 and M1 conformance, invariants); clippy `-D warnings` clean; fuzz targets `pktline`, `pack`, `delta`, `filter`, `remote_url`, `foreign` 60 s each without crashes. M1 acceptance: B1, B4, B5, B6, B7, B8 pass; B2 and B3 pass against a fake GitHub. E2E `tests/e2e/fix_failing_test.sh claude` passes on macOS 26 with Claude Code's OAuth token held only by the broker (15/15 API requests carried the brokered credential; keychain unreachable).
- **Invariants touched:** I1 now has its canonical scan test and the M0 keychain weakening is closed ([[ADR-020 Brokered Agent Credentials End the Keychain Exception]]); I7 is built with its canonical planted-key test; I6 covers Host, absolute-form authority, path and repository; I9 now records every L7 decision, including requests hyper refuses to parse.
- **Findings while building:** the `Claude Code-credentials` keychain item also holds ~40 MCP OAuth tokens, all readable under the M0 exception; hyper's `max_buf_size` does not bound request heads on a TLS stream (explicit 64 KiB limit added); a profile's own `filesystem` section was ignored in M0 (fixed); the M0 policy reference showed a rejected pattern (`*.githubusercontent.com`; now a docs test); the conformance probe could not send CRLF (escape handling fixed before trusting the framing tests).
- **Notes updated:** [[TLS Termination and Per-Session CA]], [[Credential Injector and Issuers]], [[Git Smart-HTTP Adapter]], [[Registry and LLM API Adapters]], [[I1 No Secrets in the Sandbox]], [[I7 Reject Foreign Credentials]], [[ADR-006 Deny Unmatched L7 Requests]] set to `built`; build logs on [[Sentinel Swap Pattern]], [[Just-in-Time Credential Minting]], [[GitHub App Installation Tokens]], [[Broker CLI and Daemon]], [[Sandbox Launcher]], [[Filesystem Control and Rollback]], [[Core Trait Contracts]], [[broker.toml Human Policy Layer]], [[Tech Stack]], [[Repository Layout]], [[Conformance Probe Matrix]], [[L1 Conformance Suite]], [[M1 Secrets Outside]]; [[Risk Register]] R17 closed, R18-R20 added.
- **ADRs created or changed:** [[ADR-020 Brokered Agent Credentials End the Keychain Exception]] (supersedes the keychain half of [[ADR-016 macOS M0 Compatibility Exceptions]]), [[ADR-021 L7 Path Choices for M1]].
- **Open questions resolved or raised:** hyper/rustls/rcgen pinned and exercised; GitHub branch scope still absent upstream (broker-enforced); ECH still unmeasured ([[Open Questions and Unverified Claims]]).
- **Next step:** CI on macOS 15/26 and Ubuntu 22.04/24.04; B2/B3 against a real throwaway GitHub App (needs the user's app key); then mark M1 `built`.

### 2026-09-24: M1 CI matrix green

- **Milestone:** [[M1 Secrets Outside]] (in progress).
- **Tests:** CI run 36012256447 (commit 4c2a1ef): lint, 190 tests on macOS 15, macOS 26, Ubuntu 22.04 and Ubuntu 24.04 (including the twelve M1 conformance tests, B1-B8), and the fuzz smoke over all eleven targets, all green. The M1 conformance tests also passed on Linux 6.12 in Docker (aarch64) before the push.
- **Notes updated:** [[M1 Secrets Outside]].
- **Next step:** B2/B3 against a real throwaway GitHub App on a test org with two repositories (the app key goes into the keychain or CI secrets, never the repository); then mark M1 `built`. M0 still needs A1 for Codex and on macOS 15/Ubuntu.

### 2026-09-24: M2 step 1, Cedar engine

- **Milestone:** [[M2 Policy Audit and Learn]] (in progress).
- **Built:** the compiled Broker schema, default and ceiling policy sets, the TOML-to-Cedar compiler for egress, L7 and git grants, the entity builder, and `EgressPolicy` deciding every admission and L7 request through `cedar-policy` 4.13.0 with a conjunctive repo layer; `broker learn` (record mode) with would-deny recording; the Task principal (user, agent binary hash, repo, 24 h expiry) built at session start.
- **Tests:** 37 policy tests including golden worked decisions and a 128-case property test that Cedar agrees with the M1 semantics; every M0/M1 conformance, pipeline and invariant suite passes unchanged on the engine.
- **Findings:** `cedar-policy` enables serde_json's `preserve_order` workspace-wide, which silently changed the audit's canonical key order; the canonical encoder now sorts keys itself and logs written by M0/M1 still verify. The build disk filled (228 GB volume at 100%); incremental build caches were removed and builds now run with `CARGO_INCREMENTAL=0`.
- **ADRs:** [[ADR-022 Cedar Schema and Engine as Built]].
- **Next step:** repository policy with content-hash approval; learning (`broker suggest`); OCSF export and SIEM sink; SymCC gates in CI; native config exporters.

### 2026-09-24: M2 step 2, repository policy and learning

- **Milestone:** [[M2 Policy Audit and Learn]] (in progress).
- **Built:** repository policy (`.broker/broker.toml`, `.broker/policy.cedar`) read on the host, conjoined only after `broker policy approve` records its content hash; `broker learn` (record mode) and `broker suggest` (`code/crates/learn`: observe, templatize, generalise with G2-G9 and P1-P3, replay); structured `actions` in L7 audit rows.
- **Tests:** 212 passing on macOS 26.5, including I4 end to end, learn-mode I8, and C1/C2 with a deterministic agent against fake upstreams. CI for step 1 (commit e5338be) green on macOS 15/26 and Ubuntu 22.04/24.04.
- **Invariants touched:** I4 built (conjunction, repo-scope key restrictions, approval); I5 extended to repository policy; I8 covers `broker learn`; I3 holds (the miner is deterministic and writes a diff a human must merge).
- **Next step:** OCSF export and a SIEM sink test (C4); SymCC gates in CI (C3); native config exporters; shadow mode.


### 2026-09-24: M2 step 3, OCSF export and SIEM sink

- **Milestone:** [[M2 Policy Audit and Learn]] (in progress).
- **Built:** OCSF 1.9.0 mapping and validation of every decision (Network Activity 4001, HTTP Activity 4002, API Activity 6003; class IDs verified from schema.ocsf.io), OTLP/HTTP JSON logs body, `broker audit export --format ocsf|hec|otlp [--to URL] [--token REF] [--from-seq N]` exporting only the verified prefix, with the chain hash and sequence in every event.
- **Tests:** C4 passes (`m2_ocsf::c4_events_validate_and_reach_the_sinks`): 100% of decisions validate, a HEC-style sink and an OTLP collector receive every event, the sink token is read from a secret reference, plain HTTP to a non-loopback sink is refused. 216 tests pass on macOS 26.5.
- **ADRs:** [[ADR-023 OCSF and OTLP Export as Built]] (pull export without the OTel SDK instead of live `opentelemetry-otlp` spans).
- **Open questions:** OCSF class names and IDs resolved; OTel GenAI conventions still open ([[Open Questions and Unverified Claims]]).
- **Next step:** SymCC gates in CI (C3); native config exporters; shadow mode.

### 2026-09-24: M2 step 4, formal gates

- **Milestone:** [[M2 Policy Audit and Learn]] (in progress).
- **Built:** `cedar-policy-symcc` 0.7.0 gates over every request environment (ceiling, credential confinement, never-errors, deny-live and repo-narrows hard; narrowing soft with counterexamples), `broker policy check`, gates inside `broker suggest`, cvc5 1.3.1 in CI with pinned digests and a gate check of every shipped profile.
- **Findings:** credential confinement could not be proved from entity data (the analyzer treats attributes as arbitrary), so each credential now has a textual confinement forbid; record mode allowed forced pushes (now denied); a literal "not always-allowed" check passes vacuously, so high-risk actions are proved to need approval or an explicit opt-in.
- **Tests:** 221 passing on macOS 26.5 with `BROKER_REQUIRE_SOLVER=1`, including C3.
- **Invariants touched:** I4 gains its formal gate; I3 holds (widenings shown, never applied); I1/I7 confinement now provable from the policy text.
- **ADRs:** [[ADR-024 Formal Gates as Built]].
- **Open questions:** SymCC feature coverage for this schema confirmed; scaling still open ([[Open Questions and Unverified Claims]]).
- **Next step:** native config exporters (Claude Code managed settings, Codex `requirements.toml`); shadow mode; then the M2 CI matrix.

### 2026-09-24: M2 step 5, native config exporters

- **Milestone:** [[M2 Policy Audit and Learn]] (in progress).
- **Built:** `broker policy export --target claude-code|codex --profile NAME`: Claude Code `managed-settings.json` and Codex `requirements.toml` compiled from the enforced policy, with an export report of everything only the broker enforces. Vendor schemas fetched from the vendors' docs first.
- **Tests:** property test that neither exported file admits a host or port the broker denies (documented matchers); golden files for all six shipped profiles × two targets.
- **ADRs:** [[ADR-025 Native Config Exporters as Built]] (no proxy chaining, no MCP allowlist until M3, Cursor/OpenShell in phase 2).
- **Next step:** shadow mode; then the M2 CI matrix and milestone review.

### 2026-09-24: M2 step 6, shadow mode

- **Milestone:** [[M2 Policy Audit and Learn]] (in progress).
- **Built:** `broker policy shadow <file> | --off | --report`; enforce sessions run in mode `shadow` while a candidate is active, with the candidate's verdict on every admission and L7 decision row; `broker why` shows it. The daemon's session start and L7 answer code split into child modules (files under 500 lines).
- **Tests:** `m2_shadow::a_shadow_candidate_is_logged_but_never_decides`; 227 passing on macOS 26.5 with the solver required.
- **ADRs:** [[ADR-026 Shadow Mode as Built]].
- **Next step:** M2 CI matrix; milestone review (C1 over 3 real repos × 3 real agents needs Codex and Gemini CLI logins).

### 2026-09-24: M2 step 7, audit query, a same-host over-grant, plan reconciled

- **Milestone:** [[M2 Policy Audit and Learn]] (in progress).
- **Built:** `audit.query` on the control socket and `broker audit query` (every filter validated at the boundary; hosts through the canonicaliser).
- **Found and fixed:** a plain `[[egress]]` entry compiled to an `#any` permit; with a `methods = ["GET"]` entry for the same host, the host was terminated and `DELETE` was allowed through the plain entry. Plain entries are now L4 admission only ([[ADR-027 Plain Host Grants Carry No L7 Authority]]).
- **Reconciled:** the M2 task list against the code ([[ADR-028 M2 Plan Items Built Differently or Deferred]]); [[Audit Recorder and Event Schema]], [[Policy Learning Loop]], [[Policy Miner Safeguards]] and [[broker.toml Human Policy Layer]] set to `built` for their M2 scope.
- **CI:** steps 1-6 green on macOS 15/26 and Ubuntu 22.04/24.04 (lint, tests, fuzz smoke).
- **Open for M2:** C1 over 3 repositories × 3 real agents (needs Codex and Gemini CLI signed in).
- **Next step:** M3 work that needs no external accounts (MCP Guard with pinned tool descriptions against local MCP servers; the GitHub MCP toxic-flow replay against a fake GitHub).

### 2026-09-24: M3 step 1, GitHub API adapter and session labels

- **Milestone:** [[M3 CI Identity and MCP]] (in progress).
- **Built:** GitHub REST requests map to verbs (`repo.read`, `pr.create`, `pr.merge`, `issue.comment`, `contents.write`, `github.read`, `gist.create`) or deny; `protocol = "github"` grants verbs on repositories; the broker learns repository visibility with the bound credential and decides again; raise-only session labels from API facts drive the Rule-of-Two forbid.
- **Tests:** D5, the toxic-flow replay, passes against a fake GitHub API; the benign public-issue-then-PR case is allowed; route property test and fuzz target (634k runs locally); Cedar agrees with the explainer on verbs; 241 tests pass on macOS 26.5; all shipped profiles pass the formal gates.
- **Found:** every credential entity carried `risk: "high"`, which under the label rules would have blocked every write after any public-issue read; risk now comes from config.
- **ADRs:** [[ADR-029 GitHub API Adapter and Session Labels as Built]].
- **Next step:** MCP Guard (D3, D4) with local stdio MCP servers.

### 2026-09-25: M3 step 2, MCP Guard

- **Milestone:** [[M3 CI Identity and MCP]] (in progress).
- **Built:** pinned stdio MCP servers ([[ADR-030 MCP Guard as Built]]): `[mcp.<name>]` in user/org policy, the in-sandbox stub `broker mcp connect`, each server started by the daemon as its own sandboxed session with its own egress and sentinel credentials, manifest pinning before any relay, `broker mcp approve`/`list` on the host, strict framing (`mcpguard`), per-call Cedar authorization with labels, refusal of server-to-client requests, re-pin on `list_changed`.
- **Tests:** D3 and D4 pass against fakes; I1 and I5 extended to MCP principals; property tests and the `mcp_frame` fuzz target (1.4 M runs locally); 249+ tests pass on macOS 26.5.
- **Found:** the launcher refused to make a working directory inside broker state writable, as I5 requires; server working directories now live in the temp area.
- **CI:** M3 step 1 failed its test jobs because a policy-reference example named an undefined GitHub App issuer (the docs test compiles every example); fixed in this push.
- **Next step:** CI mode (D1) with GitHub Actions OIDC; AWS STS minting against a fake STS endpoint (D6).

### 2026-09-25: files under 500 lines

- **Refactor, no behaviour change:** the six Rust files at or over 500 lines split into child modules: `netguard/src/canon.rs` (877 → 308; `canon/{addr,pattern,path,tests,props}.rs`), `policy/src/l7.rs` (746 → 344; `l7/{credential,secret,explain}.rs`), `policy/src/egress.rs` (716 → 410; `egress/{authorize,mcp,tests}.rs`), `tests/conformance/src/bin/conformance-probe.rs` (564 → 129; `conformance-probe/{proxy,net,fs,secrets}.rs`), `launcher/src/backends/linux/inner.rs` (541 → 473; `inner/bridge.rs`), `audit/src/reason.rs` (500 → 419; `reason/explain.rs`). Public paths unchanged (re-exports); one canonicaliser (I6) and its lint intact.
- **Tests:** the full suite passes on macOS 26.5 with the same 249 tests as before; clippy clean for the host and, for the launcher, the Linux target; every shipped profile passes the formal gates.
- **Notes updated:** [[Hostname Canonicaliser]], [[Registry and LLM API Adapters]], [[Policy Engine and Entity Builder]], [[Conformance Probe Matrix]], [[Sandbox Launcher]], [[Audit Recorder and Event Schema]].

### 2026-09-25: M3 step 3, CI identity

- **Milestone:** [[M3 CI Identity and MCP]] (in progress).
- **Built:** the `grant` crate (strict JWS parsing, RS256 verification, OIDC identity checks); `[[identity.oidc]]` issuers in user/org policy; `brokerd` verifies a runner token before assembling a session (keys via discovery, `jwks_url` or `jwks_file`; public addresses only; cached, refetched once on key rotation) and attributes the session and every row to its subject; the GitHub Action (`code/integrations/github-action`) and the D1 untrusted-issue fixture, run by a new `ci-mode` CI job with the real runner token.
- **Found:** running the fixture locally from the repository root was refused because the broker binaries sat inside the agent's writable working tree (I5, correct); the CI job and the action README install the binaries outside the workspace. The first `ci-mode` run failed because the job canary was written inline in `ci.yml`, which the agent can read in its checkout (the scan was right); the canary is now random per run and never in the repository.
- **Tests:** `grant` unit and property tests, `m3_identity` (attribution, token never in the agent, refusal on audience, expiry, signature, malformed token and unconfigured issuer), fuzz target `jwt` (5.7 M runs locally).
- **Moved:** the launch step from `crates/brokerd/src/session.rs` to `crates/brokerd/src/session/launch.rs` (500-line rule; no behaviour change).
- **ADRs:** [[ADR-031 CI Identity as Built]].
- **Next step:** AWS STS minting and SigV4 re-signing against a fake STS/S3 (D6).

### 2026-09-25: M3 step 4, AWS STS and the S3 adapter

- **Milestone:** [[M3 CI Identity and MCP]] (in progress).
- **Built:** S3 grants (`protocol = "s3"`, bucket plus read/write/delete prefixes) and the `l7::s3` adapter (every request is `s3.get`, `s3.list`, `s3.put` or `s3.delete` on one bucket and key, or denied); Cedar actions for them; the `aws_sts` issuer (`AssumeRole` signed by the broker with the base credentials, inline session policy compiled from the grant and size-checked at compile time, 15-minute default, `SourceIdentity`); SigV4 re-signing of authorized S3 requests with the minted session; sentinel `AWS_ACCESS_KEY_ID` and a placeholder secret key in the sandbox; SigV4 `Authorization` headers inspected for foreign access keys.
- **Verified:** the STS request and response details and the SigV4 procedure against AWS's own documentation (2026-09-25); the signer against four AWS SigV4 test-suite vectors and against curl's `--aws-sigv4`.
- **Found:** clippy flagged the repository-policy `Status` enum once `IssuersSection` grew; the approved policy is now boxed.
- **Tests:** `m3_s3::d6_*` (reads and in-prefix writes through minted credentials; out-of-prefix writes, ACL headers and subresources denied at the broker and never forwarded; the session policy alone denies out-of-prefix writes; a planted AWS key is rejected), `policy::s3::tests::broker_and_aws_agree` (property), `cedar::s3_tests::*` (including Cedar agreeing with the reference check), `l7::s3::tests::*` (including a canonical-form property test), `creds::issuers::{sigv4,aws_sts}::tests::*`; the formal gates now include an S3 grant (credential confinement proved); fuzz target `s3_route` (2.3 M runs locally).
- **ADRs:** [[ADR-032 AWS STS and S3 Adapter as Built]].
- **Next step:** what remains in M3 needs outside resources (Okta/Entra tenants for D2, a GitHub token for the real MCP server run, an AWS test account for D6 against real S3); the org public-sink option and GraphQL mapping can proceed without them.

### 2026-09-25: M3, the org public-sink rule

- **Milestone:** [[M3 CI Identity and MCP]] (in progress).
- **Built:** `[trifecta] deny_public_sinks_after_untrusted_input` (user or org policy, off by default) compiling to two Cedar forbids with reason `public_sink_after_untrusted_input`; repository policy may not set it.
- **Found:** the first version lost the forbids when the MCP permits rebuilt the engine; the end-to-end test caught it, and option policies are now part of every rebuild.
- **Also:** the `ci-mode` attribution step prints the subject, issuer and run ID and checks them with `jq` (the D1 fixture passed on CI after the canary fix; the attribution grep did not match, and the step now shows why).
- **Tests:** `cedar::github_tests::the_org_option_denies_public_sinks_after_untrusted_input`, `gates::tests::the_public_sink_option_is_a_proved_narrowing`, `m3_github::with_the_org_option_the_public_pr_after_a_public_issue_is_denied`.
- **ADRs:** [[ADR-033 Public-Sink Rule as Built]].

