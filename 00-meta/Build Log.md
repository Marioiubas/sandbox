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

