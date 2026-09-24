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
| [[M0 Contained Run]] | in progress: implemented; A1 verified on macOS 26 with Claude Code only | | 109 tests green on macOS 26 and Linux 6.12 (2026-09-24) |
| [[M1 Secrets Outside]] | not started |  |  |
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
