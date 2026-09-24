---
title: "M0 Contained Run"
aliases: ["M0"]
type: milestone
section: build
tags: [sandbox/build, milestone, milestone/m0, topic/isolation, topic/egress, topic/dns, topic/filesystem, platform/macos, platform/linux, control/iso, control/fs, control/egress, invariant/i2, invariant/i5, invariant/i6, invariant/i8, invariant/i9]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
milestone: M0
code: ["code/"]
---

# M0 Contained Run

> Weeks 1-2: workspace skeleton, broker run, Seatbelt and bwrap+Landlock+seccomp backends, empty netns plus UDS bridge, CONNECT and SOCKS5 with host allowlist, canonicaliser, broker DNS, fail-closed launch; done when claude and codex fix a failing test on macOS 15/26 and Ubuntu 22.04/24.04 with probe categories 3, 4, 5, 9 and 10 fully denied.

## Goal

At the end of M0, `broker run -- <agent>` launches an unmodified coding agent inside the OS sandbox on macOS and Linux, and the **only** network path out of that sandbox is the broker's own proxy, which resolves DNS itself, canonicalises every hostname once, and enforces a host allowlist. Nothing about credentials changes yet (that is [[M1 Secrets Outside]]); M0 is about topology and fail-closed launch. This is work order number one: it creates `code/` and the skeleton every later milestone builds into.

The reason M0 comes first is the incident record: bugs in the enforcement layer itself (empty-list semantics, prefix matching, NUL bytes, symlink fallback) appeared at least seven times in 13 months across four vendors, and Anthropic's custom proxy "repeatedly introduced vulnerabilities" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). The canonicaliser and the conformance corpus therefore start in week one.

## Scope

**In scope (from the report's M0 row):**

- Cargo workspace skeleton for all twelve crates ([[Repository Layout]]).
- `broker run` end to end: CLI → `brokerd` session → launcher → agent ([[Broker CLI and Daemon]]).
- `macos-seatbelt` backend with generated SBPL ([[Seatbelt]]).
- `linux-native` backend: bwrap with no network interface, seccomp, Landlock, `PR_SET_NO_NEW_PRIVS` ([[bubblewrap]], [[seccomp-bpf]], [[Landlock]]).
- Empty network namespace plus a Unix-domain-socket bridge on Linux; loopback-only port on macOS ([[Topology-Forced Egress]]).
- HTTP CONNECT and SOCKS5 ingress with a host allowlist ([[Netguard Ingress]]).
- The single [[Hostname Canonicaliser]] and the [[Broker DNS Resolver]].
- Fail-closed launch ([[I2 Fail-Closed Launch]]).
- Filesystem deny-read of secret paths and read-only agent config and git hooks ([[Filesystem Control and Rollback]]).
- A minimal append-only deny log sufficient to show "100% of denies logged with a reason" (the full hash chain arrives in [[M2 Policy Audit and Learn]], but the chain format should be used from day one).

**Out of scope (later milestones):** TLS termination, per-session CA, sentinels and minting (M1); Cedar schema and TOML compiler beyond a host allowlist, learning, OCSF (M2); CI, IdP login, MCP guard, AWS (M3); packaging, 24 h fuzzing, pentest (M4). The transparent ingress listener is optional in M0; clients that ignore proxy variables fail closed, which is acceptable.

## Prerequisites

- Read [[CLAUDE]], [[Architecture Overview]], [[Request and Session Lifecycle]], [[Core Trait Contracts]] and the invariant notes it links.
- Test machines or CI runners: macOS 15 and macOS 26; Ubuntu 22.04 and 24.04. Ubuntu 24.04+ gates unprivileged user namespaces via AppArmor ([srt](https://github.com/anthropic-experimental/sandbox-runtime)); Codex notes AppArmor configuration may be needed for bubblewrap ([Codex docs](https://learn.chatgpt.com/codex/sandboxing)).
- Claude Code and Codex CLI installed on each machine, with a throwaway sample repo containing one failing test.
- Resolve before depending on them (see [[Open Questions and Unverified Claims]]): crate versions ([[Tech Stack]]); Landlock ABI availability (assume ABI 10/11 are **not** in a released stable kernel and probe at runtime).

## Ordered task checklist (Proposal)

Each item names the files to create under `code/`. Order matters: the canonicaliser and its fuzz target land before any ingress listener uses them.

**Workspace**

- [ ] Create `code/Cargo.toml` (workspace, `license = "Apache-2.0"`), `code/rust-toolchain.toml`, `code/LICENSE`, and empty crates `broker-cli`, `brokerd`, `launcher`, `netguard`, `tls`, `l7`, `creds`, `policy`, `grant`, `audit`, `learn`, `mcpguard`. Pin crate versions and record them in [[Tech Stack]].
- [ ] CI skeleton: `.github/workflows/ci.yml` with `cargo build --locked`, `cargo test`, clippy, and jobs for macOS 15/26 and Ubuntu 22.04/24.04.
- [ ] Create `tests/conformance/{03-name-resolution,04-ip-literals,05-alt-protocols,09-proxy-bypass,10-filesystem}/` and `tests/bypass-corpus/`.

**Canonicaliser and DNS (netguard)**

- [ ] `crates/netguard/src/canon.rs`: one function from raw host bytes to a `CanonicalHost` or a rejection. Reject NUL, CR/LF and `%` in hostnames; trailing dots; mixed IDNA forms; IP-literal encodings (decimal, octal, hex, IPv4-mapped IPv6); link-local, cloud-metadata (169.254.169.254) and RFC 1918 destinations unless explicitly granted ([[I6 Single Canonicaliser]]).
- [ ] `tests/fuzz/fuzz_targets/canon.rs` plus `proptest` properties in `canon.rs` (idempotence: `canon(canon(x)) == canon(x)`; every accepted name is LDH-only after IDNA handling).
- [ ] `crates/netguard/src/resolver.rs`: the broker's policy resolver; answers only allowlisted names; blocks DoH endpoints by name; returns addresses that are then matched again against the address policy.
- [ ] `crates/netguard/src/dns_stub.rs`: Linux-only stub in the namespace that forwards only to the broker resolver (optional if all resolution happens inside CONNECT/SOCKS5).

**Ingress (netguard)**

- [ ] `crates/netguard/src/ingress/connect.rs`: HTTP CONNECT listener; deny IP-literal CONNECT by default.
- [ ] `crates/netguard/src/ingress/socks5.rs`: SOCKS5 listener; hostnames go through `canon.rs`; add `tests/fuzz/fuzz_targets/socks5.rs`.
- [ ] `crates/netguard/src/splice.rs`: after allow, splice bytes without decryption (the L4 path; TLS termination arrives in M1).
- [ ] Match on the canonical name **and** on the broker-resolved address for every connection.
- [ ] Deny UDP entirely (no DNS, no QUIC/UDP 443) and ICMP; deny SSH and other SNI-less protocols by default.

**Launcher**

- [ ] `crates/launcher/src/spec.rs` and `lib.rs`: the `SandboxBackend` trait and `SandboxSpec` exactly as in [[Core Trait Contracts]].
- [ ] `crates/launcher/src/probe.rs`: `probe()` reports Landlock ABI, userns/AppArmor gate status and seccomp availability; any missing required layer is an error.
- [ ] `crates/launcher/src/backends/seatbelt/sbpl.rs`: generate SBPL: deny writes except repo and tmp; deny reads of secret dirs (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`, `~/.docker/config.json`); network only to the per-session broker localhost port; no Apple Events; no `trustd` (srt calls `trustd` an exfiltration vector ([srt](https://github.com/anthropic-experimental/sandbox-runtime))).
- [ ] `crates/launcher/src/backends/linux/bwrap.rs`: `--ro-bind / /`, repo bind, `.git/hooks` and `.git/config` read-only, agent config dirs read-only, `--unshare-net`, `--unshare-user --unshare-pid`. Codex's Linux pipeline confirms this recipe in production ([codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)).
- [ ] `crates/launcher/src/backends/linux/netns_bridge.rs`: TCP→UDS bridge from the empty namespace to `brokerd`'s data socket.
- [ ] `crates/launcher/src/backends/linux/seccomp.rs`: after the bridge exists, block new `AF_UNIX` sockets, ptrace, bpf, raw sockets and keyctl.
- [ ] `crates/launcher/src/backends/linux/landlock.rs`: FS rules plus TCP connect only to the bridge port; best-effort on older ABIs, but refuse if the profile requires a rule the kernel cannot enforce.
- [ ] `crates/launcher/src/fs_compile.rs`: compile the default filesystem grants (from `broker.toml` defaults) to SBPL and to bwrap/Landlock. Remember Linux path rules are literal, so deny-globs miss files created after start.
- [ ] Trust-bundle and proxy env: set `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` to the per-session endpoint; on macOS add a per-session `Proxy-Authorization` sentinel because any local process can reach a loopback port.

**CLI and daemon**

- [ ] `crates/brokerd/src/ctl_rpc.rs`: JSON-RPC 2.0 over a per-user Unix socket, mode 0600, peer credentials checked (`peercred.rs`); methods `session.start`, `session.stop`, `decision.explain` stubs ([[Broker CLI and Daemon]]).
- [ ] `crates/broker-cli/src/cmd/run.rs`: `broker run -- <cmd>`; exits non-zero and prints which layer failed if `probe()` or the proxy fails ([[I2 Fail-Closed Launch]]).
- [ ] `crates/broker-cli/src/cmd/doctor.rs`: report per-layer status (Landlock ABI, AppArmor userns gate, Seatbelt availability).
- [ ] Profiles: `profiles/claude-code.toml`, `profiles/codex.toml` with agent config dirs to make read-only.
- [ ] Flags: no CLI flag or agent flag passthrough may disable any layer ([[I8 No Flag Disables Isolation]]); add a test that enumerates every `broker run` flag.

**Audit (minimal)**

- [ ] `crates/audit/src/chain.rs` and `store.rs`: append every allow/deny with reason, session ID and chain hash `H(prev || canonical_json(ev))` to SQLite WAL outside the sandbox ([[I9 Hash-Chained Audit Outside the Sandbox]]).

**Probes**

- [ ] Write deterministic, non-LLM probes for categories 3, 4, 5, 9, 10 of the [[Conformance Probe Matrix]], each with an in-policy control and an out-of-policy case; add the bypass-corpus entries named in the acceptance criteria.
- [ ] `tests/e2e/`: scripted "fix failing test" task for `claude` and `codex` on each OS.

## Components delivered

[[Sandbox Launcher]] (seatbelt and linux backends), [[Netguard Ingress]] (CONNECT, SOCKS5), [[Hostname Canonicaliser]], [[Broker DNS Resolver]], [[Broker CLI and Daemon]] (run, doctor, ctl.sock), the M0 slice of [[Filesystem Control and Rollback]] (deny-read and read-only config; rollback deferred), and a first slice of [[Audit Recorder and Event Schema]]. Each gets `status: built` and a Build log entry only when its tests pass.

## Acceptance criteria

Verbatim from the report, each turned into an automated test (test names are proposals):

| # | Criterion | Test | Threshold |
|---|---|---|---|
| A1 | `broker run -- claude` and `-- codex` finish a "fix failing test" task | `tests/e2e/fix_failing_test_{claude,codex}` on macOS 15, macOS 26, Ubuntu 22.04, Ubuntu 24.04 | 8 of 8 agent×OS cells pass |
| A2 | Conformance categories 3, 4, 5, 9, 10 are 100% denied | `tests/conformance/{03,04,05,09,10}` | 100% of out-of-policy probes denied; 100% of in-policy controls succeed |
| A3 | Named probes denied: NUL-byte, CRLF, IDNA, IP-literal, 169.254.169.254, DNS TXT | `tests/bypass-corpus` entries, run through every ingress mode | 100% denied |
| A4 | Reading `~/.ssh/id_ed25519` is denied | category 10 probe with a canary key file | denied on all four OS targets |
| A5 | Launch refuses to run if any layer is missing | `tests/e2e/fail_closed_*`: disable each layer in turn (Seatbelt, bwrap, Landlock, seccomp, proxy) | `broker run` exits non-zero every time, agent never starts |
| A6 | `curl` to a non-allowlisted host fails (research note 05 M0 row) | category 9 control | denied and logged |
| A7 | Every deny is logged with a reason | audit assertion over all M0 probe runs | 100% |

## Eval layers and probes that must pass

- [[L1 Conformance Suite]]: categories 3 (name resolution), 4 (IP literals and encodings), 5 (alternate protocols), 9 (proxy bypass) and 10 (filesystem) from the [[Conformance Probe Matrix]]; the fuzz target for `canon.rs` and `socks5.rs` runs in CI (the 24 h requirement is [[M4 Harden and Ship]]).
- Invariant tests for [[I2 Fail-Closed Launch]], [[I6 Single Canonicaliser]], [[I8 No Flag Disables Isolation]] and the minimal [[I9 Hash-Chained Audit Outside the Sandbox]] row-tamper test.
- [[I5 Config Outside Writable Mounts]]: write attempts from inside the sandbox to agent config dirs, `.git/hooks` and `.git/config` are denied (category 10).

## Risks

- **Ubuntu AppArmor userns gate** blocks bwrap on 24.04+: the installer or `broker doctor` must detect it and refuse, never silently degrade ([[Risk Register]]).
- **Landlock ABI spread**: rules the kernel cannot enforce must be reported by `probe()`; if the profile needs them, launch fails.
- **macOS clients that ignore proxy variables** (static Go binaries, gRPC) fail because nothing else is reachable; acceptable for M0 and documented. Go TLS needs `trustd`, which is denied; expect failures in Go-based tools and record them.
- **Parser bugs in `canon.rs`** are the highest-consequence M0 defect; fuzz and property tests are part of the task, not a follow-up.

## Definition of done

1. Every acceptance criterion A1-A7 passes in CI on macOS and Linux, and the test names are listed in this note's Build log.
2. Invariant tests for I2, I5, I6, I8 and the minimal I9 pass; no invariant was weakened without an ADR.
3. `tests/conformance` covers categories 3, 4, 5, 9, 10, with 100% of out-of-policy probes denied and logged with a reason.
4. [[Sandbox Launcher]], [[Netguard Ingress]], [[Hostname Canonicaliser]], [[Broker DNS Resolver]] and [[Broker CLI and Daemon]] are `status: built` with Build log entries; deviations have ADRs.
5. [[Build Log]] has an M0 entry; the Landlock ABI and crate-version items in [[Open Questions and Unverified Claims]] are resolved with evidence.
6. Set this note to `status: built`; the next milestone is [[M1 Secrets Outside]].

## How it connects

- implements:: [[I2 Fail-Closed Launch]]
- implements:: [[I6 Single Canonicaliser]]
- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[Seatbelt]]
- depends-on:: [[bubblewrap]]
- depends-on:: [[Landlock]]
- depends-on:: [[seccomp-bpf]]
- depends-on:: [[Netguard Ingress]]
- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[Broker DNS Resolver]]
- depends-on:: [[Broker CLI and Daemon]]
- depends-on:: [[Topology-Forced Egress]]
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[L1 Conformance Suite]]
- mitigates:: [[sandbox-runtime SOCKS NUL-Byte Bypass]]
- mitigates:: [[Claude Code DNS Exfiltration CVE-2025-55284]]
- mitigates:: [[sandbox-runtime Empty Allowlist Bypass]]
- decided-by:: [[ADR-003 Topology-Enforced Egress]]
- decided-by:: [[ADR-009 Broker-Only DNS Resolution]]
- part-of:: [[MVP Plan]]

Next milestone: [[M1 Secrets Outside]], which adds TLS termination and credentials on top of the egress path built here.

## Implications for the build

- The empty-list rule is global from day one: an empty allowlist denies everything (the CVE-2025-66479 lesson, [[sandbox-runtime Empty Allowlist Bypass]]).
- Do not add a "warn and run unsandboxed" path for convenience; Claude Code's default of warning and running unsandboxed unless `sandbox.failIfUnavailable` is set is the anti-pattern ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)).
- Never mount `docker.sock` or host paths; srt warns that doing so "would effectively grant access to the host system" ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).

## Open questions

- Landlock ABI 10 (UDP) and 11 availability; the UDP series was still at v5 in June 2026 ([[Landlock]]).
- Whether transparent interception on macOS is possible without a Network Extension (unvalidated; fail closed for now) ([[Netguard Ingress]]).
- Which Go-based developer tools break without `trustd`, and whether any needs a documented exception.

## Sources

- Report: milestone table row "Weeks 1-2 M0 Contained run"; recommended layered design per platform; topology and canonicaliser sections.
- Research note 05 section 5.2 M0 row (curl to a non-allowlisted host fails).

## Build log

- 2026-09-24: implementation complete for the M0 scope; **milestone not yet `built`** because A1 is verified in 1 of 8 agent × OS cells.
- A1 (agents finish a "fix failing test" task): scripted as `code/tests/e2e/fix_failing_test.sh <claude|codex>`. **PASS on macOS 26.5 with Claude Code 2.1.268** (Haiku; the agent edited `calc.py` and ran the test inside the sandbox; host-side checks: test passes, test file unchanged, git hooks and config untouched, audit chain verifies). Not run: Codex (not installed on the build machine), macOS 15, Ubuntu 22.04/24.04 (need agent CLIs and credentials on runners).
- A2 (categories 3, 4, 5, 9, 10 fully denied, controls succeed): PASS on macOS 26.5 (Seatbelt) and Linux 6.12 (bwrap + Landlock ABI 6 + seccomp, Docker, Ubuntu 24.04 userland). Tests: `cat03_name_resolution`, `cat04_ip_literals_and_encodings`, `cat05_alternate_protocols`, `cat09_proxy_bypass`, `cat10_filesystem`, `cat10_git_commit_still_works`, `cat10_non_repo_directory_cannot_grow_git_hooks`. The CI matrix (macOS 15/26, Ubuntu 22.04/24.04 runners) is configured in `.github/workflows/ci.yml`.
- A3 (NUL-byte, CRLF, IDNA, IP-literal, 169.254.169.254, DNS TXT): PASS: `bypass_corpus_denied_with_reason_through_every_ingress_mode`, `i6_bypass_corpus_end_to_end`, `cat03_name_resolution`, `cat04_ip_literals_and_encodings`.
- A4 (`~/.ssh/id_ed25519` unreadable): PASS on macOS 26.5 against the real key path (`cat10_filesystem`); CI plants a canary key on runners.
- A5 (launch refuses when any layer is missing): PASS: `i2_launch_refuses_when_any_layer_is_missing`, `i2_missing_shim_refuses_launch`.
- A6 (curl to a non-allowlisted host fails and is logged): PASS (manual `curl` in a session; probe `proxy connect evil.example` in `i9_every_decision_is_chained_and_explainable`).
- A7 (every deny logged with a reason): PASS: every network deny in the pipeline and conformance tests is asserted in the audit log with its reason.
- Totals at this entry: 109 tests pass on macOS and on Linux; clippy clean with `-D warnings` on both; five fuzz targets ran 60 s each without a crash.
- ADRs: [[ADR-016 macOS M0 Compatibility Exceptions]], [[ADR-017 Landlock Filesystem Layer Required]], [[ADR-018 seccomp Filter Shape for M0]], [[ADR-019 Mandatory Deny-Write List Additions]].
- Remaining to mark M0 `built`: A1 for Codex and for macOS 15, Ubuntu 22.04 and 24.04; a green CI run on all four runners.
