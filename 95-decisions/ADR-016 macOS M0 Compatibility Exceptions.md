---
title: "ADR-016 macOS M0 Compatibility Exceptions"
aliases: ["ADR-016"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/isolation, topic/credentials, platform/macos, control/fs, control/cred-out, boundary/tb2, invariant/i1, invariant/i5, milestone/m0, milestone/m1]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "On macOS in M0, keep the per-user temp dir writable (Apple toolchain shims reset TMPDIR to it) and let only profiles that declare it (claude-code) read the login keychain so agents keep their own credentials until M1; both are announced, audited and time-boxed."
related: ["[[Seatbelt]]", "[[Sandbox Launcher]]", "[[Filesystem Control and Rollback]]", "[[I1 No Secrets in the Sandbox]]", "[[I5 Config Outside Writable Mounts]]", "[[M0 Contained Run]]", "[[M1 Secrets Outside]]", "[[Sentinel Swap Pattern]]", "[[Risk Register]]", "[[MOC Decisions]]", "[[Build Log]]"]
sources: []
superseded_by: "[[ADR-020 Brokered Agent Credentials End the Keychain Exception]]"
code: ["code/crates/brokerd/src/session.rs", "code/crates/launcher/src/fs_compile.rs", "code/crates/launcher/src/backends/seatbelt/sbpl.rs", "code/profiles/claude-code.toml"]
---

# ADR-016 macOS M0 Compatibility Exceptions

> On macOS in M0, keep the per-user temp dir writable and let only profiles that declare it read the login keychain, so unmodified agents run; both are announced, audited and time-boxed.

## Status

Superseded in part: the keychain exception (decision 2 and 3) is superseded by [[ADR-020 Brokered Agent Credentials End the Keychain Exception]] (2026-09-24); the temp-dir exception (decision 1) stands.

Built (2026-09-24) for [[M0 Contained Run]]. The keychain exception ends when [[M1 Secrets Outside]] moves credentials out of the sandbox; the temp-dir exception is reviewed then.

## Context

Measured on macOS 26.5 (build log of [[Seatbelt]]):

1. **Apple toolchain shims ignore `TMPDIR`.** `/usr/bin/python3`, `/usr/bin/git` and other `xcrun` shims reset `TMPDIR` to `confstr(_CS_DARWIN_USER_TEMP_DIR)` (`/var/folders/…/T/`). With only `${repo}` and a per-session `${tmp}` writable, `python3 -c 'import tempfile; tempfile.gettempdir()'` raised `FileNotFoundError: No usable temporary directory`. Homebrew Python respected `TMPDIR`. Codex's `workspace-write` mode also treats `TMPDIR` as writable by default.
2. **Agents keep their credentials in the login keychain.** Claude Code 2.1.268 on macOS reads its OAuth token from the login keychain (`~/Library/Keychains/login.keychain-db` via securityd). The default deny-read list includes the keychain DB ([[Filesystem Control and Rollback]]), so the agent reported "Not logged in". [[M0 Contained Run]] states that "nothing about credentials changes yet": minting and sentinel swap are M1.

## Decision

1. On macOS the writable set is `${repo}`, the per-session `${tmp}` (inside the per-user temp dir) **and the per-user temp dir itself**. The broker's own state, config and runtime directories must not be inside it; `fs_compile` refuses a `BROKER_HOME` that overlaps a writable root.
2. A profile may set `[agent] macos_keychain = true`. Only then, and only on macOS, the session profile allows the `com.apple.SecurityServer` and `com.apple.securityd.xpc` Mach services and drops `~/Library/Keychains` from deny-read. The built-in `claude-code` profile sets it; no user or repository layer can.
3. Every such session prints a warning at start (`profile claude-code can read the login keychain … ends when M1 moves credentials out`) and records `macos_keychain: true` in the `session.start` audit event.

**Testable as:** `profiles::tests::all_builtins_parse_and_compile`; `fs_compile` rejects a broker home inside a writable root (`fs_compile::tests::refuses_home_root_and_broker_overlap`); the e2e run `tests/e2e/fix_failing_test.sh claude` passes on macOS 26.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep the temp dir read-only | Breaks `/usr/bin/python3` and other Apple shims inside the sandbox: a large utility cost on stock macOS for a moderate risk |
| Pass the agent's token as an environment variable | A secret in the environment is the anti-pattern I1 forbids outright; the keychain exception at least keeps the token out of env, argv and files the agent writes |
| Implement M1's sentinel swap for the Anthropic API now | Needs TLS termination and the per-session CA, which are M1 scope; doing it partially would skip the M1 tests |
| Deny keychain access and accept that Claude Code cannot authenticate on macOS in M0 | Fails acceptance A1 on macOS and contradicts "nothing about credentials changes yet" |

## Consequences

- A sandboxed agent on macOS can create or modify files in the per-user temp dir, which other programs of the same user also use. Network, Mach-service and file-read rules still apply; tampering with another program's temporary files is the residual (Risk Register R16).
- Under the `claude-code` profile, a sandboxed process can ask securityd for login-keychain items whose ACL admits it (for example items created through `/usr/bin/security`). This is the same exposure the agent has without the broker today, and it is the gap M1 closes (Risk Register R17).
- Writes back to the keychain are still denied, so an agent cannot persist a refreshed token from inside the sandbox; refreshing outside (by running the agent once unsandboxed) was needed once in testing.

## Invariants affected

- [[I1 No Secrets in the Sandbox]]: **weakened for macOS `claude-code` sessions in M0 only** (keychain readable). I1's acceptance is an M1 criterion; this ADR must be superseded or closed before M1 is built.
- [[I5 Config Outside Writable Mounts]]: the per-user temp dir holds no authority-bearing configuration of the broker; the overlap check keeps broker state out of it.

## Relationships

- motivated-by:: [[Seatbelt]]
- decided-by:: [[M0 Contained Run]]
- supersedes::

## Build log

- 2026-09-24: created and built with M0; evidence and measurements in [[Build Log]] and the [[Seatbelt]] build log.
- 2026-09-24: keychain exception removed by [[ADR-020 Brokered Agent Credentials End the Keychain Exception]]; `macos_keychain` no longer exists in profiles, the launcher or the SBPL generator.
