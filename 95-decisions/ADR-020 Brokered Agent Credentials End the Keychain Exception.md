---
title: "ADR-020 Brokered Agent Credentials End the Keychain Exception"
aliases: ["ADR-020"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/credentials, platform/macos, platform/linux, control/cred-out, boundary/tb4, invariant/i1, invariant/i7, milestone/m1]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Coding agents' own credentials are held by brokerd and attached at egress: the claude-code profile brokers the Claude Code OAuth token (keychain or ~/.claude/.credentials.json) behind a sentinel in CLAUDE_CODE_OAUTH_TOKEN; agent token files are deny-read for every session; the macos_keychain profile switch of ADR-016 is removed."
related: ["[[ADR-016 macOS M0 Compatibility Exceptions]]", "[[I1 No Secrets in the Sandbox]]", "[[I7 Reject Foreign Credentials]]", "[[Credential Injector and Issuers]]", "[[Sentinel Swap Pattern]]", "[[Sandbox Launcher]]", "[[Filesystem Control and Rollback]]", "[[M1 Secrets Outside]]", "[[Risk Register]]", "[[MOC Decisions]]", "[[Build Log]]"]
sources: []
superseded_by:
code: ["code/profiles/claude-code.toml", "code/profiles/claude-code-apikey.toml", "code/profiles/codex.toml", "code/profiles/gemini-cli.toml", "code/crates/policy/src/l7.rs", "code/crates/creds/src/secrets.rs", "code/crates/launcher/src/fs_compile.rs", "code/tests/e2e/fix_failing_test.sh"]
---

# ADR-020 Brokered Agent Credentials End the Keychain Exception

> Agents' own credentials are held by brokerd and attached at egress; the sandbox holds only sentinels, agent token files are unreadable, and the macOS keychain switch of ADR-016 is removed.

## Status

Built (2026-09-24) with [[M1 Secrets Outside]]. Supersedes the keychain half of [[ADR-016 macOS M0 Compatibility Exceptions]]; its temp-dir half stands.

## Context

- ADR-016 let the `claude-code` profile reach securityd on macOS so Claude Code could read its own OAuth token, and recorded that I1 was weakened "for macOS `claude-code` sessions in M0 only" and "must be superseded or closed before M1 is built".
- Inspecting the `Claude Code-credentials` keychain item on the reference Mac (key names only, never values) showed it holds more than the Claude.ai OAuth token: `claudeAiOauth.{accessToken, refreshToken, expiresAt, …}` **and** `mcpOAuth.*` access tokens (some with client secrets) for about forty MCP connectors. Under ADR-016 all of them were readable from inside the sandbox.
- Claude Code accepts a bearer token in `CLAUDE_CODE_OAUTH_TOKEN` and an API key in `ANTHROPIC_API_KEY`; Codex accepts `OPENAI_API_KEY`; Gemini CLI accepts `GEMINI_API_KEY` (agent documentation; the Claude Code path verified end to end below).
- On Linux, Claude Code keeps the same JSON in `~/.claude/.credentials.json`; Codex keeps `~/.codex/auth.json`; Gemini CLI keeps `~/.gemini/oauth_creds.json`. None was on the deny-read list.

## Decision

1. **The `claude-code` profile declares a brokered credential** on `api.anthropic.com`: `static`, reference `keychain:Claude Code-credentials#claudeAiOauth.accessToken|file:~/.claude/.credentials.json#claudeAiOauth.accessToken`, attached as `Authorization: Bearer`, sentinel in `CLAUDE_CODE_OAUTH_TOKEN`. brokerd reads only that JSON field, per session, into memory.
2. **`claude-code-apikey`** (selected with `--profile`) brokers `keychain:broker-anthropic-api-key|env:ANTHROPIC_API_KEY` as `x-api-key`; **codex** and **gemini-cli** broker `OPENAI_API_KEY` / `GEMINI_API_KEY` the same way (keychain item first, then brokerd's own environment).
3. **Secret references gain alternatives** (`a|b`, first that yields wins) and **home-relative files** (`file:~/…`, must be owned by the user with mode 0600). Plain `file:<name>` still means the broker config directory.
4. **Agent token files join the default deny-read list** for every session: `~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`. Profile `filesystem` sections are now applied (they were ignored in M0).
5. **The `[agent] macos_keychain` switch is removed** from the profile schema, the launcher and the SBPL generator. `~/Library/Keychains` is always deny-read and securityd is never reachable. Re-introducing keychain access needs a new ADR.

**Testable as:** `tests/e2e/fix_failing_test.sh claude` (the agent completes the task; from inside a `claude-code` session `CLAUDE_CODE_OAUTH_TOKEN` is a sentinel and the keychain item and credentials file are unreadable); `sbpl::tests::*` (no `SecurityServer` in any profile); `secrets::tests::file_source_requires_0600` (alternatives, `~/` files); `profiles::tests::all_builtins_parse_and_compile`; the M1 conformance tests `b1_i1_only_sentinels_inside_the_sandbox` and `b4_i7_planted_key_to_allowed_host_is_rejected`.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Keep ADR-016's keychain exception through M1 | Contradicts M1's acceptance ("scan finds only sentinels") and exposes ~40 MCP tokens in the same keychain item |
| Copy the token into the sandbox as an environment variable | The I1 anti-pattern |
| A broker OAuth issuer that refreshes Claude Code's token | Correct long-term, but the refresh flow is undocumented in the record; per-session load of the current access token is enough for M1 |
| Ask API-key users to override the profile's credential in user policy | Two credentials on one host is an ambiguity the policy engine denies by design; a separate profile is explicit |

## Consequences

- Claude Code on macOS and Linux works under the broker with no credential in the sandbox: verified on macOS 26 (e2e, 29 s, 15 of 15 API requests carried the brokered credential; 0 keychain access).
- The access token is read once per session. If it expires mid-session the agent sees 401s; running the agent once outside the broker refreshes it. Broker-side refresh is future work (Risk Register R18).
- MCP OAuth tokens in the same keychain item are no longer reachable by sandboxed agents, so MCP servers that need them do not work inside the sandbox until [[M3 CI Identity and MCP]].
- Codex ChatGPT-login and Gemini Google-login modes are **not brokered** and now fail closed (their token files are unreadable); only their API-key modes are supported. Not verified here: neither agent is installed on the reference machine.
- A missing keychain item or unset variable is a `mint_failed` deny on the first API request, not a launch refusal.

## Invariants affected

- [[I1 No Secrets in the Sandbox]]: **strengthened**; the M0 weakening recorded in ADR-016 is closed.
- [[I7 Reject Foreign Credentials]]: unchanged; a token planted in `CLAUDE_CODE_OAUTH_TOKEN` is a foreign credential.

## Relationships

- supersedes:: [[ADR-016 macOS M0 Compatibility Exceptions]] (keychain exception only)
- decided-by:: [[M1 Secrets Outside]]
- motivated-by:: [[I1 No Secrets in the Sandbox]]

## Build log

- 2026-09-24: created and built with M1. Evidence in [[Build Log]] ("M1 secrets outside implemented").
