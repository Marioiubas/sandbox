---
title: "ADR-025 Native Config Exporters as Built"
aliases: ["ADR-025"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, milestone/m2, invariant/i8]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "broker policy export writes Claude Code managed-settings.json and Codex requirements.toml from the compiled policy of one profile, per the vendors' documented schemas as of 2026-09-24; it exports domain allows only on ports the Cedar policy admits, the org ceiling as denies, fail-closed flags and deny-read paths, and does not export proxy chaining or an MCP allowlist."
related: ["[[Native Config Exporters]]", "[[M2 Policy Audit and Learn]]", "[[Claude Code and sandbox-runtime]]", "[[OpenAI Codex CLI]]", "[[I8 No Flag Disables Isolation]]", "[[MOC Decisions]]"]
sources: ["https://code.claude.com/docs/en/sandboxing", "https://code.claude.com/docs/en/settings-reference", "https://code.claude.com/docs/en/managed-settings", "https://learn.chatgpt.com/docs/enterprise/managed-configuration"]
superseded_by: 
---

# ADR-025 Native Config Exporters as Built

> `broker policy export --target claude-code|codex --profile NAME` prints one vendor file compiled from the same policy the broker enforces, plus an export report on stderr; the broker never installs it and never reads it back.

## Status

built (2026-09-24, M2 step 5).

## Context

[[Native Config Exporters]] asked that each exporter first fetch the vendor's current schema. Verified on 2026-09-24:

- **Claude Code** ([sandboxing](https://code.claude.com/docs/en/sandboxing), [settings reference](https://code.claude.com/docs/en/settings-reference), [managed settings](https://code.claude.com/docs/en/managed-settings)): `sandbox.enabled`, `sandbox.failIfUnavailable`, `sandbox.allowUnsandboxedCommands`; `sandbox.network.allowedDomains` entries are a domain, `*.name` (subdomains) or IP literal with optional `:port` (no port = every port), IPv6 bracketed; `deniedDomains` wins over a broader allow; `allowManagedDomainsOnly` (managed only); `strictAllowlist` (v2.1.219+); `sandbox.filesystem.denyRead`/`denyWrite` with `~/` for home and `/` absolute, while `./` resolves differently per scope; `filesystem.allowManagedReadPathsOnly` (managed only); `httpProxyPort`/`socksProxyPort` take a local TCP port. Managed file: `/Library/Application Support/ClaudeCode/managed-settings.json` (macOS), `/etc/claude-code/managed-settings.json` (Linux and WSL).
- **Codex** ([managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration)): `/etc/codex/requirements.toml`; `allowed_sandbox_modes`; `[experimental_network]` with `enabled` (domain rules alone do not activate the proxy), `managed_allowed_domains_only` and a `domains` map of `"name" = "allow"|"deny"` where `*.name` is subdomains only, `**.name` is apex plus subdomains and deny wins; the section is marked experimental. `[permissions.filesystem] deny_read`. MCP allowlist entries are `[mcp_servers.<name>]` with an `identity`.

## Decision

- **Input** is the normalised form (`code/crates/policy/src/exporters/mod.rs`): each grant's host pattern with only the ports the Cedar policy admits it on (`admit_host`), so grants the ceiling or the DoH block deny are dropped; wildcard grants under a ceiling name are dropped; the ceiling names; deny-read (built-in credential stores plus profile and user entries) and home deny-write lists.
- **Claude Code** (`claude.rs`): `enabled`, `failIfUnavailable: true`, `allowUnsandboxedCommands: false`, `allowManagedDomainsOnly`, `strictAllowlist`, `allowedDomains` as `host:port` per admitted port, `deniedDomains` = each ceiling name and `*.name`, `denyRead`, `denyWrite`, `allowManagedReadPathsOnly`.
- **Codex** (`codex.rs`): `allowed_sandbox_modes = ["read-only", "workspace-write"]`, `[experimental_network]` enabled with `managed_allowed_domains_only`, allows per host (ports inexpressible, reported), `**.name = "deny"` for each ceiling name, `[permissions.filesystem] deny_read`.
- **Report** (stderr): every grant exported at domain level whose method, path or git rules only the broker enforces; credentials that stay in the broker; dropped grants; address classes and pinned addresses; inexpressible ports (Codex) and deny-write (Codex); project-relative deny-write names; the minimum Claude Code version.
- **Not exported (deviations from the proposal):** proxy chaining (the broker's ingress is per session, so a static `httpProxyPort` would point nowhere); the Codex MCP allowlist (no pinned MCP servers until M3, and whether an empty allowlist denies all is undocumented); project-relative deny-write entries (their resolution in managed settings is not documented); `sandbox.credentials` entries (the broker's sentinels already keep secrets out; a `deny` would unset sentinels a tool needs). Cursor and OpenShell stay in phase 2.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Write the files into the system paths | Modifies system configuration; distribution belongs to MDM or the control plane. |
| Export every grant port-agnostic | Wider than the broker on other ports; Claude Code can express ports, so it gets them. |
| Export `sandbox.credentials` masks | The note forbids exporting secrets; masks authorize another proxy to inject them. |
| Emit an empty `[mcp_servers]` table | Semantics of an empty allowlist are not documented; guessing could either block everything or nothing. |

## Consequences

- An exported file is a second, independent layer on the vendor's own sandboxed commands; it never replaces `broker run`, and its domain allows are wider than the broker's method and path rules (reported).
- Vendor schema drift shows up as a golden-file diff (`code/tests/golden/exporters/`), reviewed and re-blessed.
- Codex's network section is experimental upstream; the file says so.

## Invariants affected

Upholds I8 in the vendor layer (`allowUnsandboxedCommands: false`, `failIfUnavailable: true`, `danger-full-access` not allowed). No invariant depends on an exported file.

## Relationships

- decided-by:: M2 build
- motivated-by:: [[Native Config Exporters]]

## Build log

- 2026-09-24: created and built. Code: `code/crates/policy/src/exporters/{mod,claude,codex,tests}.rs`, `code/crates/broker-cli/src/cmd/policy.rs` (`export`). Tests: `exporters::tests::{claude_settings_carry_the_fail_closed_flags_and_drop_ceiling_grants, codex_requirements_parse_and_match_the_documented_semantics, exported_files_never_admit_what_the_broker_denies}` (256-case property test against the documented matchers), `m2_exporters::{exports_match_the_golden_files, unknown_targets_and_profiles_are_refused}`.
