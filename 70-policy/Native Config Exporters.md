---
title: "Native Config Exporters"
aliases: ["Compile-to-Native", "policy exporters"]
type: component
section: policy
tags: [sandbox/policy, component, topic/policy, topic/market, milestone/m2, milestone/phase2]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Compile the one Cedar source to Claude Code managed settings, Codex requirements.toml, Cursor sandbox.json and OpenShell YAML so each vendor's own controls become defense in depth instead of competitors."
related: ["[[Gap Analysis]]", "[[Claude Code and sandbox-runtime]]", "[[OpenAI Codex CLI]]", "[[Cursor and Gemini CLI]]", "[[NVIDIA OpenShell]]", "[[M2 Policy Audit and Learn]]", "[[broker.toml Human Policy Layer]]", "[[Risk Register]]", "[[Broker Cedar Schema]]", "[[Cedar]]", "[[Docker Sandboxes]]", "[[SymCC CI Gates]]", "[[Control Plane and Policy Bundles]]", "[[ADR-001 Value Lives in the Broker]]", "[[Repository Layout]]"]
sources: ["https://code.claude.com/docs/en/sandboxing", "https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/", "https://cursor.com/changelog/2-5", "https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html", "https://github.com/NVIDIA/openshell", "https://docs.docker.com/ai/sandboxes/security/defaults/", "https://geminicli.com/docs/cli/sandbox/", "https://learn.chatgpt.com/codex/sandboxing"]
code: ["code/crates/policy/src/exporters", "code/crates/broker-cli/src/cmd/policy.rs", "code/tests/golden/exporters"]
milestone: M2
---

# Native Config Exporters

> Compile the one Cedar source to Claude Code managed settings, Codex requirements.toml, Cursor sandbox.json and OpenShell YAML so each vendor's own controls become defense in depth instead of competitors.

## Responsibility

Every agent vendor now ships its own sandbox and its own managed-policy surface, and they are mutually incompatible:

- Claude Code: managed settings with `allowManagedDomainsOnly` and `sandbox.credentials` ([Claude Code docs](https://code.claude.com/docs/en/sandboxing));
- Codex: `requirements.toml` via MDM ([Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/));
- Cursor: an Enterprise admin-dashboard allowlist and user `sandbox.json` ([Cursor 2.5](https://cursor.com/changelog/2-5));
- Docker Sandboxes: org-level policy ([Docker docs](https://docs.docker.com/ai/sandboxes/security/defaults/));
- OpenShell: YAML policies ([OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)).

**Proposal:** The exporters compile the broker's one policy source (Cedar, via [[broker.toml Human Policy Layer]]) into each of these formats. The broker remains the enforcement point. Each vendor control then enforces a *subset* of the same policy inside its own agent, as a second, independent layer. This is gap item 1 in [[Gap Analysis]]: cross-agent policy-as-code that compiles to native configs. It also answers the "vendors bundle the feature" risk, turning a competitor's control into a deployment target ([[Risk Register]], [[ADR-001 Value Lives in the Broker]]).

It does **not** make vendor configs authoritative, merge them back, or depend on them for any invariant.

Crate path: `code/crates/policy/exporters/{claude,codex,cursor,openshell}` ([[Repository Layout]]).

## Inputs and outputs

- **Input:** the validated, SymCC-gated Cedar policy set and entity data for one profile (org + user layers; repository narrowing applies too).
- **Output:** one file per target, plus an **export report** listing every Cedar rule that the target cannot express and was therefore dropped or approximated.

### Target capabilities (what each format can carry)

| Target | Relevant documented controls | What exports cleanly | What cannot be expressed |
|---|---|---|---|
| Claude Code managed settings | `allowManagedDomainsOnly`, `strictAllowlist` (v2.1.219+), `allowUnsandboxedCommands: false`, `sandbox.failIfUnavailable`, `sandbox.credentials` `deny`/`mask` with `injectHosts` ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)) | Domain allowlist; FS deny-read paths; fail-closed flag; strict mode | Method/path rules, git ref rules, minting, trifecta forbids |
| Codex `requirements.toml` | Pins allowed sandbox modes and MCP server allowlists; the managed proxy takes `allowed_domains`/`denied_domains` and HTTP-method filtering; "`requirements.toml` alone does not apply network filtering" ([Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/)) | Allowed sandbox mode (`workspace-write`), MCP allowlist, domain lists and read-only method mode for the managed proxy | Per-path rules, credentials, git semantics |
| Cursor `sandbox.json` | Network modes: user `sandbox.json` only, plus Cursor defaults, or allow-all; filesystem controls; admin allow/deny lists ([Cursor 2.5](https://cursor.com/changelog/2-5)) | Domain allow/deny lists | Anything below domain level |
| OpenShell YAML | Host/port/method rules, per-binary scoping, `read-only` preset (GET/HEAD/OPTIONS), `enforcement: enforce\|audit` ([OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)) | Host, method, path, per-binary; audit mode | Minting, IdP binding, trifecta, git ref rules |

> [!question] Unverified
> The record documents these controls' existence, not their exact file schemas. Before writing each exporter, fetch the current vendor schema and pin its version in the exporter's tests. Cursor's `sandbox.json` field names and the Codex managed-proxy key names are not in the record. Gemini CLI documents sandbox profiles but no credential brokering or managed network policy ([Gemini CLI docs](https://geminicli.com/docs/cli/sandbox/)), so it has no export target yet ([[Cursor and Gemini CLI]]).

**Implementation notes (2026-09-24, M2):** the Claude Code and Codex schemas were fetched from the vendors' docs and are recorded in [[ADR-025 Native Config Exporters as Built]]. Codex's `[experimental_network]` uses a `domains` map (`"name" = "allow"|"deny"`; `*.name` subdomains only, `**.name` apex and subdomains; deny wins) and needs `enabled = true`; the legacy `allowed_domains`/`denied_domains` lists must not be combined with it. Claude Code domain entries take an optional `:port`. Cursor's `sandbox.json` remains unverified (phase 2).

### Exporter rules (Proposal)

1. **Export only narrowings.** Each exported file must be at least as restrictive as the Cedar source on everything it expresses. When a Cedar rule cannot be expressed, the exporter omits the *permit*, not the *forbid*: a host whose Cedar permits depend on method or path is exported to Claude Code as an allowed domain only if the broker also mediates that host.
2. **Never export secrets.** Credential references stay in the broker. For Claude Code, the exporter may emit `deny` entries for credential files but never `mask` values.
3. **Always export fail-closed flags** where they exist (`sandbox.failIfUnavailable`, `allowUnsandboxedCommands: false`), because Claude Code by default warns and runs unsandboxed if its sandbox cannot start ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)).
4. **Proxy chaining.** Where the vendor supports an upstream corporate proxy (Claude Code; Codex chains to a corporate SOCKS5 proxy since v0.93.0 per the [Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/)), point it at the broker so the vendor proxy and the broker are in series.
5. **Round-trip test.** For a request corpus, the decision of "vendor control, then broker" must never allow something the broker alone would deny.

### OpenShell: interoperate, don't fight

OpenShell is the closest open-source analogue: Apache-2.0, per-binary L7 rules, NVIDIA-backed ([GitHub](https://github.com/NVIDIA/openshell)). **Proposal:** Offer both directions. Export Cedar to OpenShell YAML for users who run OpenShell sandboxes, import OpenShell YAML into Cedar for migration, and in phase 2 offer the broker's minting as an OpenShell credential provider ([[NVIDIA OpenShell]]).

## Invariants upheld

- [[I3 Probabilistic Components Only Narrow]] in spirit: exported configs only narrow; nothing in a vendor config can widen broker policy, because the broker never reads them back.
- [[I8 No Flag Disables Isolation]]: exported settings disable the vendor's own unsandboxed escape hatches where the vendor allows it.

## Failure modes

- Unknown target version → refuse to export and say which schema version is supported.
- A rule that cannot be expressed → listed in the export report; export still succeeds (it is defense in depth, not the boundary).
- Export target drift (vendor renames a key) → caught by schema-pinned golden tests in CI.

## Tests

- Golden files per target for each example profile.
- Narrowing property test per target: parse the exported file back and check it allows nothing the Cedar source denies on a generated request corpus.
- M2 acceptance includes exporters to Claude Code managed settings and Codex `requirements.toml` ([[M2 Policy Audit and Learn]]). Cursor and OpenShell exporters are listed in the repository layout; **Proposal:** ship them in phase 2.

## How it connects

- implements:: [[Gap Analysis]] (unowned capability 1)
- depends-on:: [[broker.toml Human Policy Layer]]
- depends-on:: [[Broker Cedar Schema]]
- depends-on:: [[Cedar]]
- depends-on:: [[Claude Code and sandbox-runtime]] (export target)
- depends-on:: [[OpenAI Codex CLI]] (export target)
- depends-on:: [[Cursor and Gemini CLI]] (export target)
- depends-on:: [[NVIDIA OpenShell]] (export and import target)
- mitigates:: [[Risk Register]] (row "Vendors bundle the feature")
- delivered-by:: [[M2 Policy Audit and Learn]]
- decided-by:: [[ADR-001 Value Lives in the Broker]]
- part-of:: [[Control Plane and Policy Bundles]] (fleet distribution of exported files in phase 2)

## Implications for the build

- Build the Claude Code and Codex exporters in M2; defer Cursor and OpenShell.
- Keep exporter code free of policy logic: it consumes a normalised intermediate form (host → methods → paths → credential), not raw Cedar ASTs.
- Document for buyers that exported vendor configs are a second layer, never a replacement for running under `broker run`.

## Open questions

- Can Docker Sandboxes org policy be a fifth target? The format is not in the record ([[Docker Sandboxes]]).
- Should exporters be distributed through MDM alongside the broker (Codex `requirements.toml` is already fetched at sign-in for ChatGPT Business/Enterprise per the [Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/))?

## Sources

- [Claude Code docs: sandboxing](https://code.claude.com/docs/en/sandboxing)
- [Codex Knowledge Base (third-party): requirements.toml](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/); [Codex docs](https://learn.chatgpt.com/codex/sandboxing)
- [Cursor changelog 2.5](https://cursor.com/changelog/2-5)
- [NVIDIA OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html); [NVIDIA OpenShell GitHub](https://github.com/NVIDIA/openshell)
- [Docker Sandboxes security defaults](https://docs.docker.com/ai/sandboxes/security/defaults/)
- [Gemini CLI sandbox docs](https://geminicli.com/docs/cli/sandbox/)

## Build log

- 2026-09-24: Claude Code and Codex exporters built as `broker policy export --target claude-code|codex --profile NAME` ([[ADR-025 Native Config Exporters as Built]]): rules 1-3 and 5 hold (only narrowings, no secrets, fail-closed flags; a property test checks the exported files never admit a host or port the broker denies); rule 4 (proxy chaining) is not exported because the broker ingress is per session. Golden files per shipped profile in `code/tests/golden/exporters/`.
