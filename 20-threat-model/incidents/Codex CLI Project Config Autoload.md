---
title: "Codex CLI Project Config Autoload"
aliases: ["CVE-2025-61260"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/mcp, topic/supply-chain, topic/filesystem, control/pin, control/fs, control/iso, control/cred-out, adversary/a1, adversary/a2, boundary/tb5, boundary/tb6, invariant/i4, invariant/i5, milestone/m3, evidence/conflict]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Codex auto-loaded project-local .env and .codex/config.toml, so a malicious repo could define MCP server commands that ran at startup (CVE-2025-61260, CVSS 9.8)."
related: [AUTO]
sources: [AUTO]
---

# Codex CLI Project Config Autoload

OpenAI's Codex CLI "automatically loads project-local .env and .codex/config.toml files without requiring user confirmation", so a malicious repository could define MCP server commands that ran as soon as a developer started `codex` in it ([GitHub Advisory](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)). Rated CVSS 9.8, it is the most direct instance of repository content becoming executable configuration. The MCP guard answers it structurally: the agent can name an MCP server but can never choose its command.

## Timeline

- **2025**: reported by Check Point Research ([Check Point Research](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/)).
- **14 Apr 2026**: GHSA-xrxf-jgv3-qmrm published, CVSS 9.8 ([GitHub Advisory](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)).

> [!warning] Conflict
> The GHSA metadata lists affected versions ≤0.23.0 with "no patched versions", which may be inconsistent with the vendor fix. Verify the fixed version before citing one.

## What happened

1. An attacker publishes or contributes to a repository containing `.codex/config.toml` (and optionally `.env`).
2. The config defines one or more MCP servers whose launch commands are attacker-chosen.
3. A developer clones the repo and runs `codex`.
4. Codex auto-loads the project-local files without confirmation and starts the defined MCP servers, executing the attacker's command with the developer's privileges ([GitHub Advisory](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)).

## Root cause

- **(e) untrusted configuration / supply chain** and **(d) missing config boundary**: project-local config was trusted and executed at startup.
- `.env` autoload also meant repo content could set environment variables that influence the agent.
- Adversary **A1/A2** (the repository author). Boundaries TB5 and TB6.

## Impact

Arbitrary command execution on opening a repository with Codex, with access to everything the user's session can reach.

## Stopping control in this design

- **Would have prevented: MCP guard ([[MCP Guard]]).** Pinned MCP servers are defined only in user or org config, never in the repo. The agent's MCP configuration points at a stub (`broker mcp connect <name>`); `brokerd` launches the **pinned** command for that name in its own sandbox as a separate principal. Writing a new MCP config buys an attacker nothing ([[ADR-012 MCP Servers as Pinned Sandboxed Principals]]).
- **Would have prevented: config inert until approved ([[I5 Config Outside Writable Mounts]], [[I4 Repo Policy Only Narrows]]).** `.codex/` and `.env` in the workspace are data until content-hash approved; repo policy can only narrow.
- **Would have contained: ISO + CRED-OUT.** Anything that does run executes inside the sandbox with no secrets and no network except the broker.

## Regression test

- **Config inertness fixture**: a repo carrying `.codex/config.toml` with an MCP server whose command writes a marker file outside the workspace and a `.env` that sets a proxy-disabling variable; under `broker run -- codex` no marker appears and egress is still brokered.
- **Category 10**: the agent cannot write `.codex/` or other agent config paths inside the sandbox.
- **MCP guard unit**: an MCP name not in the pinned set cannot be launched; a pinned name always launches the pinned command regardless of what the agent's config says.

## How it connects

- mitigated-by:: [[I4 Repo Policy Only Narrows]]
- mitigated-by:: [[I5 Config Outside Writable Mounts]]
- mitigated-by:: [[MCP Guard]]
- decided-by:: [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]
- example-of:: [[OpenAI Codex CLI]]
- part-of:: [[Threat Model Overview]]

Siblings: [[Claude Code Pre-Trust Config Execution]] and [[Cursor CurXecute and MCPoison]].

## Implications for the build

- The Codex profile must mount `.codex` read-only (Codex's own Linux pipeline already re-binds `.codex` read-only ([codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md))) and must not let project `.env` files set variables that affect the proxy or CA bundle.
- Environment passed into the sandbox is constructed by the broker from an allowlist, never inherited from project files.

## Open questions

- Fixed-version ambiguity above ([[Open Questions and Unverified Claims]]).

## Sources

- [GHSA-xrxf-jgv3-qmrm](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)
- [Check Point Research](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/)
- [codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)
