---
title: "OpenAI Codex CLI"
aliases: ["Codex", "requirements.toml"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/isolation, topic/egress, platform/macos, platform/linux, platform/windows, evidence/secondary, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Codex's Seatbelt and bubblewrap sandbox (read-only, workspace-write, danger-full-access) with a managed proxy offering domain allowlists and HTTP-method filtering, requirements.toml via MDM, and no documented credential brokering."
related: ["[[bubblewrap]]", "[[Seatbelt]]", "[[Landlock]]", "[[Native Config Exporters]]", "[[Codex CLI Project Config Autoload]]", "[[Broker DNS Resolver]]", "[[Gap Analysis]]", "[[Two-Tier Isolation Design]]", "[[seccomp-bpf]]", "[[Topology-Forced Egress]]", "[[Claude Code and sandbox-runtime]]", "[[Open Questions and Unverified Claims]]", "[[Registry and LLM API Adapters]]", "[[I5 Config Outside Writable Mounts]]", "[[Tech Stack]]", "[[Product Thesis]]", "[[Risk Register]]"]
sources: ["https://learn.chatgpt.com/codex/sandboxing", "https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md", "https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/", "https://github.com/openai/codex/issues/22387", "https://developers.openai.com/codex/cloud/internet-access", "https://github.com/advisories/GHSA-xrxf-jgv3-qmrm", "https://github.com/openai/codex/issues/215", "https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md"]
---

# OpenAI Codex CLI

> Codex's Seatbelt and bubblewrap sandbox (read-only, workspace-write, danger-full-access) with a managed proxy offering domain allowlists and HTTP-method filtering, requirements.toml via MDM, and no documented credential brokering.

## What it is

OpenAI's open-source coding-agent CLI. Its sandbox lives in the Rust `codex-rs` tree ([codex linux-sandbox README](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md)). It is the second production confirmation, after srt, of the standard-tier recipe this broker adopts ([[Two-Tier Isolation Design]]). The exact licence and pricing are not in the record; the report lists it as an "open source CLI".

## Architecture teardown

### Isolation

- Three sandbox modes: `read-only`, `workspace-write` (the default) and `danger-full-access`. "The sandbox applies to spawned commands, not just to built-in file operations" ([Codex docs](https://learn.chatgpt.com/codex/sandboxing)).
- macOS uses Seatbelt; Linux and WSL2 use bubblewrap ("uses the first `bwrap` executable it finds on `PATH`", falling back to a bundled helper, with AppArmor configuration possibly needed on Ubuntu 24.04+); native Windows uses a "native Windows sandbox" ([Codex docs](https://learn.chatgpt.com/codex/sandboxing); [[Seatbelt]], [[bubblewrap]]).
- Approval policies are `on-request` and `never`. An `auto_review` option delegates approvals to a reviewer agent ([Codex docs](https://learn.chatgpt.com/codex/sandboxing)).

The Linux pipeline ([codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)):

- `--ro-bind / /`, then `--bind` for each writable root.
- Protected subpaths re-bound read-only: `.git`, the resolved `gitdir:` and `.codex`. Missing or symlink components are masked by mounting `/dev/null`.
- `--unshare-user --unshare-pid`, plus `--unshare-net` when restricted.
- `PR_SET_NO_NEW_PRIVS` and an in-process seccomp network filter ([[seccomp-bpf]]).
- In managed-proxy mode, a TCP→UDS→TCP bridge is set up, and seccomp then blocks new `AF_UNIX`/`socketpair`.
- Landlock is a legacy fallback (`features.use_legacy_landlock`), which admins can forbid ([[Landlock]]). WSL1 is rejected.

This is [[Topology-Forced Egress]]: the command has no network interface, and its only exit is the bridge.

### Network: the managed proxy

A managed network proxy takes `allowed_domains`/`denied_domains` with wildcards and **HTTP-method filtering**: read-only mode allows only GET/HEAD/OPTIONS. It can chain to a corporate SOCKS5 proxy (SOCKS5 support since v0.93.0, Dec 2025) ([Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/), a third-party knowledge base).

An open issue asks for the managed proxy to provide allowlisted DNS resolution inside the Linux sandbox ([openai/codex#22387](https://github.com/openai/codex/issues/22387)). The broker resolves DNS itself for exactly this reason ([[Broker DNS Resolver]]).

### Managed policy: `requirements.toml`

`requirements.toml` is deployed via MDM or `/etc/codex/`, and ChatGPT Business/Enterprise fetch it at sign-in. It pins allowed sandbox modes and MCP server allowlists, but "`requirements.toml` alone does not apply network filtering" ([Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/)).

### Credentials

**No credential brokering is documented.** The CLI teardown lists none, and in Codex cloud credential injection is not documented; secrets are handled around the setup phase ([OpenAI Codex docs](https://developers.openai.com/codex/cloud/internet-access)).

### Codex cloud (for comparison)

Internet access is off during the agent phase by default, and setup scripts have access. Per environment, the allowlist can be empty, "Common dependencies" (70+ domains) or unrestricted, with an optional HTTP-method restriction to GET/HEAD/OPTIONS ([OpenAI Codex docs](https://developers.openai.com/codex/cloud/internet-access)).

### Security history

CVE-2025-61260 / GHSA-xrxf-jgv3-qmrm: "Codex automatically loads project-local .env and .codex/config.toml files without requiring user confirmation", so a malicious repo could define MCP server commands that run at start ([GHSA](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm); [[Codex CLI Project Config Autoload]]).

> [!warning] Conflict
> GHSA metadata lists affected ≤0.23.0 with "no patched versions", which may conflict with the vendor fix. Verify before citing a fixed version.

The `sandbox-exec` deprecation in the macOS 15.4 man page was raised against Codex in [openai/codex#215](https://github.com/openai/codex/issues/215).

> [!question] Unverified
> The exact Codex Seatbelt base policy, the Windows sandbox mechanism, the local (non-cloud) network policy details and any 2026 credential-injection feature were not retrieved ([[Open Questions and Unverified Claims]]).

## Strengths

- Production-grade Linux pipeline, with read-only `.git` and `.codex` re-binds that close config-rewrite attacks on the agent's own files.
- Method filtering in the managed proxy, finer than host-only allowlists.
- Enterprise distribution through MDM and sign-in fetch.

## Weaknesses (versus this thesis)

- Single vendor; policy lives in Codex's own format.
- No credential brokering or minting; no git ref or GitHub verb semantics.
- DNS inside the Linux sandbox is an open request.
- Project-local config was auto-loaded before trust (CVE-2025-61260), the class [[I5 Config Outside Writable Mounts]] addresses.

## What we reuse or interoperate with

- **Reuse:** the bwrap flags, the read-only re-bind of `.git`/gitdir and agent config, and the "bridge then block `AF_UNIX`" ordering. The broker narrows `.git` protection to `.git/hooks` and `.git/config` so the agent can still commit locally.
- **Interoperate:** export the broker's policy into `requirements.toml` (sandbox mode, MCP allowlist) and the managed-proxy domain and method lists, then chain Codex's proxy to the broker ([[Native Config Exporters]]).
- **Share the language choice:** Codex chose Rust for its sandbox, one reason the broker does too ([[Tech Stack]]).

## How we differentiate

Codex filters methods on domains. The broker adds path and verb semantics ([[Registry and LLM API Adapters]] and the GitHub adapters), mints credentials per task, owns DNS, and applies one policy and audit stream across Codex, Claude Code, Cursor and MCP servers ([[Gap Analysis]]).

## How it connects

- depends-on:: [[bubblewrap]]
- depends-on:: [[Seatbelt]]
- depends-on:: [[Landlock]]
- example-of:: [[Topology-Forced Egress]]
- example-of:: [[Two-Tier Isolation Design]]
- motivated-by:: [[Codex CLI Project Config Autoload]]
- contrasts-with:: [[Broker DNS Resolver]]
- contrasts-with:: [[Claude Code and sandbox-runtime]]
- competes-with:: [[Product Thesis]]
- Export target of: [[Native Config Exporters]]
- Analysed in: [[Gap Analysis]], [[Risk Register]]

## Implications for the build

- `broker run -- codex` is an M0 acceptance target on macOS 15/26 and Ubuntu 22.04/24.04. Test with Codex's own sandbox set to `danger-full-access` inside the broker's sandbox, and with it on, since nested bwrap may need the installer's AppArmor step.
- Make sure Codex's managed proxy, if enabled, is chained to the broker and never given a direct route.
- Add CVE-2025-61260 as a regression test: a repo-supplied `.codex/config.toml` defining an MCP command must be inert under the broker.

## Open questions

- Does Codex export audit events to a SIEM natively? Not in the record.
- What does Codex's Seatbelt base policy allow by default on macOS?

## Sources

- [Codex docs: sandboxing](https://learn.chatgpt.com/codex/sandboxing)
- [codex linux-sandbox README (raw)](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md); [codex linux-sandbox README](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md)
- [Codex Knowledge Base (third-party)](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/)
- [openai/codex#22387](https://github.com/openai/codex/issues/22387); [openai/codex#215](https://github.com/openai/codex/issues/215)
- [OpenAI Codex cloud internet access](https://developers.openai.com/codex/cloud/internet-access)
- [GHSA-xrxf-jgv3-qmrm](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)
