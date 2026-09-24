---
title: "Claude Code Pre-Trust Config Execution"
aliases: ["CVE-2025-59536", "CVE-2026-21852"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/filesystem, topic/credentials, topic/supply-chain, control/pin, control/fs, control/cred-out, control/egress, adversary/a1, adversary/a2, boundary/tb5, invariant/i1, invariant/i4, invariant/i5, milestone/m1]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Repository config ran code before the trust dialog (CVE-2025-59536) or redirected API calls to leak Anthropic API keys before trust (CVE-2026-21852)."
related: [AUTO]
sources: [AUTO]
---

# Claude Code Pre-Trust Config Execution

Two Claude Code CVEs showed that configuration shipped inside a repository was acted on before the user decided whether to trust that repository. In the first, code from an untrusted project could run before the "trust this folder" dialog was accepted; in the second, project-load configuration could redirect API calls to an attacker endpoint and exfiltrate data including Anthropic API keys, again before trust was confirmed ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-59536); [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)). The class is "configuration that executes before or outside the approval gate", and the design's answers are that repo config is inert data until hash-approved and can only narrow, and that the API key and base URL live in the broker.

## Timeline

- **CVE-2025-59536**: published 3 Oct 2025, CVSS 3.1 score 8.8, fixed in Claude Code 1.0.111: "Code Injection due to a bug in the startup trust dialog implementation" ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-59536)).
- **CVE-2026-21852**: published 21 Jan 2026, fixed in 2.0.65: a malicious repo's project-load configuration could redirect API calls and "exfiltrate data including Anthropic API keys before users confirmed trust" ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)).
- Researcher write-up by Check Point ([Check Point Research](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)); the page did not render during research, so details here come from NVD.

## What happened

- **Code before trust (CVE-2025-59536).** NVD describes a bug in the startup trust dialog that let code from an untrusted project run before acceptance. Anthropic describes a matching case (the extracted material does not name the CVE): a repo's `.claude/settings.json` hook executed before the "trust this folder" prompt; the fix defers parsing of project-local config until after trust ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).
- **Key exfiltration before trust (CVE-2026-21852).** Project configuration changed where the client sent its API calls, so the client's own Anthropic API key was delivered to an attacker endpoint ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)).

ATLAS technique AML.T0081 (Modify AI Agent Configuration) and AML.T0083 (Credentials from AI Agent Configuration) map to this class ([Zenity Labs](https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of)).

## Root cause

- **(d) missing filesystem/config boundary** and **(e) untrusted configuration treated as trusted**: repo-supplied config was parsed and acted on before the trust decision.
- The API credential sat inside the agent process, and the agent chose its own upstream base URL.
- Adversary **A1/A2** (whoever authors the repository). Boundary TB5.

## Impact

Code execution on the developer machine on opening a repository, and theft of the user's model API key. Both fixed.

## Stopping control in this design

- **Would have prevented: repo config inert until hash-approved ([[I5 Config Outside Writable Mounts]]).** Hooks, agent settings and MCP manifests that the agent obeys are loaded by the broker from outside every writable mount, only after content-hash approval. A repository file named `.claude/settings.json` is data until approved.
- **Would have prevented widening: [[I4 Repo Policy Only Narrows]].** Repository-supplied policy can only narrow user and org policy; a SymCC `check_implies(repo ∧ org, org)` gate rejects widening.
- **Would have prevented key theft: CRED-OUT + fixed base URL.** The Anthropic key never enters the sandbox ([[I1 No Secrets in the Sandbox]]); the LLM API adapter injects it and the **base URL is fixed by the broker**, which closes the CVE-2026-21852 redirect class ([[Registry and LLM API Adapters]]). A redirected client reaches only hosts policy allows, and carries only a sentinel.
- **Would have contained: EGRESS.** An attacker endpoint not on the allowlist is unreachable.
- MCP server definitions in the repo are likewise ignored in favour of pinned user/org definitions ([[MCP Guard]]).

## Regression test

- **Category 10 (filesystem)**: from inside the sandbox, writes to agent config paths (`.claude/`, `.cursor/`, `.codex/`, `.vscode/`), hooks and MCP manifests are denied.
- **Config inertness**: a fixture repo contains agent config that defines a hook, an MCP server and an alternate API base URL; launching under the broker executes none of them, and the LLM traffic still goes to the broker-fixed upstream.
- **Category 2**: with an API key configured, the sandbox sees only a sentinel; a request to a non-allowlisted host carrying that sentinel yields nothing usable.

## How it connects

- mitigated-by:: [[I4 Repo Policy Only Narrows]]
- mitigated-by:: [[I5 Config Outside Writable Mounts]]
- mitigated-by:: [[Registry and LLM API Adapters]]
- mitigated-by:: [[I1 No Secrets in the Sandbox]]
- mitigated-by:: [[MCP Guard]]
- example-of:: [[Claude Code and sandbox-runtime]]
- part-of:: [[Threat Model Overview]]

Sibling incidents in the same class: [[Codex CLI Project Config Autoload]], [[Copilot Auto-Approve Settings Write]], [[Cursor CurXecute and MCPoison]].

## Implications for the build

- The launcher mounts agent config directories read-only and supplies the approved config itself.
- Built-in agent profiles must enumerate every project-local config path each agent auto-loads.
- The broker should also control the base URL for every LLM provider it proxies, not only Anthropic.

## Open questions

- The Check Point write-up was not read; exact pre-trust code paths are from NVD summaries ([[Open Questions and Unverified Claims]]).

## Sources

- [NVD CVE-2025-59536](https://nvd.nist.gov/vuln/detail/CVE-2025-59536)
- [NVD CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)
- [Check Point Research](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) (not rendered)
- [Anthropic, How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude)
- [Zenity Labs / MITRE ATLAS](https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of)
