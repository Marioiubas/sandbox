---
title: "Cursor and Gemini CLI"
aliases: ["Cursor", "Gemini CLI"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/isolation, platform/macos, platform/linux, platform/windows, evidence/secondary]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Cursor 2.5's sandbox with admin network allowlists and Gemini CLI's Seatbelt, Docker/Podman and gVisor sandbox options (off by default in 2025); neither documents credential brokering."
related: ["[[Cursor CurXecute and MCPoison]]", "[[Cursor DuneSlide Sandbox Escape]]", "[[Gemini CLI Prefix Allowlist Bypass]]", "[[Native Config Exporters]]", "[[Seatbelt]]", "[[gVisor]]", "[[Gap Analysis]]", "[[I5 Config Outside Writable Mounts]]", "[[I8 No Flag Disables Isolation]]", "[[MCP Guard]]", "[[Nx s1ngularity Supply-Chain Attack]]", "[[Open Questions and Unverified Claims]]", "[[Claude Code and sandbox-runtime]]", "[[OpenAI Codex CLI]]", "[[Product Thesis]]", "[[Container Runtimes and Escape History]]"]
sources: ["https://cursor.com/changelog/2-5", "https://geminicli.com/docs/cli/sandbox/", "https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison", "https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html", "https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack", "https://www.wiz.io/blog/s1ngularity-supply-chain-attack", "https://www.catonetworks.com/blog/curxecute-rce/"]
---

# Cursor and Gemini CLI

> Cursor 2.5's sandbox with admin network allowlists and Gemini CLI's Seatbelt, Docker/Podman and gVisor sandbox options (off by default in 2025); neither documents credential brokering.

## What they are

Two widely used coding agents whose sandboxes are real but thinner than Claude Code's or Codex's, and whose documented security history is dominated by config and allowlist bugs rather than network tricks. They are grouped because the broker treats them the same way: wrap the process, and export what their formats can express. Licence and pricing are not in the record; the report classes openness as "Mixed".

## Architecture teardown

### Cursor

- **Cursor 2.5 (17 Feb 2026)** added sandbox network modes: user `sandbox.json` only, user plus Cursor defaults, or allow-all. It also added filesystem controls, and Enterprise admins can "enforce network allowlists and denylists from the admin dashboard" ([Cursor changelog 2.5](https://cursor.com/changelog/2-5)).
- **Isolation technology:** not described in the record beyond "Cursor sandbox".
- **Credentials:** no brokering documented.
- **Scoping:** domain-level.

### Gemini CLI

- **Sandbox options:** Seatbelt profiles on macOS (`permissive-open` is the default, plus `restrictive-proxied`, `strict-open` and others), Docker/Podman, a Windows native sandbox via `icacls` (persistent changes), gVisor/runsc and experimental LXC ([Gemini CLI docs](https://geminicli.com/docs/cli/sandbox/); [[Seatbelt]], [[gVisor]]).
- **Credentials:** the docs cover no credential-injection mechanism ([Gemini CLI docs](https://geminicli.com/docs/cli/sandbox/)).
- **Default:** in the July 2025 incident, Google noted that its sandboxing options (Docker/Podman/Seatbelt) were off by default ([Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)). Whether that default changed later is not in the record.

## Security history

| Incident | Mechanism | Source | Broker control |
|---|---|---|---|
| Cursor CVE-2025-54135 "CurXecute" (Aug 2025, fixed 1.3.9) | Prompt injection made the agent write `.cursor/mcp.json` without approval; Cursor auto-started the new MCP command | [Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison); [Cato Networks](https://www.catonetworks.com/blog/curxecute-rce/) | Agent-config paths read-only ([[I5 Config Outside Writable Mounts]]); MCP servers only from user/org config ([[MCP Guard]]) |
| Cursor CVE-2025-54136 "MCPoison" (Aug 2025) | Approved MCP config was "bound by the MCP name not its contents", so later edits were trusted | [Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison) | Content-hash pinning ([[MCP Guard]]) |
| Cursor "DuneSlide" CVE-2026-50548/50549 (fixed Cursor 3.0, 2 Apr 2026; disclosed 1 Jul 2026) | `working_directory` set to the sandbox helper or `~/.zshrc`, which the sandbox then allowed writes to; symlink-check failure fallback wrote outside the project | [The Hacker News](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html) | Kernel-enforced FS; helper binaries outside every writable mount |
| Gemini CLI (reported 27 Jun 2025, fixed v0.1.14, 25 Jul 2025) | Prefix-matched command allowlist let chained commands run; whitespace hid the payload in the UI; README.md/GEMINI.md were injection vectors | [Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack) | OS sandbox on by default makes the command allowlist non-load-bearing |

See [[Cursor CurXecute and MCPoison]], [[Cursor DuneSlide Sandbox Escape]] and [[Gemini CLI Prefix Allowlist Bypass]].

> [!question] Unverified
> DuneSlide CVE numbers and dates come from The Hacker News only; the Cursor advisory was not fetched ([[Open Questions and Unverified Claims]]).

Gemini CLI was also one of the local AI CLIs that the Nx "s1ngularity" malware drove with permission-skipping flags (`--yolo` among them) to hunt secrets ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack); [[Nx s1ngularity Supply-Chain Attack]]). That is the evidence behind [[I8 No Flag Disables Isolation]].

## Strengths

- Both offer some OS sandboxing. Gemini CLI offers the widest menu of isolation back-ends, including gVisor.
- Cursor Enterprise has central network allow/deny lists.

## Weaknesses (versus this thesis)

- No credential brokering in either; secrets remain whatever the developer's environment holds.
- Domain-level scoping at best.
- Enforcement-layer and config bugs: string-matched allowlists, name-bound approvals, `working_directory` and symlink fallbacks. The report counts this "bugs in the enforcement layer" shape at least seven times in 13 months across four vendors.
- Gemini CLI's sandbox was off by default in 2025; a permissive Seatbelt profile is the macOS default.

## What we reuse or interoperate with

- **Wrap, don't integrate.** `broker run -- cursor-agent` and `broker run -- gemini` apply the broker's own sandbox regardless of the agent's settings. Built-in profiles for `gemini-cli` and `cursor-agent` are planned in `profiles/`.
- **Export:** Cursor `sandbox.json` domain lists and admin-dashboard lists ([[Native Config Exporters]]). Gemini CLI has no managed network or credential surface in the record to export to.
- **Regression tests:** each incident above becomes an [[L1 Conformance Suite]] category-10 probe (config writes, symlink and `working_directory` escapes).

## How we differentiate

The broker supplies what neither documents: credential minting, method/path/verb semantics, a kernel-enforced FS boundary independent of the agent's own checks, and one audit stream across agents ([[Gap Analysis]]).

## How it connects

- motivated-by:: [[Cursor CurXecute and MCPoison]]
- motivated-by:: [[Cursor DuneSlide Sandbox Escape]]
- motivated-by:: [[Gemini CLI Prefix Allowlist Bypass]]
- motivated-by:: [[Nx s1ngularity Supply-Chain Attack]]
- depends-on:: [[Seatbelt]]
- depends-on:: [[gVisor]]
- mitigated-by:: [[I5 Config Outside Writable Mounts]]
- mitigated-by:: [[MCP Guard]]
- contrasts-with:: [[Claude Code and sandbox-runtime]]
- contrasts-with:: [[OpenAI Codex CLI]]
- competes-with:: [[Product Thesis]]
- Export target of: [[Native Config Exporters]]
- Analysed in: [[Gap Analysis]]

## Implications for the build

- M2's learn-mode acceptance uses three agents; the landscape note names Claude Code, Codex and Gemini CLI. Keep Gemini CLI in the e2e matrix from M0 so its binaries and network behaviour are known early.
- Never trust an agent's own sandbox flag state. The broker's launcher decides isolation.

## Open questions

- What isolation technology does Cursor's sandbox use on each OS? Not in the record.
- Does Gemini CLI now enable sandboxing by default? Re-check the current docs.

## Sources

- [Cursor changelog 2.5](https://cursor.com/changelog/2-5)
- [Gemini CLI sandbox docs](https://geminicli.com/docs/cli/sandbox/)
- [Tenable: CurXecute/MCPoison](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison); [Cato Networks](https://www.catonetworks.com/blog/curxecute-rce/)
- [The Hacker News: DuneSlide](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)
- [Tracebit: Gemini CLI](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)
- [Wiz: s1ngularity](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)
