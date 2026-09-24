---
title: "Cursor CurXecute and MCPoison"
aliases: ["CVE-2025-54135", "CVE-2025-54136", "CurXecute", "MCPoison"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/mcp, topic/filesystem, topic/supply-chain, control/fs, control/pin, control/iso, adversary/a1, adversary/a2, boundary/tb5, boundary/tb6, invariant/i5, milestone/m3]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "An injection could make Cursor write .cursor/mcp.json and auto-start the new command (CVE-2025-54135), and approvals were bound to the MCP name rather than its content (CVE-2025-54136)."
related: [AUTO]
sources: [AUTO]
---

# Cursor CurXecute and MCPoison

Two Cursor vulnerabilities disclosed a week apart in August 2025 attacked MCP configuration from both ends. **CurXecute**: a prompt injection (for example via Slack MCP content) could make the agent write `.cursor/mcp.json` without approval, and Cursor then auto-started the newly defined MCP command. **MCPoison**: an approved MCP config was "bound by the MCP name not its contents", so later edits to an approved entry were silently trusted ([Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)). Together they show both halves of the fix: config the agent cannot write, and approvals bound to a content hash.

## Timeline

- **1 Aug 2025**: CurXecute, CVE-2025-54135, reported by Aim Security; CVSS 8.5; fixed in Cursor 1.3.9 ([Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison); [Cato Networks](https://www.catonetworks.com/blog/curxecute-rce/)).
- **5 Aug 2025**: MCPoison, CVE-2025-54136, reported by Check Point; CVSS 7.2; fixed in Cursor 1.3 ([Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)).

## What happened

**CurXecute (CVE-2025-54135).**
1. Injected content reached the agent through a connected MCP source.
2. The agent wrote a new server entry into `.cursor/mcp.json` inside the workspace; the write did not require approval.
3. Cursor auto-started the newly configured MCP command, executing attacker-chosen code.

**MCPoison (CVE-2025-54136).**
1. A user approved an MCP server entry once.
2. The approval was keyed to the server's name.
3. A later change to that entry's contents kept the same name and was silently trusted without re-approval ([Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)).

## Root cause

- **(d) missing filesystem boundary**: the agent could write its own tool configuration.
- **(e) unpinned tool definitions**: approval bound to a name, not to content.
- Adversary **A1** (CurXecute) and **A2** (MCPoison: whoever can change a shared config). Boundaries TB5 and TB6.

## Impact

Remote code execution on developer machines via prompt injection or via a poisoned shared config. Both fixed.

## Stopping control in this design

- **Would have prevented CurXecute: FS read-only config ([[I5 Config Outside Writable Mounts]]).** `.cursor/` and every other agent config path are read-only inside the sandbox ([[Filesystem Control and Rollback]]).
- **Would have prevented both structurally: MCP servers are pinned principals ([[MCP Guard]], [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]).** Pinned servers are defined only in user or org config. The agent's MCP config points at `broker mcp connect <name>`; `brokerd` launches the pinned command for that name. The agent can name a server but cannot choose its command, so a new or edited `mcp.json` buys nothing.
- **Would have prevented MCPoison: PIN to content hash.** Approval is bound to the hash of the launch command and of `tools/list` (names, schemas, descriptions); any change revokes the server's grants until re-approved.
- **Would have contained: ISO.** Each MCP server runs in its own sandbox with sentinel env vars and its own egress policy.

## Regression test

- **Category 10**: writes to `.cursor/mcp.json` (and each agent's MCP config path) from inside the sandbox fail.
- **MCP guard fixture**: change a pinned server's command or any tool description between sessions; the guard refuses to relay until re-approval and `broker why` reports "manifest hash changed". This is the same mechanism as the [[M3 CI Identity and MCP]] acceptance "a changed tool description revokes it".
- **Name-only approval**: renaming a server does not transfer an approval; editing without renaming does not keep it.

## How it connects

- mitigated-by:: [[MCP Guard]]
- mitigated-by:: [[I5 Config Outside Writable Mounts]]
- mitigated-by:: [[Filesystem Control and Rollback]]
- decided-by:: [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]
- example-of:: [[Cursor and Gemini CLI]]
- evaluated-by:: [[M3 CI Identity and MCP]]

Siblings: [[Copilot Auto-Approve Settings Write]] (agent edits its own permissions) and [[Codex CLI Project Config Autoload]] (repo defines MCP commands).

## Implications for the build

- The pin must cover the full launch spec (command, args, env names, working directory), not only `tools/list`.
- `broker mcp wrap -- <cmd>` for desktop hosts that launch MCP servers themselves must apply the same pinning.

## Open questions

- No base rate for how often real MCP servers change tool descriptions, which determines re-approval friction ([[Measurement Gaps]]; [[Open Questions and Unverified Claims]]).

## Sources

- [Tenable FAQ, CVE-2025-54135 / CVE-2025-54136](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)
- [Cato Networks, CurXecute](https://www.catonetworks.com/blog/curxecute-rce/)
