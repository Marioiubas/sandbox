---
title: "ClawHavoc Malicious Skills"
aliases: ["ClawHavoc"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/supply-chain, topic/mcp, topic/credentials, control/pin, control/iso, control/egress, control/cred-out, adversary/a2, boundary/tb6, platform/macos, platform/windows, evidence/secondary]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "An audit of 2,857 ClawHub skills found 341 malicious ones, mostly fake 'Prerequisites' that installed Atomic Stealer or trojans, plus reverse shells and bot-credential theft (Jan-Feb 2026)."
related: [AUTO]
sources: [AUTO]
---

# ClawHavoc Malicious Skills

Koi Security audited 2,857 skills on ClawHub, the skill registry for the OpenClaw agent, and found 341 malicious. 335 used fake "Prerequisites" instructions to get users to install Atomic Stealer on macOS or a trojan on Windows; others hid reverse shells or exfiltrated bot credentials from `~/.clawdbot/.env` ([The Hacker News](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html)). A skill registry is a supply chain, and the agent is the installer.

## Timeline

- **Jan–Feb 2026**: audit and disclosure; reported by The Hacker News on 2 Feb 2026 ([The Hacker News](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html)).
- OpenClaw's response: user reporting with auto-hide after 3 reports.

## What happened

- **Fake prerequisites (335 of 341).** A skill's documentation told the user, or the agent acting for the user, to install a "prerequisite" first; the prerequisite was Atomic Stealer (macOS infostealer) or a Windows trojan.
- **Reverse shells.** Some skills opened remote shells.
- **Bot-credential theft.** Some read `~/.clawdbot/.env` and exfiltrated the bot's credentials ([The Hacker News](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html)).

The same ecosystem saw exposed control planes and token theft in the same weeks ([[OpenClaw Exposure and Token Theft]]).

## Root cause

- **(e) unpinned, unvetted tool definitions / supply chain**: skills were installed from an open registry with no provenance or content review; registry moderation relied on user reports.
- Skill-triggered installs ran with the user's full privileges, and credential files were readable.
- Adversary **A2**. Boundary TB6.

## Impact

Infostealer and trojan installs on user machines, remote shells, and theft of bot credentials, across 341 skills out of 2,857 audited (about 12%).

## Stopping control in this design

- **Would have prevented silent change and unknown provenance: PIN.** Skills, like MCP servers, are pinned by content hash with explicit approval and re-approval on change ([[MCP Guard]]); registry provenance and signing checks come from the policy layer.
- **Would have contained installs: ISO.** Skill-triggered installs and scripts run inside the sandbox ([[Sandbox Launcher]]), without access to credential files, keychains or browser data; they cannot persist outside granted writable roots.
- **Would have contained exfiltration: EGRESS.** Downloads from paste sites and unknown IPs, reverse-shell connections and uploads go through deny-by-default brokered egress; raw TCP does not exist in the sandbox ([[Topology-Forced Egress]]).
- **Would have prevented credential theft: CRED-OUT.** `.env` bot tokens are not readable; the broker holds them and injects them per request.

Limit: a user who installs a "prerequisite" outside the broker on the host is outside the design's reach. **Proposal.** `broker run` should be the documented way to run any install step a skill requests.

## Regression test

- **Category 5 (alternate protocols)**: a reverse-shell attempt (outbound raw TCP to an arbitrary port) fails; only mediated protocols exist.
- **Category 2 / 10**: a scripted "prerequisite" inside the sandbox cannot read credential files (`~/.clawdbot/.env`-style dotenv files, keychains, SSH keys) and cannot write outside the workspace.
- **Category 1**: downloading from a non-allowlisted host or a raw IP is denied.

## How it connects

- mitigated-by:: [[MCP Guard]]
- mitigated-by:: [[Sandbox Launcher]]
- mitigated-by:: [[Topology-Forced Egress]]
- example-of:: [[Adversary Classes]]
- part-of:: [[Threat Model Overview]]

The MCP-server analogue is [[postmark-mcp Rug Pull]].

## Implications for the build

- The pinning mechanism in `mcpguard` should be generic enough to cover skills and plugin bundles, not only MCP `tools/list`.
- The default read-deny list must cover dotenv files outside the workspace and agent-specific credential stores.
- Phase 3 Windows support must treat installer execution the same way.

## Open questions

- Numbers come via The Hacker News; Koi's original post now redirects and was not fetched. No primary source was found for an in-the-wild malicious Claude Code skill ([[Open Questions and Unverified Claims]]).

## Sources

- [The Hacker News, 2 Feb 2026](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html)
- [Koi Security](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) (redirects; not fetched)
