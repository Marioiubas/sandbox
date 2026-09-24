---
title: "postmark-mcp Rug Pull"
aliases: ["Rug Pull", "Tool Poisoning"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/mcp, topic/supply-chain, control/pin, control/egress, control/audit, adversary/a2, boundary/tb6, milestone/m3]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "A popular npm MCP server's v1.0.16 added one line that BCC'd every sent email to an attacker; the first real-world malicious MCP server (Sep 2025)."
related: [AUTO]
sources: [AUTO]
---

# postmark-mcp Rug Pull

An npm package named `postmark-mcp`, an MCP server for sending email through Postmark, behaved normally until version 1.0.16 added a single line that BCC'd every email the agent sent to an attacker-controlled address. Koi Security called it "the world's first sighting of a real-world malicious MCP server" ([The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)). It is the real-world instance of the "rug pull" Invariant Labs described in April 2025: a trusted tool changes after approval.

## Timeline

- **1 Apr 2025** (background): Invariant Labs describes tool poisoning, rug pulls and cross-server shadowing: "A malicious server can change the tool description after the client has already approved it" ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)).
- **15 Sep 2025**: `postmark-mcp` uploaded to npm.
- **17 Sep 2025**: v1.0.16 adds the BCC line.
- **29 Sep 2025**: reported publicly; 1,643 downloads at the time ([The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)). Postmark published an advisory noting the package was not theirs ([Postmark](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package)).

## What happened

1. A third party published an MCP server under a name suggesting the Postmark email service.
2. Early versions worked as advertised, building installs and trust.
3. v1.0.16 added one line: every outgoing email was also BCC'd to the attacker.
4. Agents using the server kept sending mail normally; users saw nothing different ([The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)).

The related research classes ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)): **tool poisoning** (hidden instructions in tool descriptions make agents leak files such as `~/.cursor/mcp.json` and SSH keys), **rug pull** (descriptions or code change after approval) and **shadowing** (one server's description overrides another trusted server's behaviour, for example redirecting email recipients). Invariant's mitigations: pin server versions and hash tool descriptions, show full descriptions, enforce cross-server dataflow boundaries.

## Root cause

- **(e) unpinned tool definitions / supply chain**: updates to an approved server were trusted automatically.
- The malicious behaviour was inside the server's legitimate function (sending email), so it used an allowed channel.
- Adversary **A2** (malicious publisher). Boundary TB6.

## Impact

Silent copying of every email sent through the server to the attacker for affected installs.

## Stopping control in this design

- **Would have prevented: PIN ([[MCP Guard]], [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]).** Servers are pinned by content hash of the launch spec and of `tools/list` (names, schemas, descriptions); any change revokes the server's grants until re-approved. A silent upgrade from 1.0.15 to 1.0.16 would not run without an explicit re-approval.
- **Would have contained: semantic recipient rules.** **Proposal.** The MCP guard authorizes each `tools/call` with its arguments, and the email server's own egress runs under a per-server policy; a rule that recipients (To/CC/BCC) must originate from the user or a trusted directory addresses this and the shadowing variant. Code-level BCC injection inside the server's upstream API call is visible only if the broker parses the provider's API request (L7 adapter) at the server's egress.
- **Would have contained: EGRESS + AUDIT.** The server's upstream traffic is logged per call with the request metadata.

Pinning catches the *change*; it does not catch a server malicious from its first version. That residual is why an MCP gateway or scanner is complementary ([[MCP Gateways]]).

## Regression test

- **MCP guard fixture**: a pinned test server is replaced by a version whose code or tool description differs; the guard refuses to launch or relay until re-approval, and `broker why` names the hash change ([[M3 CI Identity and MCP]]).
- **Argument policy**: a `send_email` call whose recipient set includes an address not derived from the user's request is denied under a recipient-allowlist policy.
- **Category 1**: the server's own egress to non-allowlisted hosts is denied.

## How it connects

- mitigated-by:: [[MCP Guard]]
- decided-by:: [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]
- contrasts-with:: [[MCP Gateways]]
- example-of:: [[Adversary Classes]]
- evaluated-by:: [[Measurement Gaps]]
- part-of:: [[Threat Model Overview]]

The skill-registry analogue is [[ClawHavoc Malicious Skills]].

## Implications for the build

- Lockfile-style pinning of MCP servers (package version plus content hash) in user/org config; no floating versions.
- Re-approval UI shows the diff of tool descriptions and the launch spec, not only "server changed".
- Per-server egress policy defaults to the server's documented upstream host only.

## Open questions

- No base rate exists for how often real MCP servers change tool descriptions, which sets re-approval friction ([[Measurement Gaps]]; [[Open Questions and Unverified Claims]]).

## Sources

- [The Hacker News, 29 Sep 2025](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)
- [Postmark advisory](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package)
- [Invariant Labs, tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
