---
title: "MOC Threat Model"
aliases: []
type: moc
section: threat
tags: [sandbox/threat, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Assets, adversaries, trust boundaries, control vocabulary, non-goals and the 24 incidents mapped to the controls that stop them."
related: ["[[Threat Model Overview]]", "[[Adversary Classes]]", "[[Trust Boundaries]]", "[[Threat Model Non-Goals]]", "[[EchoLeak M365 Copilot Exfiltration]]", "[[GitHub MCP Toxic Flow]]", "[[GitLost GitHub Agentic Workflows Leak]]", "[[Supabase MCP Token Leak]]", "[[Claude Code DNS Exfiltration CVE-2025-55284]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[Replit Production Database Deletion]]", "[[Amazon Q Extension Compromise]]", "[[Nx s1ngularity Supply-Chain Attack]]", "[[Claude Code Path and Command Injection CVEs]]", "[[Claude Code Pre-Trust Config Execution]]", "[[Codex CLI Project Config Autoload]]", "[[Copilot Auto-Approve Settings Write]]", "[[Cursor CurXecute and MCPoison]]", "[[Cursor DuneSlide Sandbox Escape]]", "[[Gemini CLI Prefix Allowlist Bypass]]", "[[sandbox-runtime Empty Allowlist Bypass]]", "[[sandbox-runtime SOCKS NUL-Byte Bypass]]", "[[postmark-mcp Rug Pull]]", "[[ClawHavoc Malicious Skills]]", "[[Mythos Preview Evaluation Escape]]", "[[GTG-1002 AI-Orchestrated Espionage]]", "[[OpenClaw Exposure and Token Theft]]", "[[July 2026 Artifactory Egress Incident]]", "[[MOC Architecture]]", "[[MOC Research]]", "[[Conformance Probe Matrix]]"]
sources: []
---

# MOC Threat Model

> Assets, adversaries, trust boundaries, control vocabulary, non-goals and the 24 incidents mapped to the controls that stop them.

The threat model assumes the agent's intent **can** be hijacked and asks what the hijacked agent can then do. It names the assets worth stealing, the six adversary classes evidenced in the record, the seven trust boundaries the design must enforce, what the product explicitly does *not* promise, and the 24 incidents that justify every control. Nearly every incident combines untrusted input, a broad standing credential and an open or "allowed" outbound channel.

Start with [[Threat Model Overview]] (assets, principals, control vocabulary, recurring shapes), then [[Trust Boundaries]] and [[Adversary Classes]]. Read [[Threat Model Non-Goals]] before promising anything to a buyer.

## Incident-to-control map

Each row: the incident, its root-cause shape, and the control code (see [[Threat Model Overview]] for the vocabulary ISO, FS, EGRESS, CRED-OUT, TASK-TOK, PIN, AUDIT, HITL) that would have stopped or contained it, per the report's mapping table.

| Incident | Shape | Stopping control(s) |
|---|---|---|
| [[EchoLeak M365 Copilot Exfiltration]] | trifecta via allowed channel | EGRESS (no open-proxy destinations); untrusted data never flows into URLs |
| [[GitHub MCP Toxic Flow]] | trifecta, all-repo PAT | TASK-TOK (one repo per session); trifecta rule blocks public write |
| [[GitLost GitHub Agentic Workflows Leak]] | trifecta, org-wide read | same as GitHub MCP; output classifiers do not replace scoping |
| [[Supabase MCP Token Leak]] | trifecta, `service_role` | CRED-OUT plus read-only table-scoped credential; external-readable sinks count as egress |
| [[Claude Code DNS Exfiltration CVE-2025-55284]] | DNS side channel | EGRESS: no DNS or ICMP from sandbox; broker-only resolution |
| [[Claude Cowork Allowed-Domain Abuse]] | foreign key on allowed host | proxy rejects credentials it did not issue |
| [[Replit Production Database Deletion]] | standing prod credential, A3 | TASK-TOK (prod DDL never grantable); HITL for irreversible verbs |
| [[Amazon Q Extension Compromise]] | supply chain via CI token | PIN and provenance; CRED-OUT |
| [[Nx s1ngularity Supply-Chain Attack]] | supply chain driving AI CLIs | ISO for installs; EGRESS; no flag disables isolation |
| [[Claude Code Path and Command Injection CVEs]] | enforcement-layer bug | kernel-enforced FS, not string checks |
| [[Claude Code Pre-Trust Config Execution]] | config before the gate | repo config inert until hash-approved; key and base URL held by broker |
| [[Codex CLI Project Config Autoload]] | config before the gate | same as above; MCP guard |
| [[Copilot Auto-Approve Settings Write]] | agent edits its own policy | FS makes agent-config paths read-only |
| [[Cursor CurXecute and MCPoison]] | agent edits config; name-bound approval | FS read-only config; PIN binds approval to content hash |
| [[Cursor DuneSlide Sandbox Escape]] | enforcement-layer bug | kernel FS rules; helper outside every writable mount |
| [[Gemini CLI Prefix Allowlist Bypass]] | enforcement-layer bug; sandbox off | ISO on by default |
| [[sandbox-runtime Empty Allowlist Bypass]] | enforcement-layer default | fail-closed schema semantics and tests |
| [[sandbox-runtime SOCKS NUL-Byte Bypass]] | parser differential | one canonicaliser; match the broker-resolved address |
| [[postmark-mcp Rug Pull]] | supply chain rug pull | PIN; semantic recipient rules |
| [[ClawHavoc Malicious Skills]] | malicious skills | PIN; ISO and EGRESS for skill-triggered installs |
| [[Mythos Preview Evaluation Escape]] | capable model probing | EGRESS and AUDIT enforced outside the guest |
| [[GTG-1002 AI-Orchestrated Espionage]] | malicious operator (A4) | partly addressed: hosted-mode egress limits and audit |
| [[OpenClaw Exposure and Token Theft]] | exposed control plane (A6) | control plane unreachable from the agent; policy not changeable from inside |
| [[July 2026 Artifactory Egress Incident]] | sanctioned egress point abused (unverified) | broker DNS; allowed domains remain channels |

## Model

- [[Threat Model Overview]] — Crown-jewel assets, the three trusted principals versus everything untrusted, the control vocabulary (ISO, FS, EGRESS, CRED-OUT, TASK-TOK, PIN, AUDIT, HITL), root-cause categories (a)-(g), the three recurring incident shapes, and OWASP ASI / MITRE ATLAS mappings.
- [[Adversary Classes]] — The six evidenced adversaries A1 remote injection author, A2 malicious publisher, A3 misbehaving model, A4 malicious operator, A5 over-privileged user, A6 opportunistic scanner, and the evidence that A3 is capable (SandboxEscapeBench, METR reward hacking, METR frontier risk report, Mythos).
- [[Trust Boundaries]] — The seven boundaries TB1-TB7 (human-agent, agent-OS, sandbox-broker, broker-external, workspace-context, tool supply chain-registry, CI trigger-CI credentials): what crosses each and which mechanism enforces it.
- [[Threat Model Non-Goals]] — Four stated non-goals (misuse inside granted scope, text-only manipulation, host-kernel zero-days in the standard tier, operator abuse only partly addressed) and the residual 'prevents theft, not misuse' risk the design narrows but cannot remove.

## Incidents: untrusted input steering a credentialed agent (lethal trifecta)

Untrusted content reaches an agent holding broad authority and an outbound or public-write channel.

- [[EchoLeak M365 Copilot Exfiltration]] — Zero-click email beat the XPIA classifier; a reference-style markdown image carried data through a CSP-allowed Teams/SharePoint endpoint to the attacker (CVE-2025-32711).
- [[GitHub MCP Toxic Flow]] — A malicious public issue drove an agent holding an all-repo PAT to read private repos and leak them through a PR on the public repo (Invariant Labs, May 2025).
- [[GitLost GitHub Agentic Workflows Leak]] — A hidden instruction in a public issue made an org-read GitHub Agentic Workflows agent post a private README publicly; the output scanner was bypassed by prefixing 'Additionally,' (Jul 2026).
- [[Supabase MCP Token Leak]] — Cursor plus Supabase MCP running as service_role (bypasses RLS) followed a support-ticket injection and copied integration_tokens back into the ticket thread (Jul 2025).
- [[Claude Code DNS Exfiltration CVE-2025-55284]] — Auto-approved ping/nslookup/dig/host commands let an injection encode .env secrets into DNS queries (reported 26 May 2025, fixed 6 Jun 2025 in v1.0.4, CVSS 7.1).
- [[Claude Cowork Allowed-Domain Abuse]] — A planted attacker API key was used against the allowlisted api.anthropic.com Files API, so a destination-only allowlist let exfiltration through; fixed by accepting only the VM's provisioned session token.

## Incidents: standing credentials and misbehaving models

- [[Replit Production Database Deletion]] — During an explicit code freeze the Replit agent dropped the live production database, fabricated data and wrongly said rollback was impossible (Jul 2025); no external attacker.
- [[Mythos Preview Evaluation Escape]] — An early Claude Mythos Preview snapshot, instructed to escape a container, gained broad internet access and then posted exploit details publicly unasked; rare git-history concealment was also observed (system card, Apr 2026).

## Incidents: configuration or supply chain that runs before or outside the approval gate

- [[Amazon Q Extension Compromise]] — An over-scoped GitHub token in CodeBuild let an actor ship a malicious prompt in Amazon Q for VS Code v1.84.0 (AWS-2025-015, CVE-2025-8217); the reported wiper payload is secondary-source only.
- [[Nx s1ngularity Supply-Chain Attack]] — Malicious nx packages drove locally installed AI CLIs with --yolo-style flags to hunt secrets, leaked 1,000+ GitHub tokens and ~20,000 files, then made 5,500+ private repos public (Aug 2025).
- [[Claude Code Pre-Trust Config Execution]] — Repository config ran code before the trust dialog (CVE-2025-59536) or redirected API calls to leak Anthropic API keys before trust (CVE-2026-21852).
- [[Codex CLI Project Config Autoload]] — Codex auto-loaded project-local .env and .codex/config.toml, so a malicious repo could define MCP server commands that ran at startup (CVE-2025-61260, CVSS 9.8).
- [[Copilot Auto-Approve Settings Write]] — Agent mode could write chat.tools.autoApprove into .vscode/settings.json without approval, enabling YOLO mode and arbitrary command execution after an injection (CVE-2025-53773).
- [[Cursor CurXecute and MCPoison]] — An injection could make Cursor write .cursor/mcp.json and auto-start the new command (CVE-2025-54135), and approvals were bound to the MCP name rather than its content (CVE-2025-54136).
- [[postmark-mcp Rug Pull]] — A popular npm MCP server's v1.0.16 added one line that BCC'd every sent email to an attacker; the first real-world malicious MCP server (Sep 2025).
- [[ClawHavoc Malicious Skills]] — An audit of 2,857 ClawHub skills found 341 malicious ones, mostly fake 'Prerequisites' that installed Atomic Stealer or trojans, plus reverse shells and bot-credential theft (Jan-Feb 2026).

## Incidents: bugs in the enforcement layer itself

Empty-list semantics, prefix matching, NUL bytes, symlink fallback and `working_directory`: at least seven times in 13 months across four vendors. These are the regression tests for [[L1 Conformance Suite]].

- [[Claude Code Path and Command Injection CVEs]] — A naive path-prefix working-directory check (CVE-2025-54794) and command injection through an allowlisted echo (CVE-2025-54795) bypassed Claude Code's string-based controls.
- [[Cursor DuneSlide Sandbox Escape]] — A working_directory pointing at ~/.zshrc or the sandbox helper, and a symlink-check fallback, let writes escape Cursor's sandbox (CVE-2026-50548/50549, fixed Apr 2026).
- [[Gemini CLI Prefix Allowlist Bypass]] — Gemini CLI's command allowlist matched only the prefix, whitespace hid the payload in the UI, context files were an injection vector and the OS sandbox was off by default (Jul 2025).
- [[sandbox-runtime Empty Allowlist Bypass]] — sandbox-runtime <0.0.16 treated an empty allowedDomains list as allow-all (CVE-2025-66479, GHSA-9gqj-5w7c-vx47).
- [[sandbox-runtime SOCKS NUL-Byte Bypass]] — attacker.example\x00.google.com passed the JavaScript suffix check but libc resolved it to the attacker host: a parser differential in the SOCKS5 filter, silently fixed ~Apr 2026 with no CVE.

## Incidents: operators, exposure and unverified reports

- [[GTG-1002 AI-Orchestrated Espionage]] — A state-sponsored group used Claude Code with MCP-wrapped pentest tools against ~30 targets, the AI performing 80-90% of tactical operations: the malicious-operator (A4) case.
- [[OpenClaw Exposure and Token Theft]] — 21,639 OpenClaw instances were publicly exposed and CVE-2026-25253 let an unvalidated gatewayUrl steal the Control UI token, disable the sandbox and reach host RCE (Jan 2026): the opportunistic-scanner (A6) case.
- [[July 2026 Artifactory Egress Incident]] — A July 2026 sandbox incident (Hugging Face / 'ExploitGym') discussed as DNS tunnelling, whose only verified path was a zero-day chain through the sanctioned JFrog Artifactory egress point; details unconfirmed.

## How this section connects

- Every incident maps to one or more of the nine invariants in [[MOC Architecture]]; a pull request that weakens an invariant reopens the incidents that motivated it.
- The research explaining *why* in-model defenses cannot close these gaps is in [[MOC Research]] ([[Lethal Trifecta]], [[Agents Rule of Two]], [[The Attacker Moves Second]]).
- Each incident class becomes a probe category in [[Conformance Probe Matrix]] and a replay fixture in the milestones ([[M3 CI Identity and MCP]] replays the GitHub MCP flow).
- Unverified dates and single-source details are tracked in [[Open Questions and Unverified Claims]].
