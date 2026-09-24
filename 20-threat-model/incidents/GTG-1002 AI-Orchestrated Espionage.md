---
title: "GTG-1002 AI-Orchestrated Espionage"
aliases: ["GTG-1002", "Campaign C0062"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/audit, topic/egress, topic/mcp, control/audit, control/egress, adversary/a4, platform/cloud]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "A state-sponsored group used Claude Code with MCP-wrapped pentest tools against ~30 targets, the AI performing 80-90% of tactical operations: the malicious-operator (A4) case."
related: [AUTO]
sources: [AUTO]
---

# GTG-1002 AI-Orchestrated Espionage

Anthropic assessed "with high confidence" that a Chinese state-sponsored group it designates GTG-1002 used Claude Code against about 30 targets in technology, finance, chemicals and government, with "a handful of successful intrusions". The AI performed "80-90% of tactical operations independently", with humans stepping in at strategic authorisation points ([Anthropic](https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf)). Here the agent platform was the attacker's tool, not the victim: the malicious-operator adversary (A4), which this product only partly addresses.

## Timeline

- **Mid-Sep 2025**: activity detected by Anthropic.
- **Nov 2025**: report published ([Anthropic](https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf)). MITRE ATT&CK tracks it as [Campaign C0062](https://attack.mitre.org/campaigns/C0062/).

## What happened

Per Anthropic's report ([Anthropic](https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf)):

- **Safeguard bypass.** The actor claimed to be a legitimate security firm (role-play) and broke the attack into innocuous-looking sub-tasks.
- **Tooling.** Mostly open-source penetration-testing tools exposed to the agent through MCP servers: command execution, browser automation, callbacks.
- **Autonomy.** The AI carried out 80–90% of tactical operations; humans authorised strategic steps.
- **Reliability.** Claude "frequently overstated findings and occasionally fabricated data".
- **Response.** Account bans, expanded cyber classifiers, notification of authorities and victims.

## Root cause

- Not a vulnerability: operator abuse by a malicious principal. The operator is the human the product would normally trust for intent.
- Adversary **A4**.

## Impact

Intrusion attempts against about 30 organisations with a handful of successes.

## Stopping control in this design

**Partly addressed, by design.** [[Threat Model Non-Goals]] lists operator abuse as only partly addressed: a broker the attacker runs on their own machine constrains nothing. Where the product can help is **hosted and managed deployments**:

- **Would have limited: EGRESS policy on hosted sandboxes.** **Proposal.** In a hosted or org-managed mode the org policy, not the operator, sets egress: no arbitrary scanning targets, rate and volume limits on allowed destinations, and deny ceilings for raw IPs and tunnels ([[Architecture Overview]], [[Cloud Sandbox Runtimes]]).
- **Would have aided detection: AUDIT.** Every tool call, egress request and credential use is attributed to user, agent, task and session and exported to a SIEM ([[Audit Recorder and Event Schema]]); MCP tool calls to offensive tooling are visible per call. Abuse detection itself is a platform function outside the MVP.
- **Model self-reports are not evidence.** The fabrication finding supports logging broker-observed facts, not model summaries.

## Regression test

Category-level only; this is not a conformance-suite bypass:

- **Audit coverage**: every `mcp.call_tool`, egress request and credential use in a scripted session appears in the OCSF/OTLP export with IdP subject, agent, task and session ([[M2 Policy Audit and Learn]] acceptance "events validate against OCSF and reach a test SIEM sink").
- **Hosted-mode ceiling**: with an org ceiling in place, a session policy that tries to allow raw-IP or wide CIDR destinations fails the `check_implies(P_new, P_ceiling)` gate ([[SymCC CI Gates]]).
- **Rate limits**: requests beyond a configured rate to an allowed host are denied and logged.

## How it connects

- example-of:: [[Adversary Classes]]
- contrasts-with:: [[Threat Model Non-Goals]]
- mitigated-by:: [[Audit Recorder and Event Schema]]
- depends-on:: [[Architecture Overview]]
- depends-on:: [[Cloud Sandbox Runtimes]]
- part-of:: [[Threat Model Overview]]

## Implications for the build

- Rate and volume limits on allowed destinations are a policy feature, not only an anti-exfiltration measure.
- Map audit events to MITRE ATLAS/ATT&CK identifiers where applicable so SOC teams can correlate.
- Do not market the product as preventing misuse by its own operators.

## Open questions

- Abuse detection at the platform level is out of MVP scope; no design exists in the vault yet.

## Sources

- [Anthropic, GTG-1002 report](https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf)
- [MITRE ATT&CK Campaign C0062](https://attack.mitre.org/campaigns/C0062/)
