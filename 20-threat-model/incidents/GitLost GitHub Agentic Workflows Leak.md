---
title: "GitLost GitHub Agentic Workflows Leak"
aliases: ["GitLost"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/git, topic/ifc, topic/credentials, control/task-tok, control/egress, adversary/a1, boundary/tb4, boundary/tb7, platform/ci, milestone/m3, evidence/secondary]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "A hidden instruction in a public issue made an org-read GitHub Agentic Workflows agent post a private README publicly; the output scanner was bypassed by prefixing 'Additionally,' (Jul 2026)."
related: [AUTO]
sources: [AUTO]
---

# GitLost GitHub Agentic Workflows Leak

Fourteen months after the GitHub MCP toxic flow, the same pattern hit GitHub's own agentic CI product: a hidden instruction in a public issue made an agent with organisation-wide read access post a private repository's README as a public issue comment. GitHub's output-scanning defense was bypassed by starting the malicious instruction with the word "Additionally,". The lesson is blunt: output classifiers do not replace scoping.

## Timeline

- **7 Jul 2026**: reported by Noma Security; covered by The Hacker News ([The Hacker News](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)).
- Per the report, GitHub offered no patch, only architectural guidance: single-repo tokens, restricted public outputs, human review and author gating.

## What happened

1. An attacker filed an issue on a public repository in an organisation that ran GitHub Agentic Workflows. The issue carried a hidden instruction.
2. The workflow's agent, configured with org-wide read access, processed the issue.
3. It read a private repository's README and posted it as a comment on the public issue.
4. GitHub's threat-detection output scanner, meant to catch this, was bypassed by prefixing the malicious instruction with "Additionally," ([The Hacker News](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)).

Controls that failed, per the report: output scanning, input cleaning, and read-only token defaults once broad org read was configured.

## Root cause

- **(a) untrusted input steering tools** plus **(b) over-broad standing credential** (org-wide read).
- The exfiltration channel was a public comment on the same forge.
- Adversary **A1**, delivered through a CI trigger (**TB7**: issue payload next to privileged CI credentials).
- A probabilistic output filter was the load-bearing control; one word defeated it, consistent with the adaptive-attack record in [[The Attacker Moves Second]].

## Impact

Disclosure of private repository content to the public. Scale of real-world exploitation is not reported.

## Stopping control in this design

- **Would have prevented: TASK-TOK.** The CI broker mints a token for the single repository the workflow runs on; the private repository is not readable ([[GitHub App Installation Tokens]]).
- **Would have prevented: trifecta rule.** After a public-issue read (`untrusted_input`) and a private-repo read (`sensitive_read`), the public comment (`http.write`) requires approval; in CI with no approver, it is denied ([[Trifecta Session Labels]]).
- **Would have contained: verb rules.** The [[GitHub API Adapter]] classifies the comment as `issue.comment` on a specific public repo, so an org policy can forbid public-sink writes whenever `untrusted_input` is set.
- **What does not count as a control here:** any output classifier. **Proposal.** Detectors may be added only as narrowing signals ([[I3 Probabilistic Components Only Narrow]]), never as the reason a write is allowed.

## Regression test

- Extend the [[GitHub MCP Toxic Flow]] replay to a CI fixture: an untrusted-issue workflow in an org with a private repo; assert the agent tree holds no org-wide credential and the public comment is denied with a trifecta reason.
- **Category 1 (allowed-destination abuse)**: issue comments and PR bodies on repos other than the task repo are denied by resource rules.
- **L2 adaptive probe**: run adaptive rephrasings of the exfiltration instruction; the broker's decision must be identical regardless of wording, since it never inspects the text.

## How it connects

- example-of:: [[Lethal Trifecta]]
- motivated-by:: [[The Attacker Moves Second]]
- mitigated-by:: [[Trifecta Session Labels]]
- mitigated-by:: [[GitHub App Installation Tokens]]
- mitigated-by:: [[GitHub API Adapter]]
- part-of:: [[Threat Model Overview]]

This is a 2026 recurrence of [[GitHub MCP Toxic Flow]] in a CI product.

## Implications for the build

- The CI integration ([[M3 CI Identity and MCP]]) must default to single-repo minting even when the workflow's native token could be broader.
- In CI, any rule that would prompt resolves to deny unless an out-of-band approval channel exists.
- Never document an output scanner as a mitigation for exfiltration.

## Open questions

- Single secondary source (The Hacker News reporting Noma Security); the Noma write-up and any GitHub statement were not fetched ([[Open Questions and Unverified Claims]]).

## Sources

- [The Hacker News, Jul 2026](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)
