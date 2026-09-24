---
title: "GitHub MCP Toxic Flow"
aliases: ["Toxic Agent Flow"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/git, topic/mcp, topic/credentials, topic/ifc, control/task-tok, control/egress, control/audit, adversary/a1, boundary/tb4, boundary/tb5, milestone/m3]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "A malicious public issue drove an agent holding an all-repo PAT to read private repos and leak them through a PR on the public repo (Invariant Labs, May 2025)."
related: [AUTO]
sources: [AUTO]
---

# GitHub MCP Toxic Flow

A prompt injection planted in an issue on a public repository made an agent using the official GitHub MCP server read the victim's private repositories with the user's all-repo token and publish their contents in a pull request on the public repo. The whole flow stayed inside github.com, so no domain-level egress filter could have seen it. It is the reference case for task-scoped tokens and for turning the lethal trifecta into an enforced session rule, and [[M3 CI Identity and MCP]] must replay it.

## Timeline

- **26 May 2025**: published by Invariant Labs ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)). Demonstrated with Claude 4 Opus in Claude Desktop using the official GitHub MCP server.
- No patch: Invariant describes it as "not a flaw in the GitHub MCP server code itself, but rather a fundamental architectural issue that must be addressed at the agent system level" ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)).

## What happened

1. An attacker opened an issue on a public repo owned by the victim, containing injected instructions.
2. The user asked their agent to review the repo's open issues.
3. The agent read the issue and followed it: it used the user's personal access token, which covered public and private repos, to read private repositories.
4. It wrote private data (private project names, relocation plans, salary information) into a pull request on the public repository, where the attacker could read it ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)).

Invariant noted "Even state-of-the-art aligned models are vulnerable", and recommended granular permissions, one repository per session, runtime guardrails and monitoring. OWASP used the case as the example for ASI04 Agentic Supply Chain ([OWASP GenAI](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)).

## Root cause

- **(a) untrusted input steering tools** plus **(b) over-broad standing credential** (a PAT spanning all of the user's repos).
- The write-back channel (a public PR) was inside the same service the agent legitimately used.
- Adversary **A1**. Shape: [[Lethal Trifecta]] in its purest form: private data (private repos), untrusted content (public issue), external communication (public PR).

## Impact

Disclosure of private repository content to anyone reading the public repo. Demonstrated, not reported as exploited in the wild.

## Stopping control in this design

- **Would have prevented: TASK-TOK.** The broker mints a GitHub App installation token restricted to the task's single repository ([[GitHub App Installation Tokens]], [[Just-in-Time Credential Minting]]); the private repos are simply not reachable.
- **Would have prevented even with a broader grant: the trifecta rule.** Once the session has read content anyone can write (`untrusted_input`) and a private repo (`sensitive_read`), any `http.write` or `git.push` needs out-of-band approval ([[Trifecta Session Labels]]). The report states this "would have stopped the GitHub MCP and GitLost flows at the public-write step". The Cedar form is in [[Example Cedar Policies]]:

```cedar
forbid (principal, action in [Broker::Action::"http.write", Broker::Action::"git.push"], resource)
when { context.session.trifecta.untrusted_input && context.session.trifecta.sensitive_read }
unless { context.session.approved };
```

(Proposal; not compiled.) The broker, not the model, sets these labels: it knows repo visibility from the API it proxies.

- **Would have contained: EGRESS semantics and AUDIT.** The [[GitHub API Adapter]] maps `POST /repos/{o}/{r}/pulls` to `pr.create` on a specific repo, so "writes only to the task repo" is expressible; every call is logged.

**Proposal.** An org policy may additionally forbid public-sink writes whenever `untrusted_input` is set, addressing Willison's point that untrusted input plus external effect is dangerous even without private data ([simonwillison.net](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)).

## Regression test

- **M3 acceptance replay**: a fixture with a public repo whose issue carries an injection and a private repo in the same account; the wrapped GitHub MCP server may read issues, but the attempt to write private content to the public repo is stopped at the public write and `broker why` names the trifecta rule.
- **Category 1 (allowed-destination abuse)**: a PR, issue comment or gist on github.com targeting a repo other than the task repo is denied by verb/resource rules, not hostname.
- **Unit**: the trifecta labels flip exactly on (public issue read) and (private repo read) and reset only with a new session.

## How it connects

- example-of:: [[Lethal Trifecta]]
- example-of:: [[Agents Rule of Two]]
- mitigated-by:: [[Trifecta Session Labels]]
- mitigated-by:: [[GitHub App Installation Tokens]]
- mitigated-by:: [[GitHub API Adapter]]
- mitigated-by:: [[Example Cedar Policies]]
- evaluated-by:: [[M3 CI Identity and MCP]]
- part-of:: [[Threat Model Overview]]
- example-of:: [[Adversary Classes]]

The same pattern recurred in 2026 as [[GitLost GitHub Agentic Workflows Leak]].

## Implications for the build

- The GitHub API adapter must know repo visibility (public/private) for every resource it touches, from GitHub's own responses, to set `sensitive_read`.
- `untrusted_input` must flip on reading issues/PRs of public repos and on designated ticket or web sources, whether fetched over REST, GraphQL or MCP.
- Default grant: one repo per session; never mint installation tokens with omitted repository selection (omitted fields inherit the whole installation).

## Open questions

- Label creep: session-level labels are coarse; mitigation is one small task per session ([[Trifecta Session Labels]]). No other open items specific to this incident.

## Sources

- [Invariant Labs, GitHub MCP vulnerability](https://invariantlabs.ai/blog/mcp-github-vulnerability)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [Simon Willison, new prompt injection papers](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
