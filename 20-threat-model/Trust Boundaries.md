---
title: "Trust Boundaries"
aliases: ["TB1", "TB2", "TB3", "TB4", "TB5", "TB6", "TB7"]
type: concept
section: threat
tags: [sandbox/threat, concept, boundary/tb1, boundary/tb2, boundary/tb3, boundary/tb4, boundary/tb5, boundary/tb6, boundary/tb7, topic/isolation, topic/egress, topic/credentials, topic/mcp, topic/approval, platform/macos, platform/linux, platform/ci, invariant/i4, invariant/i5]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The seven boundaries TB1-TB7 (human-agent, agent-OS, sandbox-broker, broker-external, workspace-context, tool supply chain-registry, CI trigger-CI credentials): what crosses each and which mechanism enforces it."
related: [AUTO]
sources: [AUTO]
---

# Trust Boundaries

Seven trust boundaries separate the three trusted principals (human, policy author, broker plus kernel or hypervisor) from everything untrusted. Each boundary has a defined set of things allowed to cross it and one enforcing mechanism; every incident in the record is a crossing that the victim system failed to mediate. The boundary set is the report's **Proposal**, derived from the incident record in research note 04b Q5.

## The seven boundaries

| Boundary (Proposal) | What crosses it | Enforced by | Component |
|---|---|---|---|
| **TB1** human ↔ agent | Approvals, intent | Approval UI that renders ground truth (full command, authority diff), not model summaries | [[Fatigue-Resistant Approval Interfaces]] |
| **TB2** agent process ↔ OS | Syscalls, file access | Seatbelt, or bwrap + seccomp + Landlock; a VM in hard mode | [[Sandbox Launcher]], [[Two-Tier Isolation Design]] |
| **TB3** sandbox ↔ broker | The only network path; capability requests, never raw secrets | UDS, localhost port or vsock; per-session sentinel | [[Netguard Ingress]] |
| **TB4** broker ↔ external services | Real credentials, attached here | Cedar decision plus minted, audience-bound token | [[Credential Injector and Issuers]] |
| **TB5** workspace ↔ agent context | Repo files, context files, project config | Repo config inert until content-hashed approval; policy can only narrow | [[I4 Repo Policy Only Narrows]], [[I5 Config Outside Writable Mounts]] |
| **TB6** tool supply chain ↔ registry | MCP servers, skills, extensions | Manifest hash pinning; re-approval on change | [[MCP Guard]] |
| **TB7** CI trigger ↔ CI credentials | PR, issue and comment payloads | Runner OIDC exchanged by the broker; no long-lived secrets in the job | [[M3 CI Identity and MCP]] |

## Each boundary in detail

### TB1: human ↔ agent

The human is trusted for intent, not for attentive approval. Users approve 93% of Claude Code permission prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)), and OWASP lists "Overwhelming HITL" as threat T10 ([OWASP](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)). Gemini CLI showed that approval UIs can be lied to: whitespace hid the malicious part of a command ([Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)). **Proposal.** Prompt rarely, only for widenings and irreversible verbs; render the exact command or the Cedar authority diff; never let a prompt-disabling flag change what TB2–TB4 enforce ([[I8 No Flag Disables Isolation]]).

### TB2: agent process ↔ OS

String checks inside the agent failed repeatedly (Claude Code path-prefix check, Cursor `working_directory` and symlink fallback) ([Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/); [The Hacker News](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)). The boundary must be kernel-enforced: generated SBPL on macOS; bubblewrap with `--ro-bind / /`, the repo bound writable, `.git/hooks`, `.git/config` and agent config directories read-only, `--unshare-net`, seccomp and Landlock on Linux; a VM in the hard tier. Codex's production Linux pipeline uses the same shape ([codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)).

### TB3: sandbox ↔ broker

The sandbox has no network except the broker. On Linux the network namespace has no interface and the only exit is a Unix socket; on macOS Seatbelt permits only the broker's localhost port; in a VM the only device is vsock ([srt](https://github.com/anthropic-experimental/sandbox-runtime)). What crosses is a request plus a per-session sentinel, never a secret. On macOS any local process can reach a loopback port, so the data plane authenticates each session with a sentinel `Proxy-Authorization` value; leaking it grants nothing beyond that session's policy on that host. The **control** socket (`ctl.sock`, JSON-RPC, mode 0600, peer credentials checked) is a separate channel the sandbox can never reach: seccomp blocks new `AF_UNIX` sockets after the bridge and SBPL denies the path (report reference architecture, Proposal).

### TB4: broker ↔ external services

Real credentials exist only here. Each request is authorized by Cedar, then a minted, audience-bound token is attached; client-supplied `Authorization`, `x-api-key`, cookies and `Proxy-Authorization` are stripped, and any credential the broker did not issue is rejected, which is the Cowork lesson ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). Semantic adapters (git, GitHub API, registries, LLM APIs, MCP) sit on this boundary because allowed hosts are also exfiltration channels.

### TB5: workspace ↔ agent context

Repository content is untrusted data, including files that look like configuration. Claude Code ran repo-supplied config before the trust dialog (CVE-2025-59536) and let repo config redirect API calls before trust (CVE-2026-21852) ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-59536); [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)); Codex auto-loaded project `.env` and `.codex/config.toml` (CVE-2025-61260) ([GHSA](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)). **Proposal.** Repo policy can only narrow user and org policy; `.claude/`, `.cursor/`, `.codex/`, `.vscode/`, `.env`, hooks and MCP manifests are inert until content-hash approved and live outside every writable mount.

### TB6: tool supply chain ↔ registry

MCP servers, skills and extensions cross into the trusted computing base when installed or updated. postmark-mcp's one-line rug pull and 341 malicious ClawHub skills show the registry is hostile ([The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html); [The Hacker News](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html)). Invariant Labs recommends pinning server versions and hashing tool descriptions ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)). **Proposal.** The MCP guard hashes `tools/list` (names, schemas, descriptions); any change revokes the server's grants until re-approved; each server runs in its own sandbox as its own principal.

### TB7: CI trigger ↔ CI credentials

Both large supply-chain incidents started here. Nx's `pull_request_target` workflow echoed unsanitised PR titles with read/write default permissions, leaking the npm publish token ([Nx](https://nx.dev/blog/s1ngularity-postmortem)); Amazon Q's CodeBuild held an "inappropriately scoped GitHub token" ([AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)). An agent in CI reading PR titles, issues or comments is in the same position as the GitHub MCP victim ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)). **Proposal.** The broker runs outside the sandbox in the runner, holds the runner OIDC token, exchanges it for a session grant, and the agent tree never sees a long-lived secret.

## Per-deployment view

- **Developer laptop**: all seven apply; TB5 and TB6 are the most exercised entry points (repo config, MCP servers, malicious packages) ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-59536); [Nx](https://nx.dev/blog/s1ngularity-postmortem)).
- **CI runner**: TB7 dominates; TB1 is usually absent (no human), so HITL must become a policy deny or an out-of-band approval.
- **Cloud sandbox**: TB3/TB4 in the host (Anthropic keeps git credentials in a proxy outside the sandbox that checks each operation and attaches the token ([Anthropic](https://www.anthropic.com/engineering/claude-code-sandboxing))); residual risks are enforcement-layer bugs, container misconfiguration escapes and abuse of the hosted agent (A4).

## How it connects

- part-of:: [[Threat Model Overview]]
- implements:: [[Two-Tier Isolation Design]]
- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[Netguard Ingress]]
- depends-on:: [[Credential Injector and Issuers]]
- depends-on:: [[MCP Guard]]
- depends-on:: [[I4 Repo Policy Only Narrows]]
- depends-on:: [[I5 Config Outside Writable Mounts]]
- depends-on:: [[Fatigue-Resistant Approval Interfaces]]
- delivered-by:: [[M3 CI Identity and MCP]]

## Implications for the build

- Every boundary needs at least one crossing test in [[Conformance Probe Matrix]]: TB2 (filesystem, category 10), TB3 (proxy bypass and alternate protocols, categories 5 and 9; control socket unreachable), TB4 (foreign credential and credential exposure, categories 1 and 2), TB5 (write attempts on config paths; repo policy widening rejected), TB6 (changed tool description revokes grants), TB7 (untrusted-issue CI fixture sees no long-lived secret).
- The control socket and the data socket must be distinct, and a test must prove the sandbox cannot open the control socket.
- Audit rows record which boundary a decision was made at, so `broker why` can say "denied at TB4: foreign credential".
- In CI there is no human at TB1: any rule that would prompt must resolve to deny unless an out-of-band approval channel is configured.

## Open questions

- No public post-mortem of an incident in a CI-hosted coding agent exists; TB7 risk is inferred from the Nx and Amazon Q token root causes ([[Open Questions and Unverified Claims]]).
- No data on how often local MCP servers run with full ambient credentials (TB6).
- Transparent interception on macOS without a Network Extension is unvalidated; clients that ignore proxy variables fail closed at TB3.

## Sources

- [Anthropic, auto mode](https://anthropic.com/engineering/claude-code-auto-mode); [OWASP Agentic Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/); [Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)
- [Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/); [The Hacker News, DuneSlide](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html); [codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md); [srt](https://github.com/anthropic-experimental/sandbox-runtime)
- [Anthropic, How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude); [Anthropic, Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [NVD CVE-2025-59536](https://nvd.nist.gov/vuln/detail/CVE-2025-59536); [NVD CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852); [GHSA-xrxf-jgv3-qmrm](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)
- [The Hacker News, postmark-mcp](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html); [The Hacker News, ClawHavoc](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html); [Invariant Labs, tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [Nx postmortem](https://nx.dev/blog/s1ngularity-postmortem); [AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/); [Invariant Labs, GitHub MCP](https://invariantlabs.ai/blog/mcp-github-vulnerability)
