---
title: "Amazon Q Extension Compromise"
aliases: ["CVE-2025-8217", "AWS-2025-015"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/supply-chain, topic/credentials, control/pin, control/cred-out, control/iso, control/audit, adversary/a2, boundary/tb6, boundary/tb7, platform/ci, invariant/i1, milestone/m3, evidence/secondary]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "An over-scoped GitHub token in CodeBuild let an actor ship a malicious prompt in Amazon Q for VS Code v1.84.0 (AWS-2025-015, CVE-2025-8217); the reported wiper payload is secondary-source only."
related: [AUTO]
sources: [AUTO]
---

# Amazon Q Extension Compromise

An "inappropriately scoped GitHub token" in the CodeBuild configuration of the Amazon Q Developer extension for VS Code let an actor commit malicious code that shipped automatically in release 1.84.0 ([AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)). AWS says the code failed to execute because of a syntax error. Secondary reports say the payload was a prompt telling the agent to wipe the local system and delete cloud resources with the user's AWS profile. Either way, the latent impact depended entirely on the agent's ambient access to local files and AWS credentials.

## Timeline

- **Jul 2025**: malicious code committed via the over-scoped CI token and released automatically in v1.84.0.
- **23 Jul 2025**: AWS bulletin AWS-2025-015 published (updated 25 Jul); fixed in 1.85.0 and 1.84.0 pulled ([AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/); [GHSA-7g7f-ff96-5gcw](https://github.com/aws/aws-toolkit-vscode/security/advisories/GHSA-7g7f-ff96-5gcw)).

## What happened

1. The extension's CodeBuild configuration held a GitHub token with more permissions than the build needed ([AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)).
2. An actor used it to commit malicious code into the repository.
3. The release pipeline shipped it automatically in v1.84.0.
4. According to AWS, the code "was unsuccessful in executing due to a syntax error".

The AWS advisories do not describe what the payload was meant to do. Secondary reporting says it was a prompt instructing the agent to wipe the local system to a near-factory state and delete cloud resources using the user's AWS profile ([SC Media](https://www.scworld.com/news/amazon-q-extension-for-vs-code-reportedly-injected-with-wiper-prompt); [PointGuard AI](https://www.pointguardai.com/blog/clean-to-factory-state-the-ai-prompt-that-nearly-wiped-aws-accounts)). OWASP uses Amazon Q as the example for ASI02 Tool Misuse ([OWASP GenAI](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)).

> [!question] Unverified
> The "wiper" intent appears only in secondary reporting; treat it as unconfirmed by AWS.

## Root cause

- **(e) supply chain** entered through **(b) an over-scoped CI token** (boundary TB7), and was delivered to users through the extension channel (TB6).
- Adversary **A2** (compromised publisher pipeline).
- The damage the payload could do was bounded only by what the agent could reach on each user's machine.

## Impact

A malicious release reached users of v1.84.0. AWS reports no successful execution because of the syntax error.

## Stopping control in this design

Two sides: the publisher's CI and the victim's laptop.

- **Publisher side, would have prevented: TASK-TOK in CI.** **Proposal.** In the broker's CI mode the job holds only the runner OIDC token; the broker exchanges it for a narrowly scoped, short-lived credential, and the agent or build tree never sees a long-lived secret ([[M3 CI Identity and MCP]]).
- **Consumer side, would have prevented: PIN and provenance.** Extensions, MCP servers and tool manifests are pinned by content hash with re-approval on change ([[MCP Guard]]); an unexpected release is not auto-trusted.
- **Consumer side, would have contained: CRED-OUT + ISO.** No AWS profile is readable inside the sandbox ([[I1 No Secrets in the Sandbox]]); AWS access, when granted, is a 15-minute STS session with a session policy scoped to the task ([[AWS STS Session Policies]]); destructive AWS verbs are outside the grant. A wiper prompt could at most damage the writable repo copy.
- **AUDIT** records every attempted AWS call with the minted session's identity.

## Regression test

- **Category 2 (credential exposure)**: with `~/.aws/credentials` and `~/.aws/config` containing canaries on the host, the sandbox cannot read them; env, argv and `/proc` show only sentinels.
- **Category 10 (filesystem)**: destructive filesystem operations outside the granted writable roots fail at the kernel.
- **M3 fixture**: with an S3 read grant, a scripted request to delete resources or write outside the prefix is denied by the session policy and by Cedar.

## How it connects

- mitigated-by:: [[MCP Guard]]
- mitigated-by:: [[I1 No Secrets in the Sandbox]]
- mitigated-by:: [[AWS STS Session Policies]]
- evaluated-by:: [[M3 CI Identity and MCP]]
- example-of:: [[Adversary Classes]]
- part-of:: [[Threat Model Overview]]

The CI-token entry point is shared with [[Nx s1ngularity Supply-Chain Attack]].

## Implications for the build

- `filesystem.deny_read` defaults must include `~/.aws`, `~/.config/gh`, `~/.ssh`, `~/.netrc` and `~/.docker/config.json` (the `broker.toml` default profile).
- The AWS issuer must compile session policies from the task's grant, never assume a broad role unmodified.
- The GitHub Action integration must document that job secrets never enter the agent tree.

## Open questions

- Wiper payload intent is secondary-source only ([[Open Questions and Unverified Claims]]).

## Sources

- [AWS Security Bulletin AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)
- [GHSA-7g7f-ff96-5gcw](https://github.com/aws/aws-toolkit-vscode/security/advisories/GHSA-7g7f-ff96-5gcw)
- [SC Media](https://www.scworld.com/news/amazon-q-extension-for-vs-code-reportedly-injected-with-wiper-prompt) (secondary)
- [PointGuard AI](https://www.pointguardai.com/blog/clean-to-factory-state-the-ai-prompt-that-nearly-wiped-aws-accounts) (secondary)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
