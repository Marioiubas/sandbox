---
title: "Problem Statement"
aliases: ["Engineering Requirement", "Ambient Authority"]
type: problem
section: problem
tags: [sandbox/problem, problem, topic/credentials, topic/egress, topic/isolation, topic/audit, adversary/a1, adversary/a2, adversary/a3, invariant/i1, invariant/i5, invariant/i9]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Assume the agent's intent can be hijacked; remove ambient authority (SSH keys, gh/npm tokens, cloud profiles, model keys, DB roles) and hand back only task-scoped, short-lived, audited capabilities through a policy point the agent cannot reconfigure."
related: [AUTO]
sources: [AUTO]
---

# Problem Statement

Autonomous coding agents run with the developer's full ambient authority while reading content that anyone on the internet can write, and no model-side defense has survived adaptive attack. The engineering requirement therefore starts from the assumption that the agent's intent **will** be hijacked, and asks how little a hijacked agent can then do. The product answer is a sandbox that removes ambient authority plus a broker that hands back only task-scoped, short-lived, audited capabilities through a policy point the agent cannot reconfigure.

## The situation: ambient authority meets attacker-writable input

A coding agent launched from a developer shell inherits everything that shell can reach: SSH keys, `gh` and npm tokens, cloud profiles, model API keys and database roles (the report's synthesis of the incident record; the asset list is in [[Threat Model Overview]]). In the same session it reads content that anyone can write: issues, READMEs, dependencies, support tickets, web pages and MCP tool descriptions. Two consequences follow.

1. **Every credential on disk or in the environment is one injected instruction away from the attacker.** The Nx "s1ngularity" malware drove locally installed AI CLIs with prompt-disabling flags to hunt for secrets and leaked 1,000+ valid GitHub tokens and roughly 20,000 files; a second phase made 5,500+ private repositories public ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)). See [[Nx s1ngularity Supply-Chain Attack]].
2. **Every allowed channel is an exfiltration channel.** A malicious public issue drove an agent holding an all-repo token to leak private data through a pull request on the public repo, entirely inside github.com ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)). A domain filter could not have seen it.

The MCP specification even institutionalises the pattern for local servers: implementations using STDIO "SHOULD NOT follow this specification, and instead retrieve credentials from the environment" ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)). That sentence describes exactly the secret-in-sandbox arrangement this product exists to remove. METR likewise found internal agents at frontier labs typically held human-equivalent access to "the codebase, internal documents and communications, relevant logs" ([METR](https://metr.org/blog/2026-05-19-frontier-risk-report/)).

Nearly every documented 2025–2026 incident combined three ingredients: untrusted input, a broad standing credential, and an open or "allowed" outbound channel ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability); [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)). That is the [[Lethal Trifecta]] in field form.

## Why the model cannot be the security boundary

The evidence that in-band defenses fail is strong and recent (details in [[The Attacker Moves Second]]):

- **Adaptive attacks break published defenses.** Four attack families (gradient, RL, random search, human-guided) pushed 12 published prompt-injection defenses above 90% attack success in most cases, including defenses that originally reported near-zero; human red-teamers succeeded in 100% of evaluated scenarios ([arXiv 2510.09023](https://arxiv.org/html/2510.09023)). Per-defense figures include StruQ 100%, MetaSecAlign from 2% to 96%, MELON 76–95% and PIGuard 71%.
- **Large-scale red-teaming compromises every frontier model.** NIST CAISI's 2026 competition (400+ participants, 250,000+ attack attempts, 13 frontier models across tool-use, coding and computer-use scenarios) reported that "all models were successfully compromised", and universal attack families transferred across models ([NIST CAISI](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)). An earlier CAISI study on AgentDojo found baseline attacks succeeded 11% of the time against 81% for novel red-team attacks, and 25 retries raised average success from 57% to 80% ([NIST](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)).
- **Persistence beats low single-shot rates.** Anthropic reports Claude Opus 4.7 at about 0.1% attack success on single attempts, rising to about 5–6% after 100 adaptive attempts ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).
- **The model makers say so themselves.** OpenAI calls prompt injection "unlikely to ever be fully 'solved'" ([OpenAI](https://openai.com/index/hardening-atlas-against-prompt-injection/)), and the UK NCSC says it "will never be properly mitigated" the way SQL injection was ([NCSC](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection)).

Out-of-band, deterministic defenses have held up better, but only in small tests: a June 2026 adaptive study found Progent cut mean attack success from 25.8% to 4.2%, and its authors call this "one small-scale data point" ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)). The design conclusion is that authority must be enforced **outside** the model.

## The requirement, stated as engineering

The requirement follows directly from the two bodies of evidence above (wording from the report):

> Assume the agent's intent can be hijacked. Then make sure the hijacked agent holds only short-lived, narrowly scoped capabilities, cannot read secrets, cannot reach any network except through a policy point it cannot reconfigure, and leaves an audit trail outside its own reach.

The product therefore has two parts: a **sandbox** that removes ambient authority, and a **broker** that hands back exactly the authority a task needs, scoped per repo, path, domain and HTTP method, on macOS and Linux laptops, in CI and around local MCP servers. The sandbox side is [[Two-Tier Isolation Design]]; the broker side is [[Architecture Overview]].

**Proposal.** Decompose the requirement into clauses that each map to a testable invariant:

| Clause | What it rules out | Invariant / mechanism |
|---|---|---|
| Cannot read secrets | Secrets in env, files, argv, `/proc`, response bodies | [[I1 No Secrets in the Sandbox]], [[Sentinel Swap Pattern]] |
| Only short-lived, narrowly scoped capabilities | Standing PATs, `service_role`, cloud profiles | [[Just-in-Time Credential Minting]] |
| No network except through the policy point | Raw sockets, DNS, ICMP, `HTTP_PROXY` bypass | [[Topology-Forced Egress]], [[I2 Fail-Closed Launch]], [[I6 Single Canonicaliser]] |
| A policy point it cannot reconfigure | Agent writing its own settings, MCP config, hooks; prompt-disabling flags | [[I5 Config Outside Writable Mounts]], [[I4 Repo Policy Only Narrows]], [[I8 No Flag Disables Isolation]] |
| An allowed host is not a free channel | Attacker-planted key used on an allowlisted API | [[I7 Reject Foreign Credentials]] |
| An audit trail outside its reach | Model self-reports, in-guest logs | [[I9 Hash-Chained Audit Outside the Sandbox]] |
| AI may help, never widen | LLM-drafted policy or detectors granting authority | [[I3 Probabilistic Components Only Narrow]] |

## Where the requirement applies

- **Developer laptops** (Claude Code, Codex, Cursor, Gemini CLI plus local MCP servers): entry points are repo-supplied config auto-loaded before trust, agent-writable settings, malicious MCP servers and malicious packages that drive local AI CLIs ([Nx](https://nx.dev/blog/s1ngularity-postmortem)).
- **CI runners**: both large supply-chain incidents began with over-scoped CI tokens. Nx's `pull_request_target` workflow leaked an npm publish token ([Nx](https://nx.dev/blog/s1ngularity-postmortem)); Amazon Q's CodeBuild held an "inappropriately scoped GitHub token" ([AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)).
- **Local MCP servers**: they run with whatever the environment holds, per the stdio exemption above.

The boundaries these deployments must enforce are listed in [[Trust Boundaries]]; the attackers are in [[Adversary Classes]].

## What the requirement does not promise

The design shrinks authority and makes its use auditable. It does **not** stop an injected agent from misusing authority it legitimately holds: a proxy "prevents theft but not misuse" ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)). The explicit list is in [[Threat Model Non-Goals]]. Code, docs and CLI output must never claim the broker "stops prompt injection".

## How it connects

- motivated-by:: [[The Attacker Moves Second]]
- motivated-by:: [[Lethal Trifecta]]
- motivated-by:: [[Nx s1ngularity Supply-Chain Attack]]
- depends-on:: [[Threat Model Overview]]
- depends-on:: [[Adversary Classes]]
- depends-on:: [[Trust Boundaries]]
- contrasts-with:: [[Threat Model Non-Goals]]
- implements:: [[Product Thesis]]
- delivered-by:: [[Two-Tier Isolation Design]]
- delivered-by:: [[Architecture Overview]]

## Implications for the build

- Treat every clause of the requirement table as a release gate: each must have an automated test (see [[L1 Conformance Suite]] and [[Conformance Probe Matrix]]) before a milestone closes.
- Design every component on the assumption that the process inside the sandbox is adversarial and capable (see [[Adversary Classes]], A3). No component may rely on the model following instructions, including "do not cheat" or "respect the code freeze".
- Do not add a model-based detector as a decision point that can allow something; detectors may only narrow ([[I3 Probabilistic Components Only Narrow]]).
- The wrapper must cover laptops, CI and stdio MCP servers from the same binary; a deployment that leaves one of these with ambient credentials leaves the requirement unmet.
- User-facing text (CLI help, README, threat-model doc) must state the non-goals verbatim.

## Open questions

- No public post-mortem of a CI-hosted coding-agent incident exists; CI risk is inferred from the Nx and Amazon Q token root causes ([[Open Questions and Unverified Claims]]).
- No primary data on how often local MCP servers run with full ambient credentials; the claim is inferred from incidents.
- The adaptive-robustness evidence for deterministic monitors is thin (one small-scale study); see [[Adaptive Evaluation of Deterministic Monitors]].

## Sources

- [arXiv 2510.09023, The Attacker Moves Second](https://arxiv.org/html/2510.09023)
- [NIST CAISI red-teaming competition](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)
- [NIST CAISI agent-hijacking evaluations, Jan 2025](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)
- [OpenAI, hardening Atlas against prompt injection](https://openai.com/index/hardening-atlas-against-prompt-injection/)
- [NCSC, prompt injection is not SQL injection](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection)
- [Anthropic, How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude)
- [arXiv 2606.26479](https://arxiv.org/abs/2606.26479)
- [Wiz, s1ngularity](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)
- [Nx postmortem](https://nx.dev/blog/s1ngularity-postmortem)
- [Invariant Labs, GitHub MCP](https://invariantlabs.ai/blog/mcp-github-vulnerability)
- [MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- [METR Frontier Risk Report](https://metr.org/blog/2026-05-19-frontier-risk-report/)
- [AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)
- [Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)
