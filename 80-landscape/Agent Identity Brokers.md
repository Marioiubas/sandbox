---
title: "Agent Identity Brokers"
aliases: ["Keycard", "Aembit", "Arcade", "Tailscale Aperture"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/identity, topic/credentials, topic/audit, topic/mcp, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Identity without an egress sandbox: Keycard (task-scoped JIT credentials via agent hooks, delegation chaining, closest to this thesis but closed), Aembit (blended identity, MCP Identity Gateway VM, $20/agent/month), Arcade (per-user tool OAuth) and Tailscale Aperture."
related: ["[[Just-in-Time Credential Minting]]", "[[Okta Cross App Access]]", "[[Gap Analysis]]", "[[Risk Register]]", "[[Audit Recorder and Event Schema]]", "[[MCP Authorization Spec]]", "[[Revocable Sub-Agent Delegation]]", "[[AWS AgentCore]]", "[[Entra Agent ID]]", "[[Topology-Forced Egress]]", "[[Open Questions and Unverified Claims]]", "[[Product Thesis]]", "[[MCP Gateways]]", "[[Credential Injector and Issuers]]"]
sources: ["https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/", "https://www.globenewswire.com/news-release/2026/05/14/3295239/0/en/keycard-launches-identity-and-access-for-multi-agent-apps.html", "https://www.helpnetsecurity.com/2026/05/15/keycard-for-multi-agent-apps/", "https://siliconangle.com/2025/10/21/ai-agent-security-startup-keycard-reels-38m/", "https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/", "https://docs.aembit.io/get-started/use-cases/ai-agents/", "https://docs.arcade.dev/en/home/auth/auth-tool-calling", "https://workos.com/blog/arcade-vs-workos-agent-authentication-enterprise-auth", "https://tailscale.com/docs/aperture/what-is-aperture", "https://startwithidentity.com/blog/agent-identity-gets-a-protocol/", "https://modelcontextprotocol.io/specification/latest/basic/authorization"]
---

# Agent Identity Brokers

> Identity without an egress sandbox: Keycard (task-scoped JIT credentials via agent hooks, delegation chaining, closest to this thesis but closed), Aembit (blended identity, MCP Identity Gateway VM, $20/agent/month), Arcade (per-user tool OAuth) and Tailscale Aperture.

## What they are

Vendors that solve the *identity* half of the thesis: binding a user and an agent into one access decision, vaulting or issuing credentials so the model never holds them, and streaming attributed telemetry. None of them ships an OS sandbox or topology-forced egress. An agent that can open a raw socket, or read a file its user can read, is outside their control. The report's one-line verdict: "identity without an egress sandbox".

## Teardowns

### Keycard

- **Keycard for Coding Agents** was announced on 19 Mar 2026, with Chime named as a production customer. It hooks the Claude Code and Cursor "hook and tool approval APIs" and issues credentials "scoped to the task, agent, user, and environment". Credentials are held in memory only and reaped at session end. It runs as `keycard run` on laptops, in CI containers or as a gateway (on-device, cloud or hosted). It supports OAuth 2.1/OIDC, sends telemetry to SIEM and supports step-up approval. No public pricing ([Keycard](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/)).
- "Credentials are injected just-in-time for that specific action and identity." There are three modes: federated, brokered (runtime attenuation) and secrets (rotation). Identity is resolved across user × agent × device × task, with device and workload attestation. **Delegation chaining** stops sub-agents exceeding their parent. An optional gateway keeps real credentials away from agents ([Keycard](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/)).
- Identity for multi-agent apps followed on 14 May 2026 ([GlobeNewswire](https://www.globenewswire.com/news-release/2026/05/14/3295239/0/en/keycard-launches-identity-and-access-for-multi-agent-apps.html); [Help Net Security](https://www.helpnetsecurity.com/2026/05/15/keycard-for-multi-agent-apps/)).
- Keycard launched with $38M for per-task agent access control ([SiliconANGLE](https://siliconangle.com/2025/10/21/ai-agent-security-startup-keycard-reels-38m/)).
- **Licence:** closed.

**Keycard is the closest product to this thesis** on minting and identity, but it is closed and has no OS sandbox ([[Gap Analysis]]).

### Aembit

- **Aembit IAM for Agentic AI** went GA in April 2026. It evaluates "Blended Identity" (agent plus human) per request, through a managed **MCP Authorization Server** (OAuth 2.1; Okta, Azure AD or Google via OIDC/SAML) and an **MCP Identity Gateway deployed as a Linux VM** that exchanges credentials so "the agent never holds direct credentials". It can deploy as a host proxy, CLI or SDK; containers are on the roadmap ([Aembit](https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/)).
- Its MCP Authorization Server supports OAuth 2.1 with DCR for Claude Desktop, Gemini CLI and others. The audit example reads: "<user>'s Claude Desktop agent accessed Jira… under policy 'Jira-Read', and made 3 API calls" ([Aembit docs](https://docs.aembit.io/get-started/use-cases/ai-agents/)).
- **Pricing:** Starter free, AI Teams **$20 per agent per month**, Enterprise custom ([Aembit](https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/)). This is the main public price anchor for the broker's commercial tier.
- **Licence:** closed.

### Arcade

- An "actions runtime" doing per-user OAuth for tools ("authorized tool calling"); agents never hold the tokens ([Arcade docs](https://docs.arcade.dev/en/home/auth/auth-tool-calling)).
- An MCP runtime with managed OAuth 2.0/2.1 (PKCE, refresh). "LLMs never see OAuth tokens". It runs in cloud, on-prem or hybrid, and does not do SSO/SCIM for your own app. Pricing as of 3 Dec 2025: Hobby free, Growth $25/mo plus $0.01 per standard execution, Enterprise custom ([WorkOS comparison](https://workos.com/blog/arcade-vs-workos-agent-authentication-enterprise-auth)).

### Tailscale Aperture

An LLM and API reverse-proxy gateway that "injects provider API keys from its server configuration on behalf of the user". Identity comes from tailnet device and user auth. It logs full request and response bodies, including tool use, with retention and zero-retention options and SIEM export, and proxies remote MCP servers and HTTP APIs ([Tailscale docs](https://tailscale.com/docs/aperture/what-is-aperture)).

> [!question] Unverified
> Keycard, Lasso and Pomerium pricing; Arcade's 2026 architecture (known only from the docs landing page); the deployment models and Okta/Entra integration depth of Keycard, Aembit and Arcade; and whether Claude Code's and Cursor's hook APIs expose enough task context to bind credentials to a task, as Keycard claims, were all not verified ([[Open Questions and Unverified Claims]]).

## Strengths

- Real user × agent binding, which the audit trail needs ([[Audit Recorder and Event Schema]]).
- Keycard: task-scoped JIT credentials, in-memory only, delegation chaining ([[Revocable Sub-Agent Delegation]]).
- Aembit: MCP authorization done per spec, with a public per-agent price.
- Arcade and Aperture: tokens never reach the model; Aperture's full-body logging with SIEM export.

## Weaknesses (versus this thesis)

- **No OS sandbox and no topology-forced egress.** A hook-based or proxy-based identity layer is only as strong as the agent's cooperation ([[Topology-Forced Egress]]).
- **Hook dependency.** Keycard relies on vendor hook APIs; whether vendors keep those stable is unknown ([[Risk Register]], row "Vendor hook and API instability").
- **Closed.**
- **No developer-protocol semantics** (git refs, GitHub verbs) and no learning loop documented.
- Aperture logs **full bodies**, which is the opposite of the broker's redacted-metadata audit design.

## What we reuse or interoperate with

- **Adopt:** Keycard's user × agent × device × task identity tuple for the `Task` principal, in-memory-only credentials reaped at session end, and delegation chaining as the model for sub-agent attenuation.
- **Plug into, don't compete with, the IdP:** use Okta ID-JAG / Cross App Access or Entra Agent ID on-behalf-of to get the user-delegated token at task start, then narrow it ([[Okta Cross App Access]], [[Entra Agent ID]]). Delegation chains "inherit the broadest permission unless actively narrowed" ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)); narrowing is the broker's job ([[Just-in-Time Credential Minting]]).
- **MCP:** act as a spec-compliant MCP client toward remote servers, honouring the passthrough ban ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization); [[MCP Authorization Spec]]).
- **Possible interop:** Aembit or Keycard as an upstream issuer behind a broker `CredentialIssuer` ([[Credential Injector and Issuers]]); not designed in the record.

## How we differentiate

Identity **plus** the sandbox: the broker wraps the process, so the agent cannot route around it, and it adds protocol semantics, a verified learning loop and one audit schema. It works by wrapping the process rather than depending on hooks ([[Gap Analysis]]).

## How it connects

- competes-with:: [[Product Thesis]] (Keycard most directly)
- example-of:: [[Just-in-Time Credential Minting]] (Keycard)
- depends-on:: [[Okta Cross App Access]] (Aembit and Keycard federate to IdPs)
- depends-on:: [[MCP Authorization Spec]] (Aembit's MCP Authorization Server)
- contrasts-with:: [[Topology-Forced Egress]]
- motivated-by:: none; Keycard's delegation chaining informs [[Revocable Sub-Agent Delegation]]
- contrasts-with:: [[Audit Recorder and Event Schema]] (Aperture logs full bodies)
- Siblings: [[AWS AgentCore]] (Identity's token vault), [[MCP Gateways]]
- Analysed in: [[Gap Analysis]], [[Risk Register]]

## Implications for the build

- The `Task` principal must carry user, agent and (later) device, so audit rows match what identity-first buyers already see.
- M3 acceptance requires audit rows with IdP subject and groups; match Aembit's audit example in readability.
- Never forward a user's IdP token as-is to an upstream or MCP server (CLAUDE.md non-negotiable).

## Open questions

- Would Keycard partner (broker as sandbox, Keycard as issuer) or compete? The report treats it as the closest competitor.
- Is $20 per agent per month the right anchor when agent counts are ephemeral? The landscape note proposes per-developer-seat pricing instead.

## Sources

- [Keycard: coding agents](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/); [GlobeNewswire](https://www.globenewswire.com/news-release/2026/05/14/3295239/0/en/keycard-launches-identity-and-access-for-multi-agent-apps.html); [Help Net Security](https://www.helpnetsecurity.com/2026/05/15/keycard-for-multi-agent-apps/); [SiliconANGLE](https://siliconangle.com/2025/10/21/ai-agent-security-startup-keycard-reels-38m/)
- [Aembit GA](https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/); [Aembit docs](https://docs.aembit.io/get-started/use-cases/ai-agents/)
- [Arcade docs](https://docs.arcade.dev/en/home/auth/auth-tool-calling); [WorkOS: Arcade comparison](https://workos.com/blog/arcade-vs-workos-agent-authentication-enterprise-auth)
- [Tailscale Aperture](https://tailscale.com/docs/aperture/what-is-aperture)
- [Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)
- [MCP spec: Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)
