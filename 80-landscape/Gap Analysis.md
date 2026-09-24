---
title: "Gap Analysis"
aliases: ["The Gap to Own", "Buyer Demand", "Commoditised Injection"]
type: concept
section: landscape
tags: [sandbox/landscape, concept, topic/market, topic/credentials, topic/policy, topic/audit, topic/learning, topic/mcp, topic/git, evidence/secondary, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Proxy-side secret injection is commoditised across eight products; six capabilities remain unowned (cross-agent policy that compiles to native configs, minting, developer-protocol semantics, verified learning, one audit schema, container-free MCP containment); buyer evidence, threats and the licensing opening."
related: ["[[Product Thesis]]", "[[ADR-001 Value Lives in the Broker]]", "[[Native Config Exporters]]", "[[Just-in-Time Credential Minting]]", "[[Git Smart-HTTP Adapter]]", "[[Policy Learning Loop]]", "[[Audit Recorder and Event Schema]]", "[[MCP Guard]]", "[[NVIDIA OpenShell]]", "[[Claude Code and sandbox-runtime]]", "[[Risk Register]]", "[[Agent Identity Brokers]]", "[[OpenAI Codex CLI]]", "[[Cursor and Gemini CLI]]", "[[Docker Sandboxes]]", "[[Vercel Sandbox]]", "[[Cloud Sandbox Runtimes]]", "[[Local Credential Proxies]]", "[[AWS AgentCore]]", "[[MCP Gateways]]", "[[GitHub API Adapter]]", "[[SymCC CI Gates]]", "[[Threat Model Non-Goals]]", "[[ADR-014 Apache-2.0 Endpoint with Commercial ee]]", "[[ADR-012 MCP Servers as Pinned Sandboxed Principals]]", "[[Sentinel Swap Pattern]]", "[[Open Questions and Unverified Claims]]", "[[MOC Landscape]]"]
sources: ["https://code.claude.com/docs/en/sandboxing", "https://docs.docker.com/ai/sandboxes/security/defaults/", "https://vercel.com/docs/sandbox/concepts/firewall", "https://blog.cloudflare.com/sandbox-auth/", "https://docs.e2b.dev/network/internet-access.md", "https://docs.runloop.ai/docs/devboxes/agent-gateways", "https://github.com/NVIDIA/openshell", "https://github.com/Infisical/agent-vault", "https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/", "https://cursor.com/changelog/2-5", "https://geminicli.com/docs/cli/sandbox/", "https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/", "https://www.anthropic.com/engineering/claude-code-sandboxing", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/", "https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html", "https://docs.stacklok.com/toolhive/guides-cli/network-isolation", "https://github.com/docker/mcp-gateway", "https://microsoft.github.io/wassette/latest/concepts.html", "https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/", "https://zenity.io/blog/coding-agent-risk-for-cisos-blast-radius-governance", "https://startwithidentity.com/blog/agent-identity-gets-a-protocol/", "https://siliconangle.com/2026/06/15/sailpoint-acquires-ai-agent-security-startup-entro-reported-200m/", "https://techcrunch.com/2026/07/30/okta-buys-ai-security-startup-permiso-source-says-for-about-200m/", "https://docs.docker.com/ai/sandboxes/", "https://www.darkreading.com/cybersecurity-operations/ai-security-spending-jumps-fear-outpaces-proof-value", "https://www.bcg.com/publications/2026/cybersecurity-spending-ai-threat-trends", "https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/", "https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk", "https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/", "https://modelcontextprotocol.io/specification/latest/basic/authorization"]
---

# Gap Analysis

> Proxy-side secret injection is commoditised across eight products; six capabilities remain unowned (cross-agent policy that compiles to native configs, minting, developer-protocol semantics, verified learning, one audit schema, container-free MCP containment); buyer evidence, threats and the licensing opening.

## Summary

The thesis's starting pattern (a host-side proxy with a per-sandbox CA that injects secrets outside the sandbox) is standard by September 2026, so a new entrant cannot win on it. What remains unowned is **neutral authority management**: one policy and audit stream across agents, per-task minting, developer-protocol rules and verified least-privilege learning. Hence [[ADR-001 Value Lives in the Broker]] and the [[Product Thesis]].

## What is commoditised

Eight products put a host-side proxy with a per-sandbox CA in front of the agent and inject secrets outside the sandbox (report, "The gap to own"):

| Product | How injection works |
|---|---|
| Claude Code (v2.1.199+) | `mask` sentinels, experimental `tlsTerminate`, SigV4 re-signing ([Claude Code docs](https://code.claude.com/docs/en/sandboxing); [[Claude Code and sandbox-runtime]]) |
| Docker Sandboxes | Host proxy injects headers ([Docker docs](https://docs.docker.com/ai/sandboxes/security/defaults/)) |
| Vercel Sandbox | Per-sandbox CA, `transform` injection ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)) |
| Cloudflare Sandbox | Outbound Workers with an ephemeral per-sandbox CA ([Cloudflare](https://blog.cloudflare.com/sandbox-auth/)) |
| E2B | Egress `transform.headers` from secrets or workload identity ([E2B docs](https://docs.e2b.dev/network/internet-access.md)) |
| Runloop | Devbox-bound opaque tokens ([Runloop docs](https://docs.runloop.ai/docs/devboxes/agent-gateways)) |
| NVIDIA OpenShell | L7 proxy binds credentials by method and path ([GitHub](https://github.com/NVIDIA/openshell); [[NVIDIA OpenShell]]) |
| Infisical Agent Vault | Placeholders swapped per host and path ([GitHub](https://github.com/Infisical/agent-vault)) |

Each is bound to one vendor's agent or cloud, has its own config format and mostly swaps **static** secrets (research note 05, section 1). The broker keeps this [[Sentinel Swap Pattern]] only as its fallback tier.

## The six unowned capabilities

**Proposal** (the gap list is the report's synthesis over the reviewed set; absence claims were not exhaustively verified). "Closest" follows the record where it names a leader (Keycard for gap 2, Anthropic's git proxy for gap 3) and is this note's inference elsewhere.

### 1. Cross-agent policy-as-code that compiles to native configs

- **Evidence:** incompatible per-vendor policy surfaces: Claude Code managed settings, Codex `requirements.toml` via MDM ([Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/)), Cursor's admin dashboard allowlists ([Cursor 2.5](https://cursor.com/changelog/2-5)) and Docker org policy. Gemini CLI documents no credential brokering ([Gemini CLI docs](https://geminicli.com/docs/cli/sandbox/)). See [[OpenAI Codex CLI]] and [[Cursor and Gemini CLI]].
- **Closest (inference):** OpenShell, which supports many agents with one YAML policy, but only inside its own container sandboxes.
- **How we fill it:** one Cedar source, enforced by the broker **and** exported to Claude Code, Codex, Cursor and OpenShell formats, so vendor controls become defence in depth ([[Native Config Exporters]]).

### 2. Minted, resource-scoped, short-lived credentials on laptops without Docker

- **Evidence:** OpenShell, Agent Vault and Claude Code inject static secrets. Only Keycard, Aembit, AgentCore Identity and E2B's workload-identity transforms point toward minting, and none of them also provides the local OS sandbox (research note 05, section 1 inferences).
- **Closest:** Keycard issues credentials "scoped to the task, agent, user, and environment", held in memory and reaped at session end ([Keycard](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/)). It is closed and has no OS sandbox ([[Agent Identity Brokers]]).
- **How we fill it:** per-task GitHub App tokens, STS sessions with compiled session policies, OAuth token exchange ([[Just-in-Time Credential Minting]]).

### 3. Semantic egress for developer protocols

- **Evidence:** scoping stops at method (Codex), method and path (Vercel, OpenShell), per-binary (OpenShell) or host-only injection (Claude Code). **No neutral product reviewed parses git smart-HTTP per repository or branch** or understands GitHub API verbs ("may open a PR but not merge"); not exhaustively verified.
- **Closest:** Anthropic's own web sandbox validates pushes against "the configured branch" with a custom git proxy ([Anthropic](https://www.anthropic.com/engineering/claude-code-sandboxing)), but for its own agent only.
- **How we fill it:** pkt-line-level ref rules in the [[Git Smart-HTTP Adapter]], verb mapping in the [[GitHub API Adapter]], and read-only registries.

### 4. Policy learning with a verified review workflow

- **Evidence:** AgentCore turns natural language into Cedar checked by analysis, but it is cloud-bound ([AWS](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/); [[AWS AgentCore]]). OpenShell has `enforcement: audit` but no miner ([OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)). No product in the record ships an agent egress "record → enforce" miner.
- **Closest (inference):** AgentCore Policy for authoring; OpenShell audit mode for recording.
- **How we fill it:** record, mine, SymCC gates, human PR, shadow, enforce ([[Policy Learning Loop]]; [[SymCC CI Gates]]).

### 5. One audit schema across agents, attributed to IdP identities

- **Evidence:** buyers ask for SIEM capture of "tool call sequences, external API requests, and data access patterns" ([CSA Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/)). Whether Claude Code or Codex export audit to a SIEM natively is **unverified**; the sources reviewed do not mention it.
- **Closest (inference):** Aembit's audit ties user, agent and policy, but only for its own gateway traffic ([[Agent Identity Brokers]]).
- **How we fill it:** hash-chained events with IdP subject, agent, task and session, exported as OTel and OCSF ([[Audit Recorder and Event Schema]]).

### 6. Local MCP server containment without a container runtime

- **Evidence:** ToolHive and Docker MCP Gateway containerise servers but need a container runtime ([Stacklok](https://docs.stacklok.com/toolhive/guides-cli/network-isolation); [docker/mcp-gateway](https://github.com/docker/mcp-gateway)). Wassette needs tools rebuilt as Wasm components ([Wassette](https://microsoft.github.io/wassette/latest/concepts.html)). The MCP spec tells STDIO servers to "retrieve credentials from the environment" ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)).
- **Closest (inference):** Docker MCP Gateway ([[MCP Gateways]]).
- **How we fill it:** each server runs as a pinned, separately sandboxed principal with sentinel environment variables ([[MCP Guard]]; [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]).

Research note 03 frames the same gap in five parts (portability, IdP federation, L7 semantics, unified audit, learning) and finds Keycard and Aembit closest on identity but "credential or identity-centric rather than egress-proxy-centric".

## Buyer evidence

- **CSA (compiled surveys, 3 April 2026):** 92% "lack full visibility into their AI identities"; 95% "doubt they could detect or contain a compromised agent"; 86% "do not enforce access policies for AI identities"; only 38% monitor AI traffic end-to-end. It recommends "time-bound, just-in-time credentials scoped to the specific resources their task requires" ([CSA Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/)).
- **Zenity (vendor):** 47% had an agent security incident; 15% are highly confident in response; 31% documented governance ([Zenity](https://zenity.io/blog/coding-agent-risk-for-cisos-blast-radius-governance)).
- **Identity gap:** "Delegation chains inherit the broadest permission unless actively narrowed"; only 34% apply human-grade controls to agents ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)).
- **Exits:** SailPoint bought Entro for a reported ~$200M ([SiliconANGLE](https://siliconangle.com/2026/06/15/sailpoint-acquires-ai-agent-security-startup-entro-reported-200m/)), and Okta agreed to buy Permiso for ~$200M ([TechCrunch](https://techcrunch.com/2026/07/30/okta-buys-ai-security-startup-permiso-source-says-for-about-200m/)).
- **Paid control planes:** Docker sells a subscription to "centrally manage sandbox network, filesystem, and MCP policies" ([Docker docs](https://docs.docker.com/ai/sandboxes/)).
- **Brakes:** 24% of CISOs have a separate AI-security budget line ([Dark Reading](https://www.darkreading.com/cybersecurity-operations/ai-security-spending-jumps-fear-outpaces-proof-value)); 23% of organisations monitor or log their agents ([BCG](https://www.bcg.com/publications/2026/cybersecurity-spending-ai-threat-trends)).

> [!question] Unverified
> No primary buyer survey is specific to coding agents on laptops; the figures above cover AI-agent governance generally. Evidence that buyers will pay separately rather than accept bundled vendor controls is indirect (M&A comparables, Aembit's $20/agent price point). See [[Open Questions and Unverified Claims]].

The ICP splits (research note 05, section 2): devex teams want zero-friction `broker run` and CI actions; CISOs want inventory, central policy, SIEM export and SOC 2 evidence.

## What is not a gap

A proxy "prevents theft but not misuse" of a legitimately held token ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)); the broker does not claim to close that ([[Threat Model Non-Goals]]).

## Threats and the licensing opening

- **Vendor bundling:** Claude Code already ships `mask` with SigV4 re-signing and forbids repository settings from enabling injection ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)).
- **OpenShell**, the closest open-source analogue. **Proposal:** differentiate on container-free laptop mode, minting, identity and learning, and interoperate (policy import and export, or minting as an OpenShell provider). Both threats are [[Risk Register]] rows.
- **Licensing opening.** Daytona went closed-source in June 2026 ([bex.co](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk)), and Docker sbx's licence is "not final" ([INNOQ](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)). That favours an auditable Apache-2.0 data plane ([[ADR-014 Apache-2.0 Endpoint with Commercial ee]]).

## How it connects

- motivated-by:: [[Claude Code and sandbox-runtime]] (bundling evidence)
- motivated-by:: [[NVIDIA OpenShell]] (closest open analogue)
- motivated-by:: [[Agent Identity Brokers]] (minting without a sandbox)
- motivated-by:: [[MCP Gateways]] (containment that needs containers or Wasm)
- depends-on:: [[Native Config Exporters]] (gap 1)
- depends-on:: [[Just-in-Time Credential Minting]] (gap 2)
- depends-on:: [[Git Smart-HTTP Adapter]] (gap 3)
- depends-on:: [[Policy Learning Loop]] (gap 4)
- depends-on:: [[Audit Recorder and Event Schema]] (gap 5)
- depends-on:: [[MCP Guard]] (gap 6)
- part-of:: [[Product Thesis]]
- decided-by:: [[ADR-001 Value Lives in the Broker]]
- decided-by:: [[ADR-014 Apache-2.0 Endpoint with Commercial ee]]
- mitigates:: [[Risk Register]] (rows "Vendors bundle the feature" and "OpenShell becomes the default open-source data plane")
- part-of:: [[MOC Landscape]]

## Implications for the build

- Prioritise the six over parity: M1's value is minting plus git semantics, not the sentinel swap.
- Ship the Claude Code and Codex exporters in M2; they turn bundling into distribution.
- Keep the credential-issuer interface callable by a third-party data plane (the OpenShell-provider path).
- Re-check every "nobody does X" claim before public use, especially the git smart-HTTP and miner absences.

## Open questions

- Do Claude Code or Codex export audit to a SIEM natively? Unverified.
- Would buyers pay for a neutral layer when bundled controls are free? Only indirect evidence exists.
- Do Claude Code and Cursor hooks give enough task context to bind credentials to a task, as Keycard claims? Not reviewed.
- Is OpenShell moving toward minting or learning? Track its releases.

## Sources

- [Claude Code docs: sandboxing](https://code.claude.com/docs/en/sandboxing)
- [Docker docs: Sandboxes default security posture](https://docs.docker.com/ai/sandboxes/security/defaults/)
- [Docker docs: Sandboxes](https://docs.docker.com/ai/sandboxes/)
- [Vercel Sandbox firewall docs](https://vercel.com/docs/sandbox/concepts/firewall)
- [Cloudflare: sandbox auth](https://blog.cloudflare.com/sandbox-auth/)
- [E2B docs: internet access](https://docs.e2b.dev/network/internet-access.md)
- [Runloop docs: agent gateways](https://docs.runloop.ai/docs/devboxes/agent-gateways)
- [NVIDIA/OpenShell](https://github.com/NVIDIA/openshell)
- [NVIDIA OpenShell docs: first network policy](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)
- [Infisical/agent-vault](https://github.com/Infisical/agent-vault)
- [Codex KB: requirements.toml](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/)
- [Cursor 2.5 changelog](https://cursor.com/changelog/2-5)
- [Gemini CLI docs: sandbox](https://geminicli.com/docs/cli/sandbox/)
- [Keycard for coding agents](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/)
- [Anthropic: Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [AWS Security Blog: AgentCore Policy](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)
- [Stacklok: ToolHive network isolation](https://docs.stacklok.com/toolhive/guides-cli/network-isolation)
- [docker/mcp-gateway](https://github.com/docker/mcp-gateway)
- [Wassette concepts](https://microsoft.github.io/wassette/latest/concepts.html)
- [MCP specification: Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- [CSA Labs: AI agent governance gap](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/)
- [Zenity: coding agent risk for CISOs](https://zenity.io/blog/coding-agent-risk-for-cisos-blast-radius-governance)
- [Start With Identity: agent identity gets a protocol](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)
- [SiliconANGLE: SailPoint acquires Entro](https://siliconangle.com/2026/06/15/sailpoint-acquires-ai-agent-security-startup-entro-reported-200m/)
- [TechCrunch: Okta buys Permiso](https://techcrunch.com/2026/07/30/okta-buys-ai-security-startup-permiso-source-says-for-about-200m/)
- [Dark Reading: AI security spending](https://www.darkreading.com/cybersecurity-operations/ai-security-spending-jumps-fear-outpaces-proof-value)
- [BCG: cybersecurity spending 2026](https://www.bcg.com/publications/2026/cybersecurity-spending-ai-threat-trends)
- [Zujkowski: the secret-proxying gap](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)
- [bex.co: Daytona goes closed source](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk)
- [INNOQ: trust but sandbox](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)
- Report: "The gap to own" and the teardown table; research notes 03 Q3 and 05 sections 1–2; scoreboard sandboxing section (Demand paragraph and small-team paragraph).
