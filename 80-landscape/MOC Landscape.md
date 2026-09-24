---
title: "MOC Landscape"
aliases: []
type: moc
section: landscape
tags: [sandbox/landscape, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "The 2026 field: credential injection is commoditised; neutral minting, protocol semantics, learning and one audit stream are not."
related: ["[[Claude Code and sandbox-runtime]]", "[[OpenAI Codex CLI]]", "[[Cursor and Gemini CLI]]", "[[Docker Sandboxes]]", "[[NVIDIA OpenShell]]", "[[Local Credential Proxies]]", "[[Vercel Sandbox]]", "[[Cloud Sandbox Runtimes]]", "[[AWS AgentCore]]", "[[Agent Identity Brokers]]", "[[MCP Gateways]]", "[[Gap Analysis]]", "[[Product Thesis]]", "[[Risk Register]]", "[[MOC Decisions]]"]
sources: []
---

# MOC Landscape

> The 2026 field: credential injection is commoditised; neutral minting, protocol semantics, learning and one audit stream are not.

By September 2026 the thesis's starting pattern (a host-side proxy with a per-sandbox CA that injects secrets so they never enter the sandbox) is standard in at least eight products. A new entrant cannot win on that. What nobody offers neutrally is one policy and audit stream across agents, credential *minting* bound to user, agent, repo and task, semantic rules for developer protocols, and a verified record-then-restrict loop. [[Gap Analysis]] states the six unowned capabilities and the two sharpest threats (vendor bundling and OpenShell).

## Teardown at a glance

| Product | Isolation | Secret handling | Gap versus this thesis |
|---|---|---|---|
| [[Claude Code and sandbox-runtime]] | Seatbelt; bwrap with netns removed | per-session sentinel `mask`, SigV4 re-sign | single vendor; static swap, no minting; warns and runs unsandboxed by default |
| [[OpenAI Codex CLI]] | Seatbelt; bwrap | managed proxy, method filter | no credential brokering documented |
| [[Cursor and Gemini CLI]] | vendor sandboxes | none documented | no brokering |
| [[Docker Sandboxes]] | microVM per agent | host proxy injects headers | closed, licence not final; Linux GA was "what's next" |
| [[NVIDIA OpenShell]] | containers + seccomp + Landlock | env-var providers; L7 binding by method, path, binary | container-based; no minting, IdP binding or miner |
| [[Local Credential Proxies]] | none / container | placeholders (Agent Vault); keys forwarded into agent (Leash) | relies on `HTTPS_PROXY` or keeps secrets inside |
| [[Vercel Sandbox]] | Firecracker, host firewall | per-sandbox CA, `transform` injection | cloud-only; matchers never block |
| [[Cloud Sandbox Runtimes]] | Firecracker, containers, gVisor | varies (Cloudflare handlers, E2B transforms, LangSmith callback, Runloop devbox-bound) | cloud- or vendor-bound |
| [[AWS AgentCore]] | microVM per session | token vault per user-agent pair; Cedar at gateway | AWS-bound; no provenance context |
| [[Agent Identity Brokers]] | no OS sandbox | JIT credentials, blended identity | identity without an egress sandbox |
| [[MCP Gateways]] | containers or Wasm | env-var proxies, Desktop secrets, deny-by-default policy | needs a container runtime or Wasm rebuild |

## Synthesis

- [[Gap Analysis]] — Proxy-side secret injection is commoditised across eight products; six capabilities remain unowned (cross-agent policy that compiles to native configs, minting, developer-protocol semantics, verified learning, one audit schema, container-free MCP containment); buyer evidence, threats and the licensing opening.

## Agent-vendor sandboxes

- [[Claude Code and sandbox-runtime]] — Anthropic's srt (Apache-2.0 beta: Seatbelt; bwrap with netns removed and socat bridges) and Claude Code's sandbox with mask sentinels, injectHosts, experimental tlsTerminate and SigV4 re-signing; single-vendor, static-secret swap, warns and runs unsandboxed by default.
- [[OpenAI Codex CLI]] — Codex's Seatbelt and bubblewrap sandbox (read-only, workspace-write, danger-full-access) with a managed proxy offering domain allowlists and HTTP-method filtering, requirements.toml via MDM, and no documented credential brokering.
- [[Cursor and Gemini CLI]] — Cursor 2.5's sandbox with admin network allowlists and Gemini CLI's Seatbelt, Docker/Podman and gVisor sandbox options (off by default in 2025); neither documents credential brokering.

## Neutral-ish local wrappers

- [[Docker Sandboxes]] — Docker sbx: a microVM per agent with a private Docker engine, host proxy that injects credentials so the agent never reads them, Open/Balanced/Locked Down tiers, clone mode, free but closed with a licence 'not final'.
- [[NVIDIA OpenShell]] — The closest open-source analogue: Apache-2.0, Rust, alpha, ~8.7k stars; container sandboxes with seccomp and Landlock, an L7 proxy binding credentials by method, path and per-binary, enforce/audit modes; no minting, IdP binding or learning miner.
- [[Local Credential Proxies]] — Infisical Agent Vault (MITM via HTTPS_PROXY, placeholders per host and path, unmatched_host_policy=deny, MIT plus ee/), StrongDM Leash (container plus eBPF plus Cedar, but forwards API keys into the agent) and agentjail: lessons on proxy-env reliance and secrets inside the boundary.

## Cloud runtimes

- [[Vercel Sandbox]] — Firecracker sandbox with a host firewall that transparently redirects TCP and DNS, SNI-matches without termination, terminates only transform/forwardURL domains with a per-sandbox CA; matchers never block, which this broker rejects.
- [[Cloud Sandbox Runtimes]] — Cloud runtimes and their egress/credential handling: Cloudflare Sandbox Outbound Workers, E2B (header transforms, 10-domain limit, blocked connections may look successful), LangSmith Auth Proxy (fail-closed callback credentials), Runloop (devbox-bound tokens), Daytona (went closed-source Jun 2026), Modal, Fly.io Sprites and Kubernetes Agent Sandbox.
- [[AWS AgentCore]] — AgentCore Runtime (microVM per session), Identity (workload access token binding agent and user, token vault per user-agent pair) and Policy (Cedar at the Gateway, default-deny, NL-to-Cedar verified by analysis, partial evaluation); AWS-bound and without provenance context.

## Identity and MCP layers

- [[Agent Identity Brokers]] — Identity without an egress sandbox: Keycard (task-scoped JIT credentials via agent hooks, delegation chaining, closest to this thesis but closed), Aembit (blended identity, MCP Identity Gateway VM, $20/agent/month), Arcade (per-user tool OAuth) and Tailscale Aperture.
- [[MCP Gateways]] — MCP containment options that need a container runtime or a Wasm rebuild: ToolHive (containers, Squid via env vars, raw TCP bypasses it), Docker MCP Gateway, Microsoft Wassette (Wasm components, deny-by-default policy.yaml), plus Pomerium, Lasso, Snyk Agent Scan and Runlayer.

## How this section connects

- The thesis this landscape supports is [[Product Thesis]] and [[ADR-001 Value Lives in the Broker]]; licensing choices follow from the Daytona and Docker events ([[ADR-014 Apache-2.0 Endpoint with Commercial ee]]).
- Competitive risks and their mitigations are in [[Risk Register]].
- Anti-patterns adopted as decisions: [[ADR-006 Deny Unmatched L7 Requests]] (against Vercel's semantics) and [[ADR-003 Topology-Enforced Egress]] (against env-var proxies).
- Interoperability rather than competition: [[Native Config Exporters]].
