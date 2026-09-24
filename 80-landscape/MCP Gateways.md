---
title: "MCP Gateways"
aliases: ["ToolHive", "Docker MCP Gateway", "Wassette", "Snyk Agent Scan"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/mcp, topic/egress, topic/credentials, topic/supply-chain, control/pin, boundary/tb6, evidence/unverified, evidence/secondary]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "MCP containment options that need a container runtime or a Wasm rebuild: ToolHive (containers, Squid via env vars, raw TCP bypasses it), Docker MCP Gateway, Microsoft Wassette (Wasm components, deny-by-default policy.yaml), plus Pomerium, Lasso, Snyk Agent Scan and Runlayer."
related: ["[[MCP Guard]]", "[[Wasmtime and WASI]]", "[[Topology-Forced Egress]]", "[[ADR-012 MCP Servers as Pinned Sandboxed Principals]]", "[[Gap Analysis]]", "[[Docker Sandboxes]]", "[[postmark-mcp Rug Pull]]", "[[MCP Authorization Spec]]", "[[Agent Identity Brokers]]", "[[AWS AgentCore]]", "[[Local Credential Proxies]]", "[[Cursor CurXecute and MCPoison]]", "[[ADR-003 Topology-Enforced Egress]]", "[[ADR-015 Rust for the Endpoint and Custom Proxy]]", "[[Container Runtimes and Escape History]]", "[[I1 No Secrets in the Sandbox]]", "[[Product Thesis]]", "[[Measurement Gaps]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://docs.stacklok.com/toolhive/guides-cli/network-isolation", "https://radar.offseq.com/threat/cve-2026-58197-cwe-284-improper-access-control-in-stacklok-toolhive-150e81dc1ad9d600", "https://github.com/docker/mcp-gateway", "https://pkg.go.dev/github.com/docker/mcp-gateway/pkg/interceptors", "https://www.docker.com/products/mcp-enterprise-gateway/", "https://docs.docker.com/ai/sandboxes/architecture/", "https://opensource.microsoft.com/blog/2025/08/06/introducing-wassette-webassembly-based-tools-for-ai-agents/", "https://microsoft.github.io/wassette/latest/concepts.html", "https://github.com/microsoft/wassette", "https://thenewstack.io/wassette-microsofts-rust-powered-bridge-between-wasm-and-mcp/", "https://bytecodealliance.org/articles/wasmtime-security-advisories", "https://www.pomerium.com/blog/top-5-agentic-gateways-for-securing-mcp-tool-calls-in-2026", "https://github.com/lasso-security/mcp-gateway", "https://github.com/snyk/agent-scan", "https://labs.snyk.io/resources/snyk-labs-invariant-labs/", "https://appsecsanta.com/runlayer", "https://docs.aembit.io/get-started/use-cases/ai-agents/", "https://tailscale.com/docs/aperture/what-is-aperture", "https://github.com/strongdm/leash", "https://github.com/e2b-dev/awesome-mcp-gateways", "https://modelcontextprotocol.io/specification/latest/basic/authorization", "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks"]
---

# MCP Gateways

> MCP containment options that need a container runtime or a Wasm rebuild: ToolHive (containers, Squid via env vars, raw TCP bypasses it), Docker MCP Gateway, Microsoft Wassette (Wasm components, deny-by-default policy.yaml), plus Pomerium, Lasso, Snyk Agent Scan and Runlayer.

## What they are

Local MCP servers are third-party code with the developer's credentials. The spec itself tells STDIO servers to "retrieve credentials from the environment" ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)), and tool descriptions can change after approval ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks); [[postmark-mcp Rug Pull]]). Three families of products respond:

- **containment gateways** that isolate the server: ToolHive, Docker MCP Gateway and Wassette;
- **policy and identity gateways** that sit in the MCP request path: Pomerium, Lasso, Runlayer, Aembit, Tailscale Aperture and AgentCore Gateway;
- **scanners** that inspect servers before use: Snyk Agent Scan.

A curated list tracks many more ([awesome-mcp-gateways](https://github.com/e2b-dev/awesome-mcp-gateways)).

| Product | Licence, language, adoption | Core idea |
|---|---|---|
| ToolHive (Stacklok) | Open source (exact licence not in the record) | Servers in containers behind a Squid egress proxy |
| Docker MCP Gateway | MIT, Go | One container per server, Docker Desktop secrets |
| Microsoft Wassette | MIT, "Rust-powered", v0.4.0 | MCP server that runs Wasm components on Wasmtime |
| Pomerium | Open source, self-hosted | Identity-aware proxy with tool-level MCP authorization |
| Lasso MCP Gateway | MIT, Python, ~385 stars | Plugin guardrails plus a reputation scanner |
| Snyk Agent Scan | Apache-2.0 | Scanner for tool poisoning and toxic flows |
| Runlayer | Not in the record | "AI Agent and MCP Control Plane" |

## Architecture teardown

### ToolHive

- **Architecture:** MCP servers run in containers with separate internal and external networks, a **Squid** egress proxy (Envoy optional) and a DNS container ([Stacklok](https://docs.stacklok.com/toolhive/guides-cli/network-isolation)).
- **Policy:** JSON permission profiles with `allow_host` and `allow_port`.
- **Credentials:** not detailed in the record.
- **Weakness:** it relies on `HTTP(S)_PROXY`. It "does not transparently redirect all traffic with iptables or nftables rules", so raw TCP bypasses it and only HTTP and HTTPS are covered ([Stacklok](https://docs.stacklok.com/toolhive/guides-cli/network-isolation)). This is the report's cautionary example for [[Topology-Forced Egress]].
- A CVE titled "CVE-2026-58197 … Improper Access Control in stacklok toolhive" is listed, but its details were not reviewed ([OffSeq](https://radar.offseq.com/threat/cve-2026-58197-cwe-284-improper-access-control-in-stacklok-toolhive-150e81dc1ad9d600)).

### Docker MCP Gateway

- **Architecture:** each MCP server runs in its own container behind a gateway, with OCI-based catalogs and profiles ([docker/mcp-gateway](https://github.com/docker/mcp-gateway)). There is an interceptors package, but its semantics were not confirmed ([pkg.go.dev](https://pkg.go.dev/github.com/docker/mcp-gateway/pkg/interceptors)).
- **Credentials:** Docker Desktop secrets and built-in OAuth flows.
- **Requirement:** Docker Desktop 4.59+ with MCP Toolkit, or bypass flags outside Desktop.
- **Related products:** Docker also markets an "MCP Enterprise Gateway", which was not fetched ([Docker](https://www.docker.com/products/mcp-enterprise-gateway/)). In Docker Sandboxes, an MCP gateway sits on the host boundary: "Local stdio servers don't run inside the sandbox VM" ([Docker architecture](https://docs.docker.com/ai/sandboxes/architecture/); [[Docker Sandboxes]]).

### Microsoft Wassette

- **Architecture:** introduced 6 August 2025 as an MCP server that runs WebAssembly Components on Wasmtime with **deny-by-default capabilities**. Components are distributed through OCI ([Microsoft OSS blog](https://opensource.microsoft.com/blog/2025/08/06/introducing-wassette-webassembly-based-tools-for-ai-agents/)).
- **Policy:** `policy.yaml` grants storage URIs, network hosts and environment variables ([Wassette concepts](https://microsoft.github.io/wassette/latest/concepts.html)).
- **Status:** MIT, v0.4.0 (4 February 2026), marked "Early Development… not production ready" ([microsoft/wassette](https://github.com/microsoft/wassette)); described as "Rust-powered" ([The New Stack](https://thenewstack.io/wassette-microsofts-rust-powered-bridge-between-wasm-and-mcp/)).
- **Weakness:** tools must be rebuilt as Wasm components. Wasmtime had 12 advisories in April 2026, two of them critical sandbox escapes ([Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-security-advisories); [[Wasmtime and WASI]]).

### Policy, identity and scanning layers

- **Pomerium**, per its own comparison (a self-interested source): an open-source, self-hosted, identity-aware proxy with tool-level MCP authorization and upstream OAuth 2.1, issuing short-lived signed assertions. The same piece claims Cloudflare AI Gateway "cannot restrict access to specific tools or methods" and that agentgateway lacks OAuth ([Pomerium](https://www.pomerium.com/blog/top-5-agentic-gateways-for-securing-mcp-tool-calls-in-2026)).
- **Lasso MCP Gateway:** plugin guardrails (basic secret masking, Presidio PII, Lasso cloud), a reputation scanner and logging to SQLite or DuckDB ([GitHub](https://github.com/lasso-security/mcp-gateway)).
- **Snyk Agent Scan:** the successor line to Invariant's mcp-scan after Snyk acquired Invariant Labs. It scans MCP servers and skills for tool poisoning and toxic flows across Claude, Cursor, Gemini CLI and others. It **sends component data to Snyk's API** with secrets redacted, and the docs reviewed show no proxy mode ([snyk/agent-scan](https://github.com/snyk/agent-scan); [Snyk Labs](https://labs.snyk.io/resources/snyk-labs-invariant-labs/)).
- **Runlayer** positions itself as an "AI Agent and MCP Control Plane"; its internals were not fetched ([AppSecSanta](https://appsecsanta.com/runlayer)).
- **Identity gateways** ([[Agent Identity Brokers]]):
  - Aembit acts as an MCP Authorization Server issuing short-lived tokens after user authentication ([Aembit docs](https://docs.aembit.io/get-started/use-cases/ai-agents/)).
  - Tailscale Aperture's connectors "proxy connections to remote MCP servers and HTTP APIs" with centralised auth injection ([Tailscale](https://tailscale.com/docs/aperture/what-is-aperture)).
  - AgentCore Gateway evaluates Cedar per tool call ([[AWS AgentCore]]).
  - StrongDM Leash's MCP observer "inspects, records, and enforces MCP tool calls" inside a container setup that forwards API keys into the agent ([GitHub](https://github.com/strongdm/leash); [[Local Credential Proxies]]).

## Comparison

| Dimension | ToolHive | Docker MCP Gateway | Wassette | This broker ([[MCP Guard]]) |
|---|---|---|---|---|
| Isolation | Container | Container | Wasm component | OS process sandbox per server |
| Needs | Container runtime | Docker Desktop 4.59+ | Wasm rebuild | Nothing extra |
| Egress enforcement | Env-var proxy; raw TCP bypasses it | Not detailed | Deny-by-default host grants | Topology: broker is the only route |
| Credentials | Not detailed | Desktop secrets, OAuth | Env grants in `policy.yaml` | Sentinels in env; minted at egress |
| Manifest pinning | Not in the record | Not in the record | Not in the record | Hash of `tools/list`; change revokes |
| Per-call policy | Host and port | Interceptors (unconfirmed) | Capability grants | Cedar `mcp.call_tool` with arguments |

## Strengths

- Containerised servers run outside the agent's own process tree, and OCI catalogs make pinning by digest possible (inference from the architecture, not a documented feature).
- Wassette's capability model is the purest fit for purpose-built tools: every import is a capability (research note 01 Q4 verdict).
- The identity gateways already implement the OAuth 2.1 resource-server side of the MCP spec.
- Snyk Agent Scan covers the pre-install supply-chain step, which a runtime broker does not.

## Weaknesses (versus this thesis)

- **A container runtime or a Wasm rebuild is required.** On laptops without Docker, the containment gateways are unavailable. Most real servers are Node or Python and will not be rebuilt as components soon.
- **Egress by environment variable** in ToolHive repeats the "polite proxy" flaw ([[ADR-003 Topology-Enforced Egress]]).
- **Nothing in the record pins tool descriptions at runtime.** Rug pulls and name-bound approvals ([[Cursor CurXecute and MCPoison]]) are unaddressed there.
- **Scanners observe; they do not contain,** and Snyk's sends data off-host.
- **Containers share the host kernel** ([[Container Runtimes and Escape History]]).

## What we reuse or interoperate with

**Proposal.**

- Reuse: OCI digest pinning (Docker, Wassette) as an optional pin source next to the manifest hash; Wassette's deny-by-default grant shape for the optional Wasm tier ([[ADR-012 MCP Servers as Pinned Sandboxed Principals]]).
- Interoperate: run Snyk Agent Scan results as an approval input when a manifest hash changes; act as the MCP client toward remote gateways (Pomerium, Aperture, AgentCore) without forwarding the user's IdP token ([[MCP Authorization Spec]]).

## How we differentiate

Local MCP server containment **without a container runtime**: the same OS sandbox and broker egress used for the agent, sentinels instead of environment secrets, runtime manifest pinning and per-call Cedar authorization. This is gap 6 in [[Gap Analysis]].

## How it connects

- competes-with:: [[MCP Guard]]
- contrasts-with:: [[ADR-012 MCP Servers as Pinned Sandboxed Principals]] (rejects container gateways and Wasm-only)
- contrasts-with:: [[Topology-Forced Egress]] (ToolHive's env-var proxy)
- depends-on:: [[Wasmtime and WASI]] (Wassette)
- depends-on:: [[Container Runtimes and Escape History]] (ToolHive, Docker)
- part-of:: [[Docker Sandboxes]] (host-boundary MCP gateway)
- motivated-by:: [[postmark-mcp Rug Pull]] (the threat these products address; none in the record pins descriptions at runtime)
- example-of:: [[Agent Identity Brokers]] (Aembit, Aperture as MCP-facing identity gateways)
- competes-with:: [[Product Thesis]]
- Analysed in: [[Gap Analysis]]

## Implications for the build

- Add a conformance probe from inside a wrapped MCP server that unsets proxy variables and opens a raw socket. It must fail, which is the ToolHive lesson.
- Make `broker mcp wrap` accept an OCI digest or package-lock hash as an extra pin, so users moving from Docker catalogs keep their pins.
- Keep the remote-MCP client code spec-complete (resource metadata, CIMD, PKCE plus `resource`, `iss`), because the identity gateways will be upstreams.

## Open questions

- What does ToolHive CVE-2026-58197 cover? Not reviewed.
- What are the semantics of Docker MCP Gateway interceptors, and does either Docker gateway pin tool descriptions?
- What is the current status of the Invariant Gateway after the Snyk acquisition? What are the internals of Runlayer, Cloudflare MCP portals and Microsoft's MCP gateway? None was fetched ([[Open Questions and Unverified Claims]]).
- How often do real servers change tool descriptions ([[Measurement Gaps]])?
- Pomerium's competitor claims are self-interested and unverified.

## Sources

- [Stacklok: ToolHive network isolation](https://docs.stacklok.com/toolhive/guides-cli/network-isolation)
- [OffSeq: CVE-2026-58197](https://radar.offseq.com/threat/cve-2026-58197-cwe-284-improper-access-control-in-stacklok-toolhive-150e81dc1ad9d600)
- [docker/mcp-gateway](https://github.com/docker/mcp-gateway)
- [pkg.go.dev: mcp-gateway interceptors](https://pkg.go.dev/github.com/docker/mcp-gateway/pkg/interceptors)
- [Docker: MCP Enterprise Gateway](https://www.docker.com/products/mcp-enterprise-gateway/)
- [Docker docs: Sandboxes architecture](https://docs.docker.com/ai/sandboxes/architecture/)
- [Microsoft OSS blog: introducing Wassette](https://opensource.microsoft.com/blog/2025/08/06/introducing-wassette-webassembly-based-tools-for-ai-agents/)
- [Wassette concepts](https://microsoft.github.io/wassette/latest/concepts.html)
- [microsoft/wassette](https://github.com/microsoft/wassette)
- [The New Stack: Wassette](https://thenewstack.io/wassette-microsofts-rust-powered-bridge-between-wasm-and-mcp/)
- [Bytecode Alliance: Wasmtime security advisories](https://bytecodealliance.org/articles/wasmtime-security-advisories)
- [Pomerium: top agentic gateways](https://www.pomerium.com/blog/top-5-agentic-gateways-for-securing-mcp-tool-calls-in-2026)
- [lasso-security/mcp-gateway](https://github.com/lasso-security/mcp-gateway)
- [snyk/agent-scan](https://github.com/snyk/agent-scan)
- [Snyk Labs and Invariant Labs](https://labs.snyk.io/resources/snyk-labs-invariant-labs/)
- [AppSecSanta: Runlayer](https://appsecsanta.com/runlayer)
- [Aembit docs: AI agents](https://docs.aembit.io/get-started/use-cases/ai-agents/)
- [Tailscale: what is Aperture](https://tailscale.com/docs/aperture/what-is-aperture)
- [strongdm/leash](https://github.com/strongdm/leash)
- [e2b-dev/awesome-mcp-gateways](https://github.com/e2b-dev/awesome-mcp-gateways)
- [MCP specification: Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- [Invariant Labs: tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- Report: teardown row "ToolHive; Docker MCP Gateway; Wassette", the ToolHive paragraph and gap item 6; research notes 01 Q1 and Q4, 03 Q2 and 05 sections 1D, 1F and 2.
