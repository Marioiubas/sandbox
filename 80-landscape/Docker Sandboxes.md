---
title: "Docker Sandboxes"
aliases: ["sbx", "Docker sbx"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/isolation, topic/credentials, topic/egress, platform/macos, platform/windows, evidence/secondary]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Docker sbx: a microVM per agent with a private Docker engine, host proxy that injects credentials so the agent never reads them, Open/Balanced/Locked Down tiers, clone mode, free but closed with a licence 'not final'."
related: ["[[Apple Virtualization Framework]]", "[[Sentinel Swap Pattern]]", "[[Filesystem Control and Rollback]]", "[[MCP Gateways]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[Gap Analysis]]", "[[Risk Register]]", "[[ADR-014 Apache-2.0 Endpoint with Commercial ee]]", "[[Git Smart-HTTP Adapter]]", "[[Just-in-Time Credential Minting]]", "[[Policy Learning Loop]]", "[[Open Questions and Unverified Claims]]", "[[Two-Tier Isolation Design]]", "[[TLS Termination and Per-Session CA]]", "[[Native Config Exporters]]", "[[Product Thesis]]", "[[Architecture Overview]]"]
sources: ["https://docs.docker.com/ai/sandboxes/security/defaults/", "https://docs.docker.com/ai/sandboxes/architecture/", "https://docs.docker.com/ai/sandboxes/network-policies/", "https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/", "https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/", "https://github.com/docker/desktop-feedback/issues/130", "https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/", "https://docs.docker.com/ai/sandboxes/", "https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk", "https://github.com/docker/mcp-gateway"]
---

# Docker Sandboxes

> Docker sbx: a microVM per agent with a private Docker engine, host proxy that injects credentials so the agent never reads them, Open/Balanced/Locked Down tiers, clone mode, free but closed with a licence 'not final'.

## What it is

Docker Sandboxes (`sbx`) run coding agents in microVMs on the developer's machine. The product reached GA on **30 Jan 2026 for macOS and Windows**, with Linux listed under "What's next". The launch lists Claude Code, Copilot CLI, Codex CLI, Gemini CLI and Kiro ([Docker blog](https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/)). By July 2026 it supported 9 agents ([INNOQ](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)). It is the closest local prior art to the "credential stays outside, proxy swaps sentinel" half of the thesis.

- **Licence:** not open source, but it "will remain free to use, including commercially"; the licence is "not final yet" ([INNOQ](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)).
- **Pricing:** the CLI is free. Docker sells a subscription that lets admins "centrally manage sandbox network, filesystem, and MCP policies" ([Docker docs](https://docs.docker.com/ai/sandboxes/)). Enterprise pricing is not in the record.

## Architecture teardown

### Isolation

Each agent runs in a **microVM, not a container**, with its own Docker daemon, and agents "have no access to the host Docker daemon" ([Docker blog](https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/)). The agent has sudo and a private Docker Engine inside the VM ([Docker docs](https://docs.docker.com/ai/sandboxes/security/defaults/)). Sandboxes do not share images or layers ([Docker architecture](https://docs.docker.com/ai/sandboxes/architecture/)).

> [!question] Unverified
> Docker documents neither the hypervisor it uses on each OS nor its start times ([[Open Questions and Unverified Claims]]). On macOS the obvious candidate is Virtualization.framework ([[Apple Virtualization Framework]]), but that is not stated.

### Workspace

The workspace is mounted via virtiofs with caching on by default, in three layouts: a direct mount at the same absolute path; mountless; and **clone mode**, where the host source is read-only at `/run/sandbox/source` and the agent works on a private clone ([Docker architecture](https://docs.docker.com/ai/sandboxes/architecture/)). Clone mode is the precedent for the broker's rollback design ([[Filesystem Control and Rollback]]). There is no way to mask individual files inside the project folder ([INNOQ](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)).

### Network

- "All outbound TCP traffic, including HTTP, HTTPS, and SSH, is blocked unless an explicit rule allows the destination", and UDP and ICMP are blocked. Org-level policies take precedence over local ones ([Docker docs](https://docs.docker.com/ai/sandboxes/security/defaults/)).
- A filtering proxy at `host.docker.internal:3128` acts by default as a **TLS MITM** with its own CA, trusted in the sandbox. `--bypass-host` / `--bypass-cidr` switch a destination to a raw TCP tunnel. Private ranges are blocked by default. `docker sandbox network log` shows allowed and blocked requests, and config lives in `proxy-config.json` ([Docker network policies](https://docs.docker.com/ai/sandboxes/network-policies/)).
- Network modes are Open, Balanced and Locked Down ([Andrew Lock](https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/)).

### Credentials

"All outbound TCP traffic routes through a host-side proxy." "The proxy replaces the sentinel with the real credential after the request has left the microVM", and "the real credential stays outside the sandbox throughout the request" ([Docker architecture](https://docs.docker.com/ai/sandboxes/architecture/)). "The agent cannot read the raw credential values" ([Docker docs](https://docs.docker.com/ai/sandboxes/security/defaults/)). An `sbx secret` command stores secrets ([Andrew Lock](https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/)). An open request asks for custom credential-injection rules in `proxy-config.json`, which implies injection is limited to built-in providers ([docker/desktop-feedback#130](https://github.com/docker/desktop-feedback/issues/130)). This is the [[Sentinel Swap Pattern]] with static secrets.

Commit signing through a host ssh-agent (1Password) cannot be shared into the VM ([Andrew Lock](https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/)).

### MCP

An MCP gateway sits on the host boundary: "Local stdio servers don't run inside the sandbox VM" ([Docker architecture](https://docs.docker.com/ai/sandboxes/architecture/)). The separate Docker MCP Gateway is MIT-licensed Go and runs each server in its own container ([docker/mcp-gateway](https://github.com/docker/mcp-gateway); [[MCP Gateways]]).

## Strengths

- A real hypervisor boundary by default; the agent can run Docker inside it safely.
- Deny-by-default egress covering SSH, UDP and ICMP; org policy precedence.
- Host-side credential injection, clone mode and a network log.
- Free, and broad agent coverage.

## Weaknesses (versus this thesis)

- **Closed, licence not final.** A security boundary buyers cannot audit; the report pairs it with Daytona going closed-source in June 2026 ([bex.co](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk)) as a licensing opening ([[ADR-014 Apache-2.0 Endpoint with Commercial ee]]).
- **Linux was "what's next" at launch**, so Linux laptops and CI were not covered at GA.
- **Static secrets, built-in providers only;** no minting, no per-task scope ([[Just-in-Time Credential Minting]]).
- **Domain-level scoping** with tiers; no git ref or API-verb semantics ([[Git Smart-HTTP Adapter]]).
- **Operational friction:** many VMs across many projects, IDE/VM network split, no per-file masking ([INNOQ](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)), no signing agent.
- **MITM by default** for all allowed hosts, which breaks pinned clients unless bypassed ([[TLS Termination and Per-Session CA]]).

## What we reuse or interoperate with

- **Precedent adopted:** clone mode for rollback; host-side injection; the network log as a learning input ([[Policy Learning Loop]]).
- **Precedent rejected:** microVM by default. The broker's default is an OS process sandbox with a VM as the opt-in hard tier, for start time and density on laptops ([[ADR-002 OS Process Sandbox by Default with VM Hard Tier]], [[Two-Tier Isolation Design]]).
- **Interoperate (phase 2):** remote-sandbox gateway mode makes the broker the upstream proxy for Docker sbx, so the same policy and minting apply inside it ([[Architecture Overview]]). Whether Docker's org policy can be an export target is open ([[Native Config Exporters]]).
- **Differentiate:** do commit signing broker-side.

## How we differentiate

Container-free laptop mode with ~ms start, credential minting bound to user, agent, repo and task, git and GitHub semantics, verified learning, Linux and CI first, and an auditable Apache-2.0 data plane ([[Gap Analysis]], [[Risk Register]]).

## How it connects

- competes-with:: [[Product Thesis]]
- example-of:: [[Sentinel Swap Pattern]]
- depends-on:: [[Apple Virtualization Framework]] (probable on macOS; unverified)
- contrasts-with:: [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]
- Evidence for: [[ADR-014 Apache-2.0 Endpoint with Commercial ee]] (licence not final)
- Its MCP gateway is covered in: [[MCP Gateways]]
- Precedent for: [[Filesystem Control and Rollback]]
- Analysed in: [[Gap Analysis]], [[Risk Register]]

## Implications for the build

- Match Docker's defaults as a floor: block UDP, ICMP and SSH; block private ranges; log allowed and blocked.
- Keep TLS termination selective, unlike Docker's MITM-by-default.
- Implement broker-side commit signing early; it is a visible developer pain point in the incumbent.

## Open questions

- Hypervisor and start time per OS; enterprise pricing; the final licence.
- Has Linux support shipped since launch? Re-check before claiming a Linux advantage.

## Sources

- [Docker docs: security defaults](https://docs.docker.com/ai/sandboxes/security/defaults/); [architecture](https://docs.docker.com/ai/sandboxes/architecture/); [network policies](https://docs.docker.com/ai/sandboxes/network-policies/); [Sandboxes overview](https://docs.docker.com/ai/sandboxes/)
- [Docker blog: launch](https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/)
- [INNOQ, Jul 2026](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)
- [docker/desktop-feedback#130](https://github.com/docker/desktop-feedback/issues/130)
- [Andrew Lock](https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/)
- [docker/mcp-gateway](https://github.com/docker/mcp-gateway)
- [bex.co: Daytona closed source](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk)
