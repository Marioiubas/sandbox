---
title: "Local Credential Proxies"
aliases: ["Infisical Agent Vault", "StrongDM Leash", "Agent Vault", "Leash", "agentjail"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/credentials, topic/egress, topic/policy, platform/macos, platform/linux]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Infisical Agent Vault (MITM via HTTPS_PROXY, placeholders per host and path, unmatched_host_policy=deny, MIT plus ee/), StrongDM Leash (container plus eBPF plus Cedar, but forwards API keys into the agent) and agentjail: lessons on proxy-env reliance and secrets inside the boundary."
related: ["[[Sentinel Swap Pattern]]", "[[Topology-Forced Egress]]", "[[I1 No Secrets in the Sandbox]]", "[[Cedar]]", "[[AgentSentinel]]", "[[ADR-014 Apache-2.0 Endpoint with Commercial ee]]", "[[Gap Analysis]]", "[[Policy Learning Loop]]", "[[ADR-003 Topology-Enforced Egress]]", "[[Tech Stack]]", "[[MCP Guard]]", "[[gVisor]]", "[[Seatbelt]]", "[[Landlock]]", "[[ADR-015 Rust for the Endpoint and Custom Proxy]]", "[[Product Thesis]]", "[[I2 Fail-Closed Launch]]", "[[MCP Gateways]]"]
sources: ["https://github.com/Infisical/agent-vault", "https://github.com/strongdm/leash", "https://agentjail.io/docs/concepts/sandbox/", "https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/", "https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o", "https://github.com/craigbalding/safeyolo/issues/620", "https://arxiv.org/html/2509.07764v1", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/"]
---

# Local Credential Proxies

> Infisical Agent Vault (MITM via HTTPS_PROXY, placeholders per host and path, unmatched_host_policy=deny, MIT plus ee/), StrongDM Leash (container plus eBPF plus Cedar, but forwards API keys into the agent) and agentjail: lessons on proxy-env reliance and secrets inside the boundary.

## What they are

Three small, open-source, agent-neutral-ish local tools. Each owns one slice of the thesis and each shows a failure mode the broker must avoid. Two are written in Go, which is why Go was the considered alternative in [[Tech Stack]].

| Tool | Licence, version, adoption | Core idea |
|---|---|---|
| **Infisical Agent Vault** | Go, MIT with an `ee/` enterprise directory, ~2.2k stars, "in active development" | HTTPS MITM credential proxy with placeholders |
| **StrongDM Leash** | Apache-2.0, Go/TS/Swift (66.5% Go), v1.1.7 (11 Mar 2026), ~573 stars | Container plus eBPF monitor plus Cedar |
| **agentjail** | MIT, v1.8.0 | Hooks plus Seatbelt/Landlock plus optional gVisor MITM tunnel |

Sources: [Agent Vault](https://github.com/Infisical/agent-vault); [Leash](https://github.com/strongdm/leash); [agentjail](https://agentjail.io/docs/concepts/sandbox/). No pricing for any of them is in the record.

## Architecture teardown

### Infisical Agent Vault

- An HTTP(S) MITM credential proxy on port 14322, reached through `HTTPS_PROXY`.
- Agents send placeholders such as `__anthropic_api_key__`, and the vault substitutes the real secret.
- Rules work per host and path; `unmatched_host_policy=deny` gives strict mode.
- It recommends running the vault on separate infrastructure from the agent.
- **Isolation:** none; it is a proxy only.

Source: [GitHub](https://github.com/Infisical/agent-vault). Its secrets come from an encrypted local store ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)).

### StrongDM Leash

- Runs an agent container plus a Leash container that monitors syscalls with eBPF and enforces **Cedar** policies over file, process and network activity. A Control UI runs on `localhost:18080`.
- An MCP observer "inspects, records, and enforces MCP tool calls".
- Captures complete file and network telemetry "so Cedar policies and audit trails operate on complete telemetry".
- **Forwards API keys such as `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` into the agent** as env vars, so they are not brokered.
- Requires Docker or Podman; macOS native mode needs a helper app.

Source: [GitHub](https://github.com/strongdm/leash). Leash is one of two agent-authorization precedents for Cedar, with AgentCore Policy ([AWS](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/); [[Cedar]]).

### agentjail

- Wraps Claude, Cursor and Codex with hooks plus Seatbelt (macOS) or Landlock (Linux) ([[Seatbelt]], [[Landlock]]).
- An optional transparent tunnel "using gVisor + MITM" enforces `network.allowed_hosts` ([[gVisor]]).
- **Fails open on Windows and FreeBSD.**

Source: [agentjail docs](https://agentjail.io/docs/concepts/sandbox/).

## Lessons

1. **Proxy environment variables are "polite".** `HTTP_PROXY` alone is bypassable: an agent with code execution can call raw sockets ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)). Agent Vault relies on `HTTPS_PROXY` and has no sandbox, so a non-compliant program simply goes around it. The broker makes its proxy the only route by topology ([[Topology-Forced Egress]], [[ADR-003 Topology-Enforced Egress]]).
2. **Secrets inside the boundary are not brokered.** Leash's env forwarding is listed as evidence for [[I1 No Secrets in the Sandbox]]. A container that can read `ANTHROPIC_API_KEY` can exfiltrate it through any allowed channel.
3. **Fail-open platforms are a trap.** agentjail's Windows/FreeBSD behaviour is the opposite of [[I2 Fail-Closed Launch]].
4. **Placeholders are the right shape.** Agent Vault's per-host/per-path placeholder swap and deny-unmatched strict mode are the [[Sentinel Swap Pattern]], and match the broker's static-swap fallback tier.
5. **Kernel telemetry is a backstop, not the decision point.** Leash's eBPF monitor resembles AgentSentinel's eBPF and LSM tracing, which reached 79.6% defense success at a 10.8% false-positive rate with an LLM auditor ([arXiv 2509.07764](https://arxiv.org/html/2509.07764v1); [[AgentSentinel]]). The broker adopts kernel telemetry for audit and learning input, not as the primary decision.

A related data point: SafeYolo is replacing its mitmproxy-based credential proxy with focused Rust, explicitly for simplicity rather than speed, and separates route validation, credential selection, policy evaluation, inspection and injection ([SafeYolo #620](https://github.com/craigbalding/safeyolo/issues/620)). That module split informs [[ADR-015 Rust for the Endpoint and Custom Proxy]].

## Strengths

- Open source and small enough to audit. Agent Vault's MIT + `ee/` layout is the open-core precedent the broker follows ([[ADR-014 Apache-2.0 Endpoint with Commercial ee]]).
- Leash proves Cedar works for agent file, process, network and MCP policy, and its telemetry is the closest thing in the record to a learning input ([[Policy Learning Loop]]).
- Agent Vault's strict mode denies unmatched hosts.

## Weaknesses (versus this thesis)

- Agent Vault: no sandbox, env-var proxying, static secrets.
- Leash: secrets inside the container, container runtime required.
- agentjail: fail-open on some platforms; small project.
- None mints credentials, binds IdP identity or parses git.

## What we reuse or interoperate with

- **Reuse:** placeholder semantics and deny-unmatched from Agent Vault; Cedar-over-telemetry and MCP observation ideas from Leash ([[MCP Guard]]); the SafeYolo module boundary.
- **Interoperate:** Agent Vault could be a static-secret backend behind a broker issuer; not designed in the record.

## How we differentiate

Topology instead of env vars, sentinels instead of forwarded keys, minting instead of static swap, and one fail-closed launcher on every supported platform ([[Gap Analysis]]).

## How it connects

- example-of:: [[Sentinel Swap Pattern]] (Agent Vault)
- contrasts-with:: [[Topology-Forced Egress]]
- contrasts-with:: [[I1 No Secrets in the Sandbox]] (Leash)
- contrasts-with:: [[I2 Fail-Closed Launch]] (agentjail)
- depends-on:: [[Cedar]] (Leash)
- example-of:: [[AgentSentinel]] (kernel-telemetry monitoring)
- Evidence for: [[ADR-003 Topology-Enforced Egress]] (env-var proxying is bypassable) and [[ADR-014 Apache-2.0 Endpoint with Commercial ee]] (MIT + `ee/` precedent)
- competes-with:: [[Product Thesis]]
- Analysed in: [[Gap Analysis]]; MCP observation compared in [[MCP Gateways]]

## Implications for the build

- Add a conformance probe that unsets proxy variables and opens a raw socket; it must fail under every backend ([[L1 Conformance Suite]] category 9).
- Scan the sandbox environment for any variable whose value is not a sentinel (the I1 test); Leash-style forwarding must be impossible by construction.
- Consider an Agent Vault-compatible placeholder syntax so users can migrate configs.

## Open questions

- Would Agent Vault or Leash maintainers accept the broker as an upstream issuer or egress point?
- Is Leash's MCP observer a proxy or a passive tap? Not detailed in the record.

## Sources

- [Infisical/agent-vault](https://github.com/Infisical/agent-vault)
- [strongdm/leash](https://github.com/strongdm/leash)
- [agentjail docs](https://agentjail.io/docs/concepts/sandbox/)
- [Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)
- [dev.to: kernel-level egress control](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)
- [SafeYolo #620](https://github.com/craigbalding/safeyolo/issues/620)
- [AgentSentinel](https://arxiv.org/html/2509.07764v1)
- [AWS Security Blog: AgentCore Policy](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)
