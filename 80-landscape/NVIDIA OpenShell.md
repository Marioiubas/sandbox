---
title: "NVIDIA OpenShell"
aliases: ["OpenShell"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/isolation, topic/egress, topic/credentials, platform/linux, platform/macos, platform/k8s]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The closest open-source analogue: Apache-2.0, Rust, alpha, ~8.7k stars; container sandboxes with seccomp and Landlock, an L7 proxy binding credentials by method, path and per-binary, enforce/audit modes; no minting, IdP binding or learning miner."
related: ["[[Gap Analysis]]", "[[Risk Register]]", "[[Native Config Exporters]]", "[[Policy Learning Loop]]", "[[Landlock]]", "[[seccomp-bpf]]", "[[Tech Stack]]", "[[ADR-001 Value Lives in the Broker]]", "[[Just-in-Time Credential Minting]]", "[[I1 No Secrets in the Sandbox]]", "[[Product Thesis]]", "[[Container Runtimes and Escape History]]", "[[Two-Tier Isolation Design]]", "[[Credential Injector and Issuers]]", "[[Audit Recorder and Event Schema]]", "[[ADR-014 Apache-2.0 Endpoint with Commercial ee]]"]
sources: ["https://github.com/NVIDIA/openshell", "https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html", "https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/"]
---

# NVIDIA OpenShell

> The closest open-source analogue: Apache-2.0, Rust, alpha, ~8.7k stars; container sandboxes with seccomp and Landlock, an L7 proxy binding credentials by method, path and per-binary, enforce/audit modes; no minting, IdP binding or learning miner.

## What it is

OpenShell is NVIDIA's open-source runtime for sandboxing coding agents. It is **Apache-2.0**, primarily **Rust**, in **alpha** (0.1.0 prerelease pending), with about **8.7k stars** ([GitHub](https://github.com/NVIDIA/openshell)). The documentation version reviewed was v0.0.116 ([OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)). No commercial offering or pricing is in the record.

The report names it, together with vendor bundling, as one of the **two sharpest threats** to this product ([[Gap Analysis]], [[Risk Register]]).

## Architecture teardown

From [GitHub](https://github.com/NVIDIA/openshell) unless noted:

- **Gateway:** a control-plane API.
- **Sandboxes:** containers on Docker, Podman or Kubernetes, hardened with seccomp and Landlock ([[seccomp-bpf]], [[Landlock]]).
- **Policy engine with an L7 proxy** that can "allow, deny or bind credentials at HTTP method and path level".
- **Providers** inject credentials **as environment variables** at runtime.
- **Policy lifecycle:** filesystem and process policy lock at creation; network and provider policy hot-reload.
- **Supported agents:** Claude Code, OpenCode, Codex, Copilot CLI, OpenClaw, Hermes, Ollama and Pi.
- **Platforms:** Linux, macOS (Apple Silicon) and WSL2 (experimental).

### Policy format

Policies are YAML with host, port and method rules, **per-binary** scoping (for example `/usr/bin/curl`), a `read-only` preset (GET/HEAD/OPTIONS) and `enforcement: enforce|audit`. Denials log the destination, the binary and the reason ([OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)).

## Comparison with the broker

| Dimension | OpenShell | This broker |
|---|---|---|
| Isolation | Containers + seccomp + Landlock | OS process sandbox (Seatbelt; bwrap + seccomp + Landlock), VM opt-in ([[Two-Tier Isolation Design]]) |
| Needs a container runtime | Yes | No |
| Credential delivery | Env-var providers; L7 binding by method/path | Sentinels only in sandbox; mint per task at the proxy ([[Just-in-Time Credential Minting]]) |
| Scoping | Host, port, method, path, **per-binary** | Host, method, path, git ref, API verb, MCP tool; per-binary not in the MVP schema |
| Modes | enforce / audit | record / shadow / enforce |
| Learning | Audit logging, no miner | Verified record → enforce miner ([[Policy Learning Loop]]) |
| IdP binding | Not in the record | Okta/Entra subject on every decision ([[Audit Recorder and Event Schema]]) |
| Policy language | YAML | Cedar with SymCC gates, TOML front-end |
| Licence | Apache-2.0 | Apache-2.0 endpoint, commercial `ee/` ([[ADR-014 Apache-2.0 Endpoint with Commercial ee]]) |

## Strengths

- The neutral data plane already exists: many agents, per-binary L7 rules, credential binding, audit mode.
- Credible licence and NVIDIA backing, the same openness buyers want after the Daytona and Docker licensing events.
- Rust, the same language choice as the broker and Codex ([[Tech Stack]]).

## Weaknesses (versus this thesis)

- **Container-based.** Requires Docker, Podman or Kubernetes; containers share the host kernel. runc and crun had three procfs and masked-path escapes in November 2025 ([CNCF](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/); [[Container Runtimes and Escape History]]).
- **Env-var providers put credentials in the sandbox.** Where the L7 binding is not used, the secret is inside the agent's environment, contrary to [[I1 No Secrets in the Sandbox]].
- **No minting or IdP binding.** Static secrets, no user-agent-repo-task identity.
- **No learning miner.** Audit mode logs; nothing proposes or proves a narrowed policy.
- **Alpha.**

## What we reuse or interoperate with

**Proposal (from the report and the landscape note):** interoperate rather than fight it on the sandbox.

- **Export** broker policy to OpenShell YAML, and **import** OpenShell YAML into Cedar for migration ([[Native Config Exporters]]).
- **Offer minting as an OpenShell provider** if OpenShell becomes the default open-source data plane, so OpenShell sandboxes get task-scoped, short-lived credentials from the broker ([[Credential Injector and Issuers]]).
- **Adopt** its per-binary rule idea as a candidate schema extension; the audit tuple already records the binary.

## How we differentiate

Four points, from the report: **container-free laptop mode, minting, identity and learning** ([[ADR-001 Value Lives in the Broker]]). OpenShell covers much of the neutral data plane but none of those four.

## How it connects

- competes-with:: [[Product Thesis]]
- depends-on:: [[Landlock]]
- depends-on:: [[seccomp-bpf]]
- contrasts-with:: [[Policy Learning Loop]] (audit mode without a miner)
- contrasts-with:: [[Just-in-Time Credential Minting]]
- contrasts-with:: [[I1 No Secrets in the Sandbox]] (env-var providers)
- Export and import target of: [[Native Config Exporters]]
- Analysed in: [[Gap Analysis]], [[Risk Register]] (row "OpenShell becomes the default open-source data plane")
- Informs: [[ADR-001 Value Lives in the Broker]], [[Tech Stack]]

## Implications for the build

- Keep the credential-issuer interface clean enough to be called by a third-party data plane; that is the "OpenShell provider" path.
- Track OpenShell releases. If it ships minting or a miner, revisit the differentiation in [[ADR-001 Value Lives in the Broker]].
- Consider adding per-binary context (binary path, argv hash) to `HttpCtx` after the MVP; the learning plane already records process ancestry.

## Open questions

- Does OpenShell's L7 credential binding keep the secret out of the container, or only restrict where the env-var secret may be sent? The record says both "providers inject credentials as env vars" and "L7 proxy can bind credentials by method and path".
- Is a commercial OpenShell offering planned? Not in the record.

## Sources

- [NVIDIA/OpenShell on GitHub](https://github.com/NVIDIA/openshell)
- [NVIDIA OpenShell docs: first network policy](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)
- [CNCF: runc breakout vulnerabilities](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)
