---
title: "ADR-012 MCP Servers as Pinned Sandboxed Principals"
aliases: ["ADR-012"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/mcp, topic/supply-chain, topic/isolation, topic/credentials, control/pin, control/iso, control/cred-out, boundary/tb6, invariant/i1, invariant/i5, milestone/m3]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Run MCP servers as pinned, separately sandboxed principals reached by name; reject container gateways (Docker, ToolHive) and Wasm-only (Wassette)."
related: ["[[MCP Guard]]", "[[MCP Gateways]]", "[[Wasmtime and WASI]]", "[[ACE and IsolateGPT]]", "[[postmark-mcp Rug Pull]]", "[[Cursor CurXecute and MCPoison]]", "[[MCP Authorization Spec]]", "[[GitHub MCP Toxic Flow]]", "[[Sandbox Launcher]]", "[[Sentinel Swap Pattern]]", "[[Credential Injector and Issuers]]", "[[Broker Cedar Schema]]", "[[I1 No Secrets in the Sandbox]]", "[[I5 Config Outside Writable Mounts]]", "[[I7 Reject Foreign Credentials]]", "[[I2 Fail-Closed Launch]]", "[[Measurement Gaps]]", "[[M3 CI Identity and MCP]]", "[[Open Questions and Unverified Claims]]", "[[Policy Learning Loop]]", "[[MOC Decisions]]"]
sources: ["https://modelcontextprotocol.io/specification/latest/basic/authorization", "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices", "https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html", "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks", "https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison", "https://arxiv.org/abs/2403.04960", "https://arxiv.org/abs/2504.20984", "https://docs.stacklok.com/toolhive/guides-cli/network-isolation", "https://github.com/docker/mcp-gateway", "https://github.com/microsoft/wassette", "https://microsoft.github.io/wassette/latest/concepts.html", "https://bytecodealliance.org/articles/wasmtime-security-advisories", "https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/", "https://github.com/snyk/agent-scan", "https://github.com/strongdm/leash"]
superseded_by:
---

# ADR-012 MCP Servers as Pinned Sandboxed Principals

> Run MCP servers as pinned, separately sandboxed principals reached by name; reject container gateways (Docker, ToolHive) and Wasm-only (Wassette).

## Status

Proposed (2026-09-24). Delivered by [[M3 CI Identity and MCP]]: a wrapped GitHub MCP server can read issues but cannot reach non-allowlisted hosts, and a changed tool description revokes it.

## Context

Local MCP servers sit on three incident paths at once.

- **Secrets by specification.** The MCP authorization spec says implementations using STDIO "SHOULD NOT follow this specification, and instead retrieve credentials from the environment" ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)). That is the secret-in-sandbox pattern this product exists to remove ([[MCP Authorization Spec]]).
- **Supply chain and rug pulls.** postmark-mcp version 1.0.16 added one line that BCC'd every sent email to an attacker; the package had 1,643 downloads ([The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html); [[postmark-mcp Rug Pull]]). Invariant Labs showed that "a malicious server can change the tool description after the client has already approved it", and recommended pinning versions and hashing tool descriptions ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)).
- **Config rewrite.** Cursor's CurXecute (CVE-2025-54135) let a prompt injection write `.cursor/mcp.json`, which Cursor then auto-started. MCPoison (CVE-2025-54136) worked because approval was "bound by the MCP name not its contents" ([Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison); [[Cursor CurXecute and MCPoison]]).

**Isolation per tool works and is cheap.** IsolateGPT runs each app in its own spoke, with under 30% overhead for three-quarters of queries ([arXiv 2403.04960](https://arxiv.org/abs/2403.04960)). ACE later showed planning-integrity attacks on the hub, which argues for isolating the tools rather than trusting a planner ([arXiv 2504.20984](https://arxiv.org/abs/2504.20984); [[ACE and IsolateGPT]]). The confused-deputy problem is a named attack on MCP proxies, and the spec bans token passthrough ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)).

**The existing containment options each need something developers may not have** ([[MCP Gateways]]):

- ToolHive runs servers in containers behind a Squid proxy set through `HTTP(S)_PROXY`. It "does not transparently redirect all traffic with iptables or nftables rules", so raw TCP bypasses it ([Stacklok](https://docs.stacklok.com/toolhive/guides-cli/network-isolation)).
- Docker MCP Gateway runs each server in its own container using Docker Desktop secrets. It requires Docker Desktop 4.59+ with MCP Toolkit ([docker/mcp-gateway](https://github.com/docker/mcp-gateway)).
- Wassette runs WebAssembly components on Wasmtime with deny-by-default grants in `policy.yaml` ([Wassette concepts](https://microsoft.github.io/wassette/latest/concepts.html)). It is marked "Early Development… not production ready" at v0.4.0 ([microsoft/wassette](https://github.com/microsoft/wassette)), and existing servers must be rebuilt as components. Wasmtime had 12 advisories in April 2026, two of them critical sandbox escapes ([Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-security-advisories); [[Wasmtime and WASI]]).
- Claude Code's sandbox reportedly struggles with MCP server network access ([Infralovers](https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/)).

Most MCP servers are Node or Python programs, so they need a process sandbox rather than a Wasm runtime (report, layered-design table).

## Decision

**Proposal.** Every MCP server is a separately sandboxed, pinned principal that the agent can name but not define ([[MCP Guard]]):

1. **Definitions live outside the repo.** Pinned servers (name, command, args, env sentinels, egress policy) are defined only in user or org config, outside every writable mount, and loaded after content-hash approval.
2. **The agent reaches servers by name.** The agent's MCP configuration points at a stub, `broker mcp connect <name>`, which speaks over the data plane. `brokerd` launches the pinned command for that name. Writing a new `mcp.json` therefore buys an attacker nothing.
3. **Each server is its own sandbox.** The server runs in its own standard-tier sandbox (Seatbelt, or bwrap + seccomp + Landlock) as a separate `McpServer` principal, with its own filesystem grants and egress policy. Its environment holds only sentinels; real credentials are attached by the broker on the server's egress to its upstream API.
4. **Tool manifests are pinned.** Before relaying anything, the guard hashes `tools/list` (names, schemas and descriptions). Any change revokes the server's grants until a human re-approves the new hash.
5. **Every call is authorized.** Each `tools/call` becomes an `mcp.call_tool` Cedar request with its arguments. The default policy forbids calls to unpinned servers ([[Broker Cedar Schema]]).
6. **Remote MCP servers:** the broker acts as the full MCP client (resource-metadata discovery, CIMD client ID, PKCE plus `resource`, `iss` checks), holds the tokens and injects `Authorization: Bearer` at egress. It never forwards the user's IdP token.
7. **Hosts that launch servers themselves**, such as desktop apps, use `broker mcp wrap -- <cmd>` for the same treatment.
8. **Wasm is optional, not the path.** Pure-logic tools may later run as Wasm components hosted by the broker, with `wasi:http` implemented by the broker, as a hard tier. No server is required to be Wasm.

**Testable as:** the M3 criteria; a probe that writes a new `.cursor/mcp.json` or `.mcp.json` from inside the sandbox gains no new server; a scan of each server's environment finds only sentinels; a mutated tool description causes a deny with reason "manifest changed".

## Alternatives considered

| Alternative | Pros | Cons | Why rejected |
|---|---|---|---|
| **Container gateway** (Docker MCP Gateway, ToolHive) | Mature packaging, catalogs, per-server containers | Needs a container runtime (Docker Desktop 4.59+ for Docker); ToolHive's env-var proxy is bypassable by raw TCP; containers share the host kernel | Fails the "on laptops without Docker" requirement; egress not topology-enforced |
| **Wasm only** (Wassette) | Purest capability model; no ambient authority | Existing Node and Python servers must be rebuilt; "not production ready"; Wasmtime escapes in April 2026 | Excludes most real servers today; kept as an optional tier |
| **Run servers inside the agent's sandbox** (status quo) | Zero setup | Servers share the agent's authority and see stdio env secrets | Confused-deputy and secret exposure by construction |
| **Scanner only** (Snyk Agent Scan) | Finds poisoned descriptions and toxic flows; no runtime cost | Detects but does not contain; no credential brokering; sends component data to Snyk's API ([snyk/agent-scan](https://github.com/snyk/agent-scan)) | Useful as an input, not a boundary |
| **Container-wrapped agent with an MCP observer** (StrongDM Leash) | Its observer "inspects, records, and enforces MCP tool calls" | Needs Docker or Podman; forwards API keys into the agent container ([strongdm/leash](https://github.com/strongdm/leash)) | Secrets inside the boundary contradict I1 |
| **Name-bound approval** | Simple UX | Exactly the MCPoison flaw | Approval must bind to content hashes |

## Consequences

- **Easier:** CurXecute-class rewrites become harmless, rug pulls revoke themselves, and stdio servers stop holding real secrets, with no server changes.
- **Harder:** one sandbox per server means more processes and per-server policy to author. [[Policy Learning Loop]] records per-server traces to help.
- **Riskier:** legitimate server updates that change descriptions force re-approval. The base rate at which real servers change descriptions is an open measurement gap ([[Measurement Gaps]]), so the friction is unknown.
- **Residual:** a pinned, approved server that misuses its granted scope is still misuse inside scope. Semantic rules (for example, email recipient allowlists) are the mitigation.

## Revisit triggers

- Measured description-change rates make hash pinning impractically noisy: consider pinning schemas strictly and descriptions with a diff-review UI.
- The MCP spec defines a non-environment credential path for STDIO.
- Wassette or a successor reaches production readiness and major servers ship as components.
- A platform where no process sandbox is available (for example Windows, phase 3).

## Invariants and components affected

- **Upholds [[I1 No Secrets in the Sandbox]]:** servers see only sentinels.
- **Upholds [[I5 Config Outside Writable Mounts]]:** MCP manifests and definitions sit outside writable mounts and load only after hash approval.
- **Upholds [[I7 Reject Foreign Credentials]]:** credentials a server did not receive from the broker are stripped at egress.
- **Upholds [[I2 Fail-Closed Launch]]:** if a server's sandbox cannot start, the server does not start.
- **Upholds I9:** every `tools/call` is logged with its decision.
- Components: [[MCP Guard]] (`crates/mcpguard`), [[Sandbox Launcher]], [[Credential Injector and Issuers]] ([[Sentinel Swap Pattern]]), [[Broker Cedar Schema]].

## How it connects

- depends-on:: [[MCP Guard]]
- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[Sentinel Swap Pattern]]
- depends-on:: [[MCP Authorization Spec]]
- mitigates:: [[postmark-mcp Rug Pull]]
- mitigates:: [[Cursor CurXecute and MCPoison]]
- mitigates:: [[GitHub MCP Toxic Flow]] (with trifecta labels)
- motivated-by:: [[ACE and IsolateGPT]]
- contrasts-with:: [[MCP Gateways]]
- contrasts-with:: [[Wasmtime and WASI]] (Wasm-only)
- implements:: [[I5 Config Outside Writable Mounts]]
- delivered-by:: [[M3 CI Identity and MCP]]
- part-of:: [[MOC Decisions]]

## Implications for the build

- The stdio JSON-RPC relay is a hostile-input parser: property tests and a `cargo-fuzz` target from day one.
- Hash a canonical JSON serialisation of `tools/list`, so key order or whitespace changes do not trigger spurious revocations while real edits do.
- Ship built-in profiles for common servers (for example the GitHub MCP server) so M3 users do not start from an empty policy.
- Record the manifest hash on every `mcp.call_tool` audit row.

## Open questions

- How is `broker mcp connect` wired into each agent's MCP config without writing into the repo? Likely per-agent profiles; not specified in the record.
- What is the base rate of tool-description changes in real servers ([[Measurement Gaps]])?
- Wassette's permission-policy format was cited from its concepts page in one research note but marked "not captured" in another ([[Open Questions and Unverified Claims]]).

## Sources

- [MCP specification: Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- [The Hacker News: first malicious MCP server](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)
- [Invariant Labs: tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [Tenable: CurXecute and MCPoison FAQ](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)
- [IsolateGPT, arXiv 2403.04960](https://arxiv.org/abs/2403.04960)
- [ACE, arXiv 2504.20984](https://arxiv.org/abs/2504.20984)
- [Stacklok: ToolHive network isolation](https://docs.stacklok.com/toolhive/guides-cli/network-isolation)
- [docker/mcp-gateway](https://github.com/docker/mcp-gateway)
- [microsoft/wassette](https://github.com/microsoft/wassette)
- [Wassette concepts](https://microsoft.github.io/wassette/latest/concepts.html)
- [Bytecode Alliance: Wasmtime security advisories](https://bytecodealliance.org/articles/wasmtime-security-advisories)
- [Infralovers: sandboxing Claude Code on macOS](https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/)
- [snyk/agent-scan](https://github.com/snyk/agent-scan)
- [strongdm/leash](https://github.com/strongdm/leash)
- Report: decisions row "MCP servers", "MCP guard: servers are principals, names are capabilities" and the layered-design table; research notes 01 Q4, 03 Q2, 04b Q1–Q2 and 05 sections 1F and 2.
