---
title: "MOC Decisions"
aliases: []
type: moc
section: decisions
tags: [sandbox/decisions, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "The fifteen architecture decision records with the alternatives each rejected, and how to add a new one."
related: ["[[ADR-001 Value Lives in the Broker]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[ADR-003 Topology-Enforced Egress]]", "[[ADR-004 Selective TLS Termination with Per-Session CA]]", "[[ADR-005 Mint Credentials Per Task]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[ADR-007 Cedar with a TOML Front-End]]", "[[ADR-008 Grant Representation as Entities and Txn-Token JWT]]", "[[ADR-009 Broker-Only DNS Resolution]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[ADR-011 Verified Policy Learning Loop]]", "[[ADR-012 MCP Servers as Pinned Sandboxed Principals]]", "[[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]", "[[ADR-014 Apache-2.0 Endpoint with Commercial ee]]", "[[ADR-015 Rust for the Endpoint and Custom Proxy]]", "[[MOC Architecture]]", "[[Risk Register]]", "[[CLAUDE]]"]
sources: []
---

# MOC Decisions

> The fifteen architecture decision records with the alternatives each rejected, and how to add a new one.

Architecture decision records for the fourteen decisions in the report's decision table plus the endpoint-language and proxy choice from its tech-stack table. Every ADR states the chosen option, the alternatives rejected and why, and links the evidence. ADRs are `status: proposal` until the build confirms them; mark `status: built` when code implements them, and `superseded` relationships in the body when a newer ADR replaces one.

**Adding a decision:** copy `templates/Template ADR.md`, number it with the next free `ADR-NNN`, add it to this MOC and to [[Build Log]]. Never weaken an invariant from [[MOC Architecture]] without an ADR that says so explicitly.

## Decision table

| ADR | Decision |
|---|---|
| [[ADR-001 Value Lives in the Broker]] | Put the product's value in the broker (policy, minting, semantics, audit, learning), not in a new isolation primitive, because isolation is mature and shipped by incumbents. |
| [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]] | Default to the OS process sandbox (Seatbelt; bwrap+seccomp+Landlock) with a microVM as opt-in hard tier, rejecting microVM-by-default and containers. |
| [[ADR-003 Topology-Enforced Egress]] | Enforce egress by topology (no NIC or loopback-only plus UDS or vsock), rejecting HTTP_PROXY-only and eBPF-redirect-only designs. |
| [[ADR-004 Selective TLS Termination with Per-Session CA]] | Terminate TLS only for hosts with credentials or L7 rules using a per-session CA; splice everything else at L4; rejecting MITM-everything and SNI-only. |
| [[ADR-005 Mint Credentials Per Task]] | Mint per-task credentials wherever providers allow and fall back to static sentinel swap; reject static-swap-only and env-var secrets. |
| [[ADR-006 Deny Unmatched L7 Requests]] | Within an allowed domain, method and path rules are authorization: unmatched L7 requests are denied, rejecting Vercel's pass-without-credential semantics. |
| [[ADR-007 Cedar with a TOML Front-End]] | Use Cedar (Lean-verified, SymCC-analyzable, µs latency, agent-gateway precedent) behind a small TOML layer; reject OPA/Rego, Progent JSON-Schema, Invariant rules and a custom DSL. |
| [[ADR-008 Grant Representation as Entities and Txn-Token JWT]] | Represent grants as Cedar entities inside the broker and as a Txn-Token-shaped DPoP-bound JWT across hosts, with Biscuit later for sub-agents; reject Macaroons or Biscuit from day one and opaque handles only. |
| [[ADR-009 Broker-Only DNS Resolution]] | Resolve all names in the broker; the sandbox has no UDP/53 or ICMP; reject filtered UDP/53 passthrough. |
| [[ADR-010 Session-Level Trifecta Labels in the MVP]] | Ship session-level trifecta labels sourced from systems of record in the MVP; defer CaMeL-style interpreters and FIDES planners. |
| [[ADR-011 Verified Policy Learning Loop]] | Learn policy via record, mine, SymCC, human PR, shadow, enforce; reject auto-applied LLM-synthesized policy and no learning. |
| [[ADR-012 MCP Servers as Pinned Sandboxed Principals]] | Run MCP servers as pinned, separately sandboxed principals reached by name; reject container gateways (Docker, ToolHive) and Wasm-only (Wassette). |
| [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]] | Use generated Seatbelt profiles on macOS for the MVP with a Virtualization.framework backend as hedge; reject a Network Extension and VM-only. |
| [[ADR-014 Apache-2.0 Endpoint with Commercial ee]] | License everything on the endpoint Apache-2.0 and keep the fleet control plane in a commercial ee/ directory; reject AGPL and closed source. |
| [[ADR-015 Rust for the Endpoint and Custom Proxy]] | Write the whole endpoint in Rust as one static binary and build a custom tokio/hyper/rustls/rcgen proxy (hudsucker as reference); reject Go and Envoy/mitmproxy for the product path. |
| [[ADR-016 macOS M0 Compatibility Exceptions]] | On macOS in M0, keep the per-user temp dir writable and let only profiles that declare it read the login keychain until M1; both announced, audited and time-boxed. |
| [[ADR-017 Landlock Filesystem Layer Required]] | The Landlock filesystem layer is a required Linux layer; only its TCP rules degrade below ABI 4, where the empty netns remains the boundary. |
| [[ADR-018 seccomp Filter Shape for M0]] | Keep the proposed seccomp denials, add io_uring, clone3, x32 and TIOCSTI, and allow socketpair(AF_UNIX) and AF_NETLINK. |
| [[ADR-019 Mandatory Deny-Write List Additions]] | Protect the .git entry itself (rename-and-replant escape), .mcp.json, .envrc, .gemini, .broker and PATH dirs; placeholders for missing names on Linux. |
| [[ADR-020 Brokered Agent Credentials End the Keychain Exception]] | Agents' own credentials are held by brokerd behind sentinels; agent token files are deny-read; the macOS keychain switch of ADR-016 is removed. |
| [[ADR-021 L7 Path Choices for M1]] | Per-session CA only, HTTP/1.1 only, no broker-followed redirects, no cookies on terminated hosts, rule-driven attachment, buffered push inspection, fail-closed force detection. |
| [[ADR-022 Cedar Schema and Engine as Built]] | Compiled schema (Domain/HostCategory, Repo in Host, segmented Path record, net.* admission), Cedar like for ref globs, bounded record mode, conjunctive repo layer; M1 tables only explain denies. |
| [[ADR-023 OCSF and OTLP Export as Built]] | OCSF 1.9.0 classes verified (4001/4002/6003); pull export from the verified chain as NDJSON, HEC or OTLP/HTTP JSON without the OTel SDK; chain hash in every event. |
| [[ADR-024 Formal Gates as Built]] | Gates on cedar-policy-symcc 0.7.0 + cvc5 1.3.1: credential confinement in the policy text, deny-live as fire/approval/force-opt-in proofs, no forced pushes in record mode, I4 proved on a single-set encoding of the conjunction. |
| [[ADR-025 Native Config Exporters as Built]] | `broker policy export` writes Claude Code managed-settings.json and Codex requirements.toml from the enforced policy (verified vendor schemas); no proxy chaining or MCP allowlist yet. |
| [[ADR-026 Shadow Mode as Built]] | `broker policy shadow <file>` evaluates a candidate broker.toml beside the enforced policy in every enforce session (mode `shadow`), logs its verdict per decision and reports what it would change; it never decides. |
| [[ADR-027 Plain Host Grants Carry No L7 Authority]] | A plain [[egress]] entry is L4 admission only (no `#any` permit); on a host another rule terminates it allows nothing. Fixes a same-host over-grant. |
| [[ADR-028 M2 Plan Items Built Differently or Deferred]] | M2 task list reconciled: grants compile to policy text so gates can prove them; differential test instead of round-trip; per-file-op decisions, process ancestry, G1, P4, extra ceiling categories, profile tables, broker init, LLM explanations deferred. |
| [[ADR-029 GitHub API Adapter and Session Labels as Built]] | GitHub REST requests map to verbs (verified routes; GraphQL denied); `protocol = "github"` grants verbs on repos; the broker looks up visibility with the bound credential and re-decides; raise-only session labels from API facts stop the toxic flow at the public write. |
| [[ADR-030 MCP Guard as Built]] | Pinned stdio MCP servers: named in user/org policy, reached by an in-sandbox stub via the session proxy, started as their own sandboxed session with sentinel credentials, pinned by a digest of their whole tools list, approved on the host, every tools/call authorized; any change revokes. |

## Where the value is

- [[ADR-001 Value Lives in the Broker]] — Put the product's value in the broker (policy, minting, semantics, audit, learning), not in a new isolation primitive, because isolation is mature and shipped by incumbents.
- [[ADR-014 Apache-2.0 Endpoint with Commercial ee]] — License everything on the endpoint Apache-2.0 and keep the fleet control plane in a commercial ee/ directory; reject AGPL and closed source.

## Isolation and platform

- [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]] — Default to the OS process sandbox (Seatbelt; bwrap+seccomp+Landlock) with a microVM as opt-in hard tier, rejecting microVM-by-default and containers.
- [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]] — Use generated Seatbelt profiles on macOS for the MVP with a Virtualization.framework backend as hedge; reject a Network Extension and VM-only.

## Network path

- [[ADR-003 Topology-Enforced Egress]] — Enforce egress by topology (no NIC or loopback-only plus UDS or vsock), rejecting HTTP_PROXY-only and eBPF-redirect-only designs.
- [[ADR-004 Selective TLS Termination with Per-Session CA]] — Terminate TLS only for hosts with credentials or L7 rules using a per-session CA; splice everything else at L4; rejecting MITM-everything and SNI-only.
- [[ADR-006 Deny Unmatched L7 Requests]] — Within an allowed domain, method and path rules are authorization: unmatched L7 requests are denied, rejecting Vercel's pass-without-credential semantics.
- [[ADR-009 Broker-Only DNS Resolution]] — Resolve all names in the broker; the sandbox has no UDP/53 or ICMP; reject filtered UDP/53 passthrough.

## Credentials and grants

- [[ADR-005 Mint Credentials Per Task]] — Mint per-task credentials wherever providers allow and fall back to static sentinel swap; reject static-swap-only and env-var secrets.
- [[ADR-008 Grant Representation as Entities and Txn-Token JWT]] — Represent grants as Cedar entities inside the broker and as a Txn-Token-shaped DPoP-bound JWT across hosts, with Biscuit later for sub-agents; reject Macaroons or Biscuit from day one and opaque handles only.

## Policy

- [[ADR-007 Cedar with a TOML Front-End]] — Use Cedar (Lean-verified, SymCC-analyzable, µs latency, agent-gateway precedent) behind a small TOML layer; reject OPA/Rego, Progent JSON-Schema, Invariant rules and a custom DSL.
- [[ADR-010 Session-Level Trifecta Labels in the MVP]] — Ship session-level trifecta labels sourced from systems of record in the MVP; defer CaMeL-style interpreters and FIDES planners.
- [[ADR-011 Verified Policy Learning Loop]] — Learn policy via record, mine, SymCC, human PR, shadow, enforce; reject auto-applied LLM-synthesized policy and no learning.

## MCP

- [[ADR-012 MCP Servers as Pinned Sandboxed Principals]] — Run MCP servers as pinned, separately sandboxed principals reached by name; reject container gateways (Docker, ToolHive) and Wasm-only (Wassette).

## Implementation

- [[ADR-015 Rust for the Endpoint and Custom Proxy]] — Write the whole endpoint in Rust as one static binary and build a custom tokio/hyper/rustls/rcgen proxy (hudsucker as reference); reject Go and Envoy/mitmproxy for the product path.

## Built during M0

- [[ADR-016 macOS M0 Compatibility Exceptions]] — On macOS in M0, keep the per-user temp dir writable and let only profiles that declare it read the login keychain until M1; both announced, audited and time-boxed.
- [[ADR-017 Landlock Filesystem Layer Required]] — The Landlock filesystem layer is a required Linux layer; only its TCP rules degrade below ABI 4, where the empty netns remains the boundary.
- [[ADR-018 seccomp Filter Shape for M0]] — Keep the proposed seccomp denials, add io_uring, clone3, x32 and TIOCSTI, and allow socketpair(AF_UNIX) and AF_NETLINK.
- [[ADR-019 Mandatory Deny-Write List Additions]] — Protect the .git entry itself (rename-and-replant escape), .mcp.json, .envrc, .gemini, .broker and PATH dirs; placeholders for missing names on Linux.

## Built during M1

- [[ADR-020 Brokered Agent Credentials End the Keychain Exception]] — Agents' own credentials are held by brokerd behind sentinels; agent token files are deny-read; the macOS keychain switch of ADR-016 is removed.
- [[ADR-021 L7 Path Choices for M1]] — Per-session CA only, HTTP/1.1 only, no broker-followed redirects, no cookies on terminated hosts, rule-driven attachment, buffered push inspection, fail-closed force detection.

## Built during M2

- [[ADR-022 Cedar Schema and Engine as Built]] — Compiled schema (Domain/HostCategory, Repo in Host, segmented Path record, net.* admission), Cedar like for ref globs, bounded record mode, conjunctive repo layer; M1 tables only explain denies.
- [[ADR-023 OCSF and OTLP Export as Built]] — OCSF 1.9.0 classes verified (4001/4002/6003); pull export from the verified chain as NDJSON, HEC or OTLP/HTTP JSON without the OTel SDK; chain hash in every event.
- [[ADR-024 Formal Gates as Built]] — Gates on cedar-policy-symcc 0.7.0 + cvc5 1.3.1: credential confinement in the policy text, deny-live as fire/approval/force-opt-in proofs, no forced pushes in record mode, I4 proved on a single-set encoding of the conjunction.
- [[ADR-025 Native Config Exporters as Built]] — `broker policy export` writes Claude Code managed-settings.json and Codex requirements.toml from the enforced policy (verified vendor schemas); no proxy chaining or MCP allowlist yet.
- [[ADR-026 Shadow Mode as Built]] — `broker policy shadow <file>` evaluates a candidate broker.toml beside the enforced policy in every enforce session (mode `shadow`), logs its verdict per decision and reports what it would change; it never decides.
- [[ADR-027 Plain Host Grants Carry No L7 Authority]] — A plain [[egress]] entry is L4 admission only (no `#any` permit); on a host another rule terminates it allows nothing. Fixes a same-host over-grant.
- [[ADR-028 M2 Plan Items Built Differently or Deferred]] — M2 task list reconciled: grants compile to policy text so gates can prove them; differential test instead of round-trip; per-file-op decisions, process ancestry, G1, P4, extra ceiling categories, profile tables, broker init, LLM explanations deferred.
- [[ADR-029 GitHub API Adapter and Session Labels as Built]] — GitHub REST requests map to verbs (verified routes; GraphQL denied); `protocol = "github"` grants verbs on repos; the broker looks up visibility with the bound credential and re-decides; raise-only session labels from API facts stop the toxic flow at the public write.
- [[ADR-030 MCP Guard as Built]] — Pinned stdio MCP servers: named in user/org policy, reached by an in-sandbox stub via the session proxy, started as their own sandboxed session with sentinel credentials, pinned by a digest of their whole tools list, approved on the host, every tools/call authorized; any change revokes.

## How this section connects

- Decisions implement the architecture in [[MOC Architecture]] and are justified by [[MOC Landscape]], [[MOC Research]] and [[MOC Threat Model]].
- Residual risk each decision accepts is tracked in [[Risk Register]].
