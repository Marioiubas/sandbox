---
title: "ADR-030 MCP Guard as Built"
aliases: ["ADR-030"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/mcp, invariant/i1, invariant/i5, invariant/i9, milestone/m3]
status: built
confidence: medium
created: 2026-09-25
updated: 2026-09-25
summary: "Stdio MCP servers are pinned by name in user/org policy, reached by the in-sandbox stub `broker mcp connect <name>` through the session proxy's reserved name, started by the daemon as their own sandboxed session with their own egress grants and sentinel credentials, pinned by a canonical digest of their whole tools list, approved on the host, and relayed with every tools/call authorized; remote servers, `mcp wrap`, argument-schema validation and non-tool capabilities are not built."
related: ["[[MCP Guard]]", "[[ADR-012 MCP Servers as Pinned Sandboxed Principals]]", "[[Trifecta Session Labels]]", "[[I1 No Secrets in the Sandbox]]", "[[I5 Config Outside Writable Mounts]]", "[[postmark-mcp Rug Pull]]", "[[M3 CI Identity and MCP]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
---

# ADR-030 MCP Guard as Built

> The agent can name a pinned server; the daemon decides what runs, what it can reach, and which calls go through, and any change to the server's tools revokes it.

## Status

built (2026-09-25, M3 step 2).

## Context

[[MCP Guard]] specifies pinned stdio servers reached through a stub over the data plane, their own sandbox and principal, manifest hashing before any relay, and per-call authorization; M3's D3 and D4 test it. The sandbox cannot reach `ctl.sock` (by design), so the stub needs a data-plane path.

## Decision

1. **Definition:** `[mcp.<name>]` in user or org policy only (`command` with an absolute executable path, `[[mcp.<name>.egress]]` grants, `tools.write`, `tools.untrusted`, `tools.deny`); repository policy with `[mcp]` is rejected (I5). Names are 1-32 of `a-z0-9-`.
2. **Stub:** `broker mcp connect <name>` (inside the sandbox) opens `CONNECT <name>.mcp.broker.internal:1` on the session's own proxy (with the session's proxy sentinel on macOS) and pipes stdio. Reserved names skip admission, DNS and the network; an undefined name is denied (`mcp_server_unknown`).
3. **Launch:** the daemon starts the pinned command as its own session: synthetic profile `mcp:<name>`, the server's egress grants as its only user layer (credentials reach it as sentinels, swapped only on its egress), a fresh working directory in the temp area (broker state is never writable, I5), no shadow candidate, and no MCP servers of its own. The server session is linked from the agent's `mcp.connect` row (`server_session`).
4. **Pin:** before relaying anything, the daemon sends `initialize`, `notifications/initialized` and `tools/list` (all pages) itself; the digest covers every tool object (`mcpguard::manifest`: keys and tools sorted). No approval → `mcp_manifest_unapproved`; a different approved digest → `mcp_manifest_changed` with a tool-level diff; failures → `mcp_launch_failed`. The seen and approved manifests and the approvals live in the daemon's state directory. `broker mcp approve <name> [--sha …]` on the host shows the diff and every tool description, then approves that exact digest; `broker mcp list` shows the state.
5. **Relay** (strict JSON-RPC 2.0, one frame per line, 1 MiB bound, `mcpguard::frame`): `initialize` and `tools/list` are answered from the pinned state; `ping` answered; `tools/call` must name a pinned tool with object arguments, is authorized as `mcp.call_tool` (the server's permit minus `tools.deny`, the `pinned-mcp-only` forbid, and a new `rule-of-two-mcp` forbid for write tools), written to the audit log before it is forwarded, and raises `external_effect` (write tools) or `untrusted_input` (untrusted tools); `notifications/cancelled` is forwarded. Every other method is denied (`mcp_method_not_allowed`), server-to-client requests (sampling, roots, elicitation) are refused and logged, and `notifications/tools/list_changed` triggers a re-pin that revokes on any change. Denials return JSON-RPC errors naming the reason and the request ID for `broker why`.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Reach the daemon over `ctl.sock` | The sandbox must never reach the control socket. |
| `broker mcp wrap -- <cmd>` (the command on the agent side) | Lets agent-writable config choose the command, which is the CurXecute/MCPoison class; the stub only names a server. Kept out. |
| Hash only name, description and input schema | Annotations and titles also steer agents; hashing the whole tool object is simpler and stricter. |
| Relay resources, prompts and completion | Their content is unlabelled today; deny until they carry labels. |
| Server state directory under broker state | Broker state is never writable by a sandbox (the launcher refused it). |

## Consequences

- D3 and D4 pass against a fake server and API (`m3_mcp::d3_d4_pinned_server_is_approved_confined_and_revoked_on_change`), including I1 for the server principal: its environment holds a sentinel and only its egress carries the real token.
- Not built: remote MCP servers (the broker as OAuth client), `insufficient_scope` step-up, argument validation against the pinned `inputSchema` (arguments are digested into `args_integrity`), resources, prompts and completion, and a per-server `McpServer` Cedar principal for the server's own egress (its session's Task is the principal).
- A server is started per connection; there is no pooling.

## Invariants affected

Upholds I1 (sentinels for server credentials), I5 (definitions and approvals outside every mount; repository `[mcp]` rejected), I7 (the server's egress runs the normal pipeline) and I9 (connect, every call, every refusal and every revocation is a chained row). Weakens none.

## Relationships

- decided-by:: M3 build
- motivated-by:: [[MCP Guard]], [[ADR-012 MCP Servers as Pinned Sandboxed Principals]], [[postmark-mcp Rug Pull]]

## Build log

- 2026-09-25: created and built. Code: `code/crates/mcpguard/src/{frame,manifest}.rs`, `code/crates/brokerd/src/mcp/{mod,relay,pin}.rs`, `code/crates/brokerd/src/session/mcp_launch.rs`, `code/crates/policy/src/mcp.rs`, `code/crates/broker-cli/src/cmd/mcp.rs`, `code/policies/default.cedar` (`rule-of-two-mcp`), `code/tests/conformance/src/bin/fake-mcp-server.rs`. Tests: `mcpguard::frame::tests::*` (strict classifier, oversize, chunking property), `mcpguard::manifest::tests::*` (order-independent digest property, diff), `brokerd::mcp::pin::tests::approvals_are_bound_to_the_digest`, `policy::cedar::github_tests::mcp_calls_decide`, `m3_mcp::*`; fuzz target `mcp_frame` (1.4 M runs locally, in the CI smoke).
