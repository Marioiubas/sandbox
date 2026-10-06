---
title: "ADR-047 MCP Pin Covers What Reaches the Agent"
aliases: ["ADR-047"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/mcp, topic/supply-chain, invariant/i5, invariant/i9, milestone/m3]
status: built
confidence: medium
created: 2026-10-06
updated: 2026-10-06
summary: "A pinned MCP server's manifest digest covers its command by content (executable, a script's interpreter, every file argument), the fixed projection of its initialize result the relay forwards (protocolVersion, serverInfo name/title/version, instructions; capabilities fixed to tools), and every tool object; a changed command refuses the start, a command naming a path the agent can write is never started, nothing reaches the agent from an unpinned server, only progress for the agent's own calls is forwarded, and `broker mcp approve` shows all of it in full, escaped."
related: ["[[ADR-030 MCP Guard as Built]]", "[[MCP Guard]]", "[[ADR-012 MCP Servers as Pinned Sandboxed Principals]]", "[[ADR-037 Step-Up Approvals as Built]]", "[[I5 Config Outside Writable Mounts]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[postmark-mcp Rug Pull]]", "[[Cursor CurXecute and MCPoison]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[MOC Decisions]]"]
sources: ["https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-06-18/schema.ts"]
superseded_by: 
---

# ADR-047 MCP Pin Covers What Reaches the Agent

> Everything a pinned MCP server puts in front of the agent, and the code that produces it, is in the digest the user approves; anything else is not relayed.

## Status

built (2026-10-06). Amends [[ADR-030 MCP Guard as Built]] items 3 to 5. Written from a configuration-trust review (findings F7 to F10).

## Context

ADR-030 pinned the digest of a server's tool list only. A review found four gaps:

- **F7 (medium):** the relay answered the agent's `initialize` with the server's own result. Its `instructions` field is "Instructions describing how to use the server and its features ... this information MAY be added to the system prompt" ([MCP schema 2025-06-18](https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-06-18/schema.ts)), so a server could change what the model is told after approval without revocation (the [[postmark-mcp Rug Pull]] through a field ADR-030 did not list), and `broker mcp approve` never showed it.
- **F8 (low):** server notifications other than `tools/list_changed` reached the agent whatever the pin state, e.g. `notifications/message` text from a server the user never approved.
- **F9 (medium):** the command was pinned by path. A server such as `python3 /proj/tools/srv.py` whose script lives in the agent's writable project could be rewritten by the agent to serve the same tools; the pin still matched, and agent-controlled code ran with the server's egress grants and credentials (the approval-bound-to-a-name class of [[Cursor CurXecute and MCPoison]]).
- **F10 (low):** the approve view cut descriptions at 300 characters and named changed `inputSchema`, `annotations` or `title` fields without showing them.

## Decision

1. **The manifest has three parts, one digest** (`mcpguard::manifest::build`): `command`, `server` and `tools`, hashed over canonical JSON. Any change to any part revokes the server (`mcp_manifest_changed`, with a diff naming the part: `~ command file <path>: content changed`, `~ server instructions: changed`, `~ tool <name>: … changed`). Approvals stored before this ADR have no `command` or `server` part, so every server needs one re-approval after upgrade (its start is not gated by the missing command pin; it is refused until approved, as an unapproved server is).
2. **What the agent receives at `initialize` is a fixed projection** (`forwarded_init`): `protocolVersion` (required string), `serverInfo` reduced to its `name`, `title` and `version` strings, `instructions` (string), and `capabilities` fixed by the relay to `{"tools": {}}` (it relays tools only and handles list changes itself). Everything else (`_meta`, other capabilities, icons, unknown fields) is dropped. A listed field of the wrong type makes the server unpinnable (`mcp_launch_failed`) rather than guessed at. The projection is the manifest's `server` part, so the digest covers exactly what is forwarded; a re-listing after `tools/list_changed` keeps the pinned `command` and `server` parts and re-reads only the tools.
3. **The command is pinned by content** (`brokerd::mcp::command`): right before the exec, the daemon takes SHA-256 of the executable, of the interpreter a `#!` script names, of every argument that names an existing regular file (relative ones resolved against the server's working directory), and of the value of a `--flag=value` argument that does; `argv` itself is part of the pin. Once a manifest with a command part is approved, a different pin refuses the start: the server never runs, the change is logged on the `mcp.connect` row (`mcp_manifest_changed`, `server_session` empty) and a `launch_refused` row, and the seen manifest becomes the new command with the previously approved server and tools, so one `broker mcp approve` lets the new code start (anything else it then serves is a change again).
4. **Nothing the agent can write is started** (`mcp_command_writable`, a new reason): a command whose executable, interpreter or any argument names a path (file or directory, existing or not) inside a writable mount of the agent session that connects (its compiled filesystem policy: project, session temp, granted state directories) is refused before it runs, whatever the approval state. The check walks every symbolic link the kernel would follow and refuses if any link location or the target is writable. This is the check that closes the time between the hash and the exec; the hash catches every other writer between approvals.
5. **Nothing reaches the agent from a server that is not pinned** (unapproved, changed, refused, revoked mid-connection): not notifications, not results. A call forwarded before a revocation is answered with a denial instead of its result. From a pinned server the agent receives replies to its own calls and `notifications/progress` for a pending call's `progressToken`, rebuilt from `progressToken`, `progress` and `total` (the free-text `message` is not pinned, so it is dropped). Every other notification is dropped and logged once per method per connection (at most 64 methods); `tools/list_changed` still triggers the re-pin.
6. **`broker mcp approve` shows the full content it pins**: the diff, the command (`argv` and every file digest), the forwarded `initialize` result and every field of every tool (description, title, schemas, annotations, `_meta`, anything else), never truncated. Every server-written string goes through `terminal_safe` (moved to `broker-cli/src/cmd/term.rs`, shared with `broker approve`): C0/C1 controls, bidi embeddings, overrides and isolates (U+202A to U+202E, U+2066 to U+2069), zero-width characters and line separators are escaped; names and diff lines are kept on one line, and multi-line text is shown line by line behind `| `, so no server text can pass for a line of the view.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Pin the server's whole `initialize` result and forward it | Pins fields the agent does not need (`_meta`, logging and resource capabilities the relay refuses anyway); a fixed projection forwards less and pins exactly that. |
| Hash file arguments only at approval time | The agent can rewrite a script after approval; the hash must be re-checked at every start, right before the exec. |
| Rely on the hash alone, allowing commands inside writable mounts | The agent can change a file between the hash and the exec, or create a named file that did not exist at the check. Refusing such commands is stricter; real configurations install servers outside the project (the real GitHub MCP run's binary lives outside its work tree). |
| Refuse at config validation | Validation does not know which agent session, and so which mounts, will connect; the check runs per connection with that session's policy. |
| Run a changed command once to learn its new tools for the approval view | That runs the code the pin is meant to stop, with the server's grants and credentials. |
| Forward server log messages and other notifications | Their text is unpinned content in front of the model; progress numbers for the agent's own calls are the only notification forwarded. |

## Consequences

- Tests: `mcpguard::manifest::tests::*` (forwarded projection, digest covers command and server, `changes`), `brokerd::mcp::command::tests::*` (content pin, interpreter, relative and `--flag=` arguments, writable refusal including links and missing paths, gate), `brokerd::mcp::relay::tests::review_server_instructions_that_reach_the_agent_are_pinned`, `review_an_unapproved_server_sends_the_agent_nothing`, `only_permitted_calls_reach_the_server` (now also: nothing from an unapproved server reaches the agent), `brokerd::mcp::relay::tests::from_server::*`, `brokerd::mcp::pin::tests::approvals_are_bound_to_the_digest`, `broker-cli` `cmd::mcp_view::tests::*` and `cmd::term::tests::*`. Conformance `m3_mcp` D4 now rewrites a description inside a directory argument (tool-level revocation) and adds a session in which a rewritten file argument stops the server from starting.
- Every existing approval is revoked once by the upgrade (the digest format changed).
- **Not covered:** modules an interpreter imports, files beneath a directory argument and anything a server reads at run time are not hashed; keeping them outside every agent's writable mounts is documented (`code/docs/policy-reference.md`), not enforced. Commands are re-hashed at every connection (no cache keyed on metadata an attacker could preserve). A file writable by something other than the connecting agent session can still change in the moment between the hash and the exec.
- `broker mcp list` is unchanged; it reports `CHANGED since approval` for any part.

## Invariants affected

Upholds I5 (what the approval covers is now everything that reaches the agent, and code the agent can write is never run as a pinned server) and I9 (refused starts, revocations, withheld results and dropped notifications are chained rows). Weakens none.

## Relationships

- decided-by:: configuration-trust review, 2026-10-06
- amends:: [[ADR-030 MCP Guard as Built]]
- motivated-by:: [[postmark-mcp Rug Pull]], [[Cursor CurXecute and MCPoison]], [[Fatigue-Resistant Approval Interfaces]]

## Build log

- 2026-10-06: created and built. Code: `code/crates/mcpguard/src/manifest.rs` (+ `manifest_tests.rs`), `code/crates/brokerd/src/mcp/{command,from_server,relay,mod,pin}.rs` (+ `command_tests.rs`, `from_server_tests.rs`), `code/crates/brokerd/src/session/{mcp_launch,launch}.rs`, `code/crates/audit/src/reason.rs` (`mcp_command_writable`), `code/crates/broker-cli/src/cmd/{mcp,mcp_view,term,approve}.rs`, `code/tests/conformance/{src/bin/fake-mcp-server.rs,tests/m3_mcp.rs}`, `code/docs/policy-reference.md`.
