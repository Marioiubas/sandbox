---
title: "MCP Guard"
aliases: ["mcpguard", "MCP Adapter", "Tool Pinning", "MCP Tool Poisoning"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/mcp, topic/credentials, topic/supply-chain, topic/isolation, control/pin, control/iso, control/cred-out, boundary/tb6, invariant/i1, invariant/i5, milestone/m3]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "mcpguard: pinned MCP servers defined only in user/org config, reached by name via broker mcp connect, launched by brokerd in their own sandbox as separate McpServer principals with sentinel env; tools/list hashed and any change revokes grants; tools/call authorized with arguments; the broker acts as full OAuth client toward remote servers."
related: ["[[ADR-012 MCP Servers as Pinned Sandboxed Principals]]", "[[MCP Authorization Spec]]", "[[postmark-mcp Rug Pull]]", "[[Cursor CurXecute and MCPoison]]", "[[ACE and IsolateGPT]]", "[[Two-Tier Isolation Design]]", "[[Sentinel Swap Pattern]]", "[[Broker Cedar Schema]]", "[[M3 CI Identity and MCP]]", "[[MCP Gateways]]", "[[Measurement Gaps]]", "[[Broker CLI and Daemon]]", "[[Sandbox Launcher]]", "[[Core Trait Contracts]]", "[[Policy Engine and Entity Builder]]", "[[Credential Injector and Issuers]]", "[[Trifecta Session Labels]]", "[[GitHub MCP Toxic Flow]]", "[[I1 No Secrets in the Sandbox]]", "[[I5 Config Outside Writable Mounts]]", "[[Wasmtime and WASI]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[Request and Session Lifecycle]]", "[[Conformance Probe Matrix]]", "[[RFC 8693 Token Exchange]]", "[[Okta Cross App Access]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://modelcontextprotocol.io/specification/latest/basic/authorization", "https://workos.com/blog/mcp-2026-spec-agent-authentication", "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks", "https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html", "https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison", "https://arxiv.org/abs/2403.04960", "https://arxiv.org/abs/2504.20984", "https://github.com/microsoft/wassette", "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices", "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html", "https://invariantlabs.ai/blog/mcp-github-vulnerability"]
milestone: M3
---

# MCP Guard

> mcpguard: pinned MCP servers defined only in user/org config, reached by name via broker mcp connect, launched by brokerd in their own sandbox as separate McpServer principals with sentinel env; tools/list hashed and any change revokes grants; tools/call authorized with arguments; the broker acts as full OAuth client toward remote servers.

## Responsibility

`crates/mcpguard` (stdio relay, manifest pinning, `tools/call` policy) plus the `mcp` adapter in `crates/l7/src/adapters/` for MCP over HTTP ([[Core Trait Contracts]]). It enforces trust boundary TB6 (tool supply chain ↔ registry: "manifest hash pinning; re-approval on change") and answers the config-rewrite class structurally (report):

- "Pinned MCP servers are defined only in user or org config, never in the repo. The agent's MCP configuration points at a stub (`broker mcp connect <name>`) that speaks over the data plane. `brokerd` then launches the *pinned* command for that name in its own sandbox, as a separate `McpServer` principal with sentinel env vars and its own egress policy."
- "Before relaying anything, the guard hashes `tools/list` (names, schemas and descriptions). Any change revokes the server's grants until re-approved." Each `tools/call` is authorized with its arguments.
- "The agent can name a server but cannot choose its command. Writing a new `mcp.json` therefore buys an attacker nothing." For hosts that launch servers themselves, `broker mcp wrap -- <cmd>` applies the same treatment (research note 05: `broker mcp wrap -- npx @modelcontextprotocol/server-github`).

**It must never:** launch a command taken from the repo or from agent-writable config; relay any message before the manifest hash matches the approved one; put a real secret in a server's environment; forward a user's IdP token to an MCP server; accept or relay a token not issued for the server's audience; let a server reach hosts outside its own egress policy.

## Why

- **Rug pulls and shadowing.** Invariant Labs showed malicious descriptions making agents leak `~/.cursor/mcp.json` and SSH keys, servers changing descriptions after approval ("rug pull"), and one server's description overriding another's tool behaviour ("shadowing"); mitigations include "tool pinning via hashes" and cross-server boundaries ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)). postmark-mcp's rug-pull update BCC'd every email ([The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)); see [[postmark-mcp Rug Pull]]. Research note 02: an approved tool's description is part of the trusted computing base, so any change must revoke every capability derived from it.
- **Approval bound to names.** In CurXecute and MCPoison the agent could write `.cursor/mcp.json`, and approval was bound to the MCP name, not its contents ([Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)); see [[Cursor CurXecute and MCPoison]].
- **The stdio exemption.** The MCP spec says stdio implementations "SHOULD NOT follow this specification, and instead retrieve credentials from the environment" ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)), which is the secret-in-sandbox pattern.
- **Per-app isolation.** IsolateGPT puts each app in its own spoke with <30% overhead for three-quarters of queries ([arXiv 2403.04960](https://arxiv.org/abs/2403.04960)); ACE shows planning-integrity attacks that break it ([arXiv 2504.20984](https://arxiv.org/abs/2504.20984)). The report's "Add" is "each MCP server as a separate sandbox principal with separate credentials" ([[ACE and IsolateGPT]]).

## Three handling modes (report, **Proposal**)

1. **Remote MCP servers.** The broker acts as a full MCP client: resource-metadata discovery, CIMD client ID, PKCE plus `resource`, and `iss` checks. It holds the tokens and injects `Authorization: Bearer` at egress, so the in-sandbox client holds only a sentinel. The 2026-07-28 spec makes RFC 9728 metadata and RFC 8707 `resource` mandatory and prefers CIMD over DCR ([WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)); servers "MUST NOT accept or transit any other tokens" ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)). Because the broker mints a fresh audience-bound token per upstream, it satisfies the passthrough ban; enterprise tokens are exchanged, not forwarded ([[RFC 8693 Token Exchange]], [[Okta Cross App Access]]). Details in [[MCP Authorization Spec]].
2. **Stdio servers.** Env secrets become sentinels, swapped back only on the server's egress to its upstream API ([[Sentinel Swap Pattern]]).
3. **`insufficient_scope`.** A 403 with `WWW-Authenticate: Bearer error="insufficient_scope"` is the approval hook: pause, show the authority diff, re-authorize with the union of scopes ([[Fatigue-Resistant Approval Interfaces]]).

## Inputs and outputs

- **Inputs:** JSON-RPC frames from the agent via the stub (stdio) or via the L7 path (HTTP); pinned server definitions from user/org config; approvals.
- **Outputs:** relayed frames; `mcp.call_tool` Cedar requests; label updates (`untrusted_input`, `external_effect`) for [[Trifecta Session Labels]]; audit events (`mcp.launch`, `mcp.manifest_changed`, `mcp.call_tool`).

## Interface

**Proposal; not compiled.**

```rust
pub enum Transport { Stdio { command: Vec<std::ffi::OsString> }, Remote { url: CanonicalUrl } }

pub struct PinnedServer {
    pub name: String,                                   // the capability name the agent may use
    pub transport: Transport,
    pub env: BTreeMap<String, CredentialBinding>,       // becomes sentinels in the server sandbox
    pub egress: Vec<EgressRule>,                        // the server principal's own policy
    pub manifest_sha256: Option<[u8; 32]>,              // None until first approval
    pub scope: ConfigScope,                             // User | Org; Repo is rejected at load
}

/// sha256 over canonical JSON of tools sorted by name: [{name, inputSchema, description}]
pub fn manifest_hash(tools: &[serde_json::Value]) -> anyhow::Result<[u8; 32]>;

pub enum PinState { AwaitingApproval([u8; 32]), Pinned([u8; 32]), Revoked { expected: [u8; 32], got: [u8; 32] } }

impl ProtocolAdapter for McpAdapter {               // MCP over HTTP; stdio uses the same classifier
    fn claims(&self, host: &CanonicalHost, head: &http::request::Parts) -> bool;
    async fn classify(&self, req: &mut BufferedRequest, s: &SessionCtx) -> anyhow::Result<Vec<AuthzRequest>>;
}
```

User or org config (**Proposal**; values illustrative):

```toml
[mcp.github]
command = ["npx", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = { kind = "github_app", permissions = { issues = "read" }, repos = ["${repo_remote}"] } }
egress = ["api.github.com"]
tools.write = ["create_issue", "create_pull_request"]   # sets external_effect; org-classified, not server-declared

[mcp.tracker]
url = "https://mcp.tracker.example/mcp"                  # remote: broker is the OAuth client
```

The agent's MCP config contains only the stub: `{"command": "broker", "args": ["mcp", "connect", "github"]}`.

Data-channel and control messages (**Proposal**):

```json
{"jsonrpc":"2.0","id":1,"method":"mcp.connect","params":{"name":"github"}}
{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"manifest_changed",
 "data":{"server":"github","expected":"9f2c…","got":"41ab…","diff":["~ tool send_email: description changed"]}}}
```

Re-approval goes over `ctl.sock` as `grant.request {session_id, action: "mcp.approve", resource: "Broker::McpServer::\"github\"", rationale}` so it is only reachable by the human's CLI ([[Broker CLI and Daemon]]).

Cedar (from the report's example policies and schema, [[Broker Cedar Schema]]):

```cedar
forbid (principal, action == Broker::Action::"mcp.call_tool", resource) unless { resource.pinned };
```

## Internal design

**Proposal.**

1. **Launch.** On `mcp.connect <name>`, look up the name in user/org config only; unknown name → deny. Launch the pinned command through [[Sandbox Launcher]] in its own standard-tier sandbox with sentinel env, its own egress endpoint and its own `SessionId` linked to the parent session.
2. **Pin.** Send `initialize` and `tools/list` from the guard itself; compute `manifest_hash`; compare with the approved hash. Mismatch → `Revoked`: all derived grants dropped, calls denied, `mcp.manifest_changed` logged with a structured diff.
3. **Relay.** Parse every frame with a bounded JSON-RPC parser. `tools/list` responses returned to the agent are the pinned ones. On `tools/call`, check the tool exists in the pinned manifest, validate arguments against its pinned `inputSchema`, and build `mcp.call_tool` with `McpCtx { session, tool, args_integrity }` plus argument attributes. Precedent: AgentCore generates its Cedar schema from tool definitions with tool inputs in context ([AWS docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html)).
4. **Labels.** Results from tools designated as reading untrusted content set `untrusted_input`; org-classified write tools set `external_effect` ([[Trifecta Session Labels]]).
5. **Server egress.** The server's own outbound traffic runs the normal pipeline under its principal and egress list; sentinels are swapped only there.
6. **Remote servers.** The broker runs the OAuth flow itself and fetches metadata URLs through its own canonicaliser and DNS policy, since the MCP security best practices list SSRF via OAuth metadata URLs (cloud metadata 169.254.169.254, DNS rebinding) ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)).

**Hard tier.** The report's local-MCP row offers pure-logic tools as WASM components hosted by the broker, with `wasi:http` implemented by the broker (the Wassette model), but Wassette is "not production ready" ([microsoft/wassette](https://github.com/microsoft/wassette)) and most servers are Node or Python, so the process sandbox is the default ([[Two-Tier Isolation Design]], [[Wasmtime and WASI]]).

## State

Per session: `PinState` per server, child sandbox handles, sentinel bindings, OAuth tokens for remote servers (memory only). Persistent: approved `(scope, name, manifest_sha256, approved_by, approved_at)` rows in the approval store, outside every mount ([[I5 Config Outside Writable Mounts]]).

## Failure modes and fail-closed behaviour

- Unknown server name, repo-scope definition, or launch failure: deny `mcp.connect`.
- Manifest mismatch or `tools/list` unparseable: revoke; nothing relayed.
- Oversized or malformed frame, unknown tool, schema-invalid arguments: deny the call, keep the server.
- OAuth failure, `iss` mismatch, or token for another audience: deny.
- `brokerd` crash: stub and server lose their channel; nothing reaches upstreams.

## Security considerations

- **Descriptions are untrusted until pinned**, and pinning covers integrity, not honesty: a malicious server can be pinned malicious. Review shows the full description text, not a name.
- **Shadowing** is only partly addressed: the broker controls which servers exist and what they can reach, not how the agent's planner combines descriptions (research note 02).
- **Argument-level exfiltration.** A tool that sends data (the postmark BCC) needs semantic rules on arguments, such as recipient constraints; the report lists "semantic recipient rules" as a stopping control.
- **Toxic flows.** The GitHub MCP toxic flow used an all-repo PAT ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)); one-repo minted tokens plus the Rule of Two forbid stop it at the public write ([[GitHub MCP Toxic Flow]]).

## Performance budget

Per `tools/call`: JSON parse, schema validation and one Cedar call, well under the warm p50 ≤5 ms budget. Server launch shares the ≤150 ms native sandbox start budget. Manifest hashing runs once per connect.

## Invariants upheld

[[I1 No Secrets in the Sandbox]] (sentinel env for servers), [[I5 Config Outside Writable Mounts]] (definitions and approvals outside mounts, hash-bound), I7 (foreign tokens rejected on server egress), I9 (every launch, revocation and call logged).

## Test plan

- **Unit:** `manifest_hash` canonicalisation (order-insensitive over tools; any byte change in a name, schema or description changes the hash); config loader rejects repo-scope servers.
- **Property:** no frame is relayed while `PinState` is not `Pinned`; decisions for `tools/call` equal the Cedar result on the built context.
- **Fuzz:** `tests/fuzz/fuzz_targets/jsonrpc.rs` for the frame parser.
- **E2E** ([[M3 CI Identity and MCP]]): `tests/e2e/mcp_github_wrap` (issue read succeeds; every non-allowlisted connection denied), `tests/e2e/mcp_rug_pull` (modified `tools/list` revokes; calls denied and logged), `tests/e2e/toxic_flow_replay` (stopped at the public write).
- **Conformance:** categories 1, 2, 9 and 10 extended to MCP servers as principals, including writes to `mcp.json` ([[Conformance Probe Matrix]]).

## Crates

`mcpguard`, `l7` (`adapters/mcp.rs`), `launcher`, `creds`, `policy`; `serde_json`; a JSON Schema validator and an OAuth 2.1 client library, neither selected in the record.

## Delivering milestone

[[M3 CI Identity and MCP]]: `wrap.rs`, `relay.rs`, `manifest_pin.rs`, `tools_call.rs`, stdio sentinel swap. Remote-server OAuth client follows when a design partner needs it.

## How it connects

- decided-by:: [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]
- implements:: [[MCP Authorization Spec]]
- implements:: [[Sentinel Swap Pattern]]
- implements:: [[Core Trait Contracts]]
- mitigates:: [[postmark-mcp Rug Pull]]
- mitigates:: [[Cursor CurXecute and MCPoison]]
- mitigates:: [[GitHub MCP Toxic Flow]]
- motivated-by:: [[ACE and IsolateGPT]]
- depends-on:: [[Two-Tier Isolation Design]]
- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[Broker Cedar Schema]]
- contrasts-with:: [[MCP Gateways]]
- evaluated-by:: [[Conformance Probe Matrix]]
- delivered-by:: [[M3 CI Identity and MCP]]

## Implications for the build

- The report's schema lists `Task` as the only principal while the text calls each server "a separate `McpServer` principal". **Proposal:** extend `http.*` and `credential.use` `appliesTo` principals to `[Task, McpServer]` in an ADR under ADR-012, so server egress is authorized as the server, not as the agent's task.
- `McpCtx` carries only `tool` and `args_integrity`; argument constraints need per-server generated context types from the pinned `inputSchema`.
- Unlike container gateways ([[MCP Gateways]]), this needs no container runtime; keep it that way.

## Open questions

- The base rate at which real MCP servers change tool descriptions is unmeasured, so re-approval friction is unknown ([[Measurement Gaps]]).
- Whether server-declared tool annotations may ever narrow (never widen) the org's read/write classification.
- How to express recipient-style argument rules generically across servers ([[Open Questions and Unverified Claims]]).

## Sources

- https://modelcontextprotocol.io/specification/latest/basic/authorization
- https://workos.com/blog/mcp-2026-spec-agent-authentication
- https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html
- https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison
- https://arxiv.org/abs/2403.04960
- https://arxiv.org/abs/2504.20984
- https://github.com/microsoft/wassette
- https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html
- https://invariantlabs.ai/blog/mcp-github-vulnerability
- Report: "MCP guard: servers are principals, names are capabilities", "MCP authorization makes the broker compliant by construction, except for stdio", adapter "MCP over HTTP and stdio", local MCP servers row, M3 acceptance, decisions table; research notes 02 Q3 and 03 Q2, 05 §3.2.
