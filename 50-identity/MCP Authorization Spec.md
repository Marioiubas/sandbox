---
title: "MCP Authorization Spec"
aliases: ["RFC 8707", "Resource Indicators", "Token Passthrough Ban", "MCP Stdio Exemption", "MCP Security Best Practices"]
type: "standard"
section: "identity"
summary: "The 2026-07-28 MCP revision: remote servers are OAuth 2.1 resource servers (RFC 9728 metadata, mandatory RFC 8707 resource parameter, audience validation, token-passthrough ban, CIMD over DCR, RFC 9207 iss checks, insufficient_scope step-up) while stdio servers 'retrieve credentials from the environment'; plus the 2025-06-18 security best practices."
tags: [sandbox/identity, standard, topic/mcp, topic/credentials, topic/identity, topic/approval, control/task-tok, control/cred-out, control/pin, boundary/tb4, boundary/tb6, invariant/i1, milestone/m3]
status: verified
confidence: high
milestone: M3
created: 2026-09-24
updated: 2026-09-24
related: ["[[MCP Guard]]", "[[Object Capabilities]]", "[[Sentinel Swap Pattern]]", "[[Okta Cross App Access]]", "[[RFC 8693 Token Exchange]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[ADR-012 MCP Servers as Pinned Sandboxed Principals]]", "[[Credential Injector and Issuers]]", "[[MiniScope]]", "[[I6 Single Canonicaliser]]", "[[GitHub MCP Toxic Flow]]", "[[Tech Stack]]", "[[M3 CI Identity and MCP]]", "[[Open Questions and Unverified Claims]]"]
---

# MCP Authorization Spec

The 2026-07-28 revision of the Model Context Protocol makes remote MCP servers OAuth 2.1 resource servers: clients discover the authorization server through RFC 9728 metadata, must send the RFC 8707 `resource` parameter, servers must validate that tokens were issued for them, token passthrough is banned, Client ID Metadata Documents replace dynamic client registration as preferred, RFC 9207 `iss` checks apply, and runtime step-up is signalled by `insufficient_scope`. The same text tells stdio servers to "retrieve credentials from the environment", which is the secret-in-sandbox pattern the broker exists to remove. The broker is compliant by construction toward remote servers and neutralises the stdio exemption with sentinels.

## Timeline

- 2025-06-18: security best practices published (confused deputy, token passthrough, progressive scopes, SSRF via metadata URLs) ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)).
- 2025-11-25: CIMD and the first authorization extensions, including enterprise-managed authorization via ID-JAG (SEP-990) ([Den Delimarsky](https://den.dev/blog/mcp-november-authorization-spec/)).
- 2026-05-21: release candidate; 2026-07-28: final, "largest revision since launch" ([WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)).

## Normative requirements (2026-07-28)

From [MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization) unless noted:

| Area | Requirement |
|---|---|
| Discovery | RFC 9728 protected-resource metadata is required ([WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)) |
| Resource indicators (alias RFC 8707) | clients "MUST implement Resource Indicators… The `resource` parameter MUST be included in both authorization requests and token requests… MUST use the canonical URI of the MCP server", sent "regardless of whether authorization servers support it" ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)) |
| Audience | servers "MUST validate that access tokens were issued specifically for them as the intended audience" |
| Passthrough ban | "MCP clients MUST NOT send tokens to the MCP server other than ones issued by the MCP server's authorization server"; "MCP servers MUST NOT accept or transit any other tokens" |
| Token placement | `Authorization: Bearer`, never the query string |
| Client identity | CIMD preferred, DCR deprecated; `application_type` must be declared ([WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)) |
| Issuer check | clients record the expected issuer and validate `iss` in the authorization response per RFC 9207 |
| Step-up | server returns **403** with `WWW-Authenticate: Bearer error="insufficient_scope", scope="…", resource_metadata="…"`; the client re-authorizes with the **union** of previous and challenged scopes |
| Refresh | refresh-token and step-up scope accumulation formalised ([WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)) |
| Extensions | optional, additive, composable; listed in the `modelcontextprotocol/ext-auth` repo |
| **stdio** | "Implementations using an STDIO transport **SHOULD NOT** follow this specification, and instead retrieve credentials from the environment." |

Example step-up challenge (header grammar from the spec; values illustrative):

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="issues:read issues:write",
  resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
```

## Security best practices (2025-06-18) the broker inherits

From [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices):

- **Confused deputy** is a named attack on MCP proxy servers that use a static OAuth client ID plus dynamic client registration plus consent cookies; mitigations are per-client consent, exact redirect-URI match and single-use `state` (see [[Object Capabilities]]).
- **Token passthrough** is forbidden because it circumvents controls, breaks audit trails and turns the server into an exfiltration proxy.
- **Progressive least-privilege scopes:** minimal initial scope, incremental elevation via `WWW-Authenticate scope=` challenges, no wildcard or omnibus scopes.
- **SSRF via OAuth metadata URLs** (cloud metadata 169.254.169.254, DNS-rebinding TOCTOU); the document recommends egress proxies such as Smokescreen. The broker's canonicaliser and metadata-IP deny are that proxy ([[I6 Single Canonicaliser]]).

## The broker's three handling modes

**Proposal** (report "MCP authorization makes the broker compliant by construction, except for stdio").

1. **Toward remote MCP servers**, the broker is a full MCP client: PRM discovery, CIMD client ID, PKCE plus `resource`, `iss` checks. It holds the tokens and injects `Authorization: Bearer` at egress, so the in-sandbox MCP client holds only a sentinel.
2. **For stdio servers**, which "read from env", it replaces env secrets with sentinels and swaps them back only on the server's egress to its upstream API; each server runs in its own sandbox as a separate principal ([[Sentinel Swap Pattern]]; [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]). This neutralises the stdio exemption without modifying the server.
3. **On `insufficient_scope`**, it treats the challenge as the natural approval hook: pause, show the authority diff (the added scopes), and re-authorize with the union of scopes only after approval ([[Fatigue-Resistant Approval Interfaces]]).

Because the broker mints a fresh audience-bound token per upstream, it satisfies the passthrough ban; it must not forward the user's Okta/Entra token to MCP servers but exchange it via ID-JAG/XAA or RFC 8693 ([[Okta Cross App Access]]; [[RFC 8693 Token Exchange]]).

MiniScope's tool-graph-derived incremental permissions align with the spec's progressive scopes ([[MiniScope]]).

## Sharp edges

- The spec protects the server from foreign tokens; it does nothing about a *legitimately* scoped token misused by an injected agent (the GitHub MCP toxic flow), which needs broker-side trifecta rules ([[GitHub MCP Toxic Flow]]).
- Step-up with scope *union* only ever widens; the broker must make each widening an explicit, audited approval rather than an automatic retry.
- Tool descriptions are not covered by authorization; pinning and re-approval on change live in [[MCP Guard]].

## Verdict for the broker

**Proposal.**

- **Use it for:** the broker's remote-MCP client implementation (spec-conformant OAuth 2.1), the step-up approval hook, and as the normative justification for never forwarding IdP tokens.
- **Don't use it for:** stdio servers (the spec itself exempts them; use sentinels); fine-grained tool-argument authorization (Cedar `mcp.call_tool` does that).
- **How we integrate it.** In [[MCP Guard]] (`crates/mcpguard`) and [[Credential Injector and Issuers]]: an OAuth 2.1 client with PKCE, RFC 9728 discovery, CIMD, `resource` on every request and RFC 9207 `iss` validation (OAuth crate choice unverified, [[Tech Stack]]); tokens cached per MCP server `resource`; 403 `insufficient_scope` parsed into a `grant.request` step-up on the control socket.

## How it connects

- delivered-by:: [[MCP Guard]]
- delivered-by:: [[Credential Injector and Issuers]]
- motivated-by:: [[Object Capabilities]] (confused deputy)
- depends-on:: [[Sentinel Swap Pattern]] (stdio exemption)
- depends-on:: [[Okta Cross App Access]] (SEP-990)
- depends-on:: [[RFC 8693 Token Exchange]] (no IdP-token forwarding)
- depends-on:: [[Fatigue-Resistant Approval Interfaces]] (step-up as approval)
- decided-by:: [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]
- contrasts-with:: [[MiniScope]] (incremental permissions from tool graphs)
- delivered-by:: [[M3 CI Identity and MCP]]

## Implications for the build

- M3: a wrapped GitHub MCP server can read issues but cannot reach non-allowlisted hosts; a changed tool description revokes it; the GitHub MCP toxic flow replay is stopped at the public write ([[M3 CI Identity and MCP]]).
- Tests: remote MCP requests always carry `resource`; tokens from one server are never sent to another; an `iss` mismatch aborts; a 403 `insufficient_scope` produces a step-up prompt, not a silent retry.

## Open questions

- The full ext-auth extension list as of 2026-07-28 (for example whether a DPoP or workload-identity extension exists) was not enumerated ([[Open Questions and Unverified Claims]]).

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
