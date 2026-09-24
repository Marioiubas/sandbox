---
title: "Supabase MCP Token Leak"
aliases: ["Supabase MCP"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/mcp, topic/credentials, topic/ifc, control/cred-out, control/task-tok, control/audit, control/hitl, adversary/a1, boundary/tb4, invariant/i1]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Cursor plus Supabase MCP running as service_role (bypasses RLS) followed a support-ticket injection and copied integration_tokens back into the ticket thread (Jul 2025)."
related: [AUTO]
sources: [AUTO]
---

# Supabase MCP Token Leak

A developer used Cursor with the Supabase MCP server to read support tickets; the MCP server ran with the `service_role` key, which bypasses Row Level Security by design. An attacker's ticket instructed the agent to read a private `integration_tokens` table and write the contents back into the ticket thread, where the attacker could read them. The exfiltration "channel" was a write into the same database, so the incident shows that writes to externally readable sinks must count as egress.

## Timeline

- **~6–8 Jul 2025**: demonstrated by General Analysis ([General Analysis](https://generalanalysis.com/blog/supabase-mcp-blog)); framed as the "lethal trifecta" by Simon Willison on 6 Jul 2025 ([Simon Willison](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/)).
- Supabase's mitigation: read-only mode by default ([Simon Willison](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/)); further recommended settings `read_only=true`, a fixed `project_ref`, feature/tool-group limits and tool-call review ([General Analysis](https://generalanalysis.com/blog/supabase-mcp-blog)).

## What happened

1. The attacker submitted a support ticket whose body contained instructions addressed to "CLAUDE within cursor".
2. The developer asked the agent for recent tickets; the agent read the ticket through the Supabase MCP server.
3. Running as `service_role`, the agent could read every table, including `integration_tokens`.
4. It inserted the token values as a new message in the support thread, which the attacker could see ([General Analysis](https://generalanalysis.com/blog/supabase-mcp-blog)).

Willison argued that read-only mode still leaves risk and that the documentation should warn prominently about prompt injection ([Simon Willison](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/)).

## Root cause

- **(a) untrusted input steering tools** plus **(b) over-broad standing credential** (a god-mode database role).
- The exfiltration path was a write back into the same database; no network egress control would have seen it.
- Adversary **A1**. Shape: [[Lethal Trifecta]].

## Impact

Disclosure of third-party integration tokens to the attacker, which in turn gives access to whatever those tokens authorise. Demonstrated, not reported as exploited in the wild.

## Stopping control in this design

- **Would have prevented: CRED-OUT + TASK-TOK.** The `service_role` key never enters the MCP server's environment; the broker holds it ([[I1 No Secrets in the Sandbox]], [[Credential Injector and Issuers]]). **Proposal.** Where the provider allows, mint a read-only, RLS-respecting, table-scoped credential for the task ([[Just-in-Time Credential Minting]]); where it does not, the broker's method/path allowlist on the database API *is* the scope.
- **Would have prevented: sink control.** **Proposal.** Writes to a table readable by an external party are classified as `external_effect`, so after the session read an untrusted ticket (`untrusted_input`) and a sensitive table (`sensitive_read`), the write needs approval ([[Trifecta Session Labels]]).
- **Would have contained: MCP guard, AUDIT, HITL.** The MCP server runs as its own sandboxed principal with its own egress policy and per-call authorization of `tools/call` arguments ([[MCP Guard]]); every call is logged; HITL on writes.

## Regression test

- **Category 2 (credential exposure)**: scan the wrapped MCP server's environment, files, argv and `/proc` for the canary database key; only sentinels may appear.
- **MCP fixture**: a mock database MCP server with a "tickets" table carrying an injection and a "tokens" table; assert the insert of token material into the tickets table is denied (trifecta) and logged.
- **Unit**: a tool call classified as a write to an externally readable sink sets `external_effect`.

## How it connects

- mitigated-by:: [[I1 No Secrets in the Sandbox]]
- mitigated-by:: [[Credential Injector and Issuers]]
- mitigated-by:: [[Just-in-Time Credential Minting]]
- mitigated-by:: [[Trifecta Session Labels]]
- mitigated-by:: [[MCP Guard]]
- example-of:: [[Lethal Trifecta]]
- part-of:: [[Threat Model Overview]]

## Implications for the build

- Stdio MCP servers get sentinel env vars; the real key is swapped in only on the server's egress to its upstream API ([[Sentinel Swap Pattern]]).
- The MCP guard needs a way to declare which tools write to externally readable sinks (a per-server profile), because the broker cannot infer readability of an arbitrary table.
- Ship a Supabase-style profile that defaults to read-only operations.

## Open questions

- Whether Supabase offers a mintable, table-scoped credential suitable for per-task issuance is not in the record ([[Open Questions and Unverified Claims]]).

## Sources

- [General Analysis](https://generalanalysis.com/blog/supabase-mcp-blog)
- [Simon Willison, Supabase MCP lethal trifecta](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/)
