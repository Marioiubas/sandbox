---
title: "M3 CI Identity and MCP"
aliases: ["M3"]
type: milestone
section: build
tags: [sandbox/build, milestone, milestone/m3, topic/identity, topic/mcp, topic/credentials, topic/policy, platform/ci, platform/cloud, control/task-tok, control/pin, control/audit, boundary/tb6, boundary/tb7, invariant/i1, invariant/i5, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
milestone: M3
---

# M3 CI Identity and MCP

> Weeks 7-8: GitHub Action with runner OIDC, OIDC device login to Okta/Entra dev tenants, MCP guard with manifest pinning, AWS STS minting with session policy and SigV4, trifecta context; done when an untrusted-issue CI fixture exposes no long-lived secret and the GitHub MCP toxic flow replay is stopped at the public write.

## Goal

M3 takes the laptop product into the three places where the incident record says the damage happens: CI runners that read untrusted issue text next to credentials, local MCP servers that hold ambient tokens, and cloud accounts reachable with standing keys. It also attributes every decision to a human identity from the enterprise IdP, and turns the lethal trifecta from advice into an enforced rule.

The motivating incidents: a public issue drove an agent to read private repos with an all-repo PAT and leak them through a public PR ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)); an over-scoped CodeBuild GitHub token let an actor ship malicious code in an Amazon Q release ([AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)); and s1ngularity malware drove local AI CLIs to hunt secrets and later made 5,500+ private repos public ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)). The MCP specification also tells stdio servers to "retrieve credentials from the environment" ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)), which is exactly the secret-in-sandbox pattern the product removes.

## Scope

**In scope (report M3 row):**

- GitHub Action (`broker/setup@v1` per research note 05) running `broker run -- <agent>`, with the runner's OIDC JWT exchanged for a session grant; job secrets never enter the agent tree.
- OIDC device login to Okta and Entra dev tenants; audit rows carry IdP subject and groups ([[Okta Cross App Access]], [[Entra Agent ID]]).
- MCP guard: pinned stdio servers, each in its own sandbox as its own principal; `tools/list` hashing; `tools/call` authorization; `broker mcp wrap` and `broker mcp connect` ([[MCP Guard]]).
- AWS STS minting with a session policy compiled from the grant, and SigV4 re-signing ([[AWS STS Session Policies]]).
- Trifecta context: `untrusted_input`, `sensitive_read`, `external_effect` computed by the broker and enforced by the Rule-of-Two forbid ([[Trifecta Session Labels]]).
- The [[Internal Grant JWT]] for the CI sidecar case where sandbox and broker may be on different hosts.

**Out of scope:** ID-JAG/XAA and Entra Agent ID registration of agents (phase 3); SaaS token exchange (phase 3); Kubernetes and remote-sandbox gateway modes (phase 2); Biscuit delegation (phase 3); remote MCP servers' full OAuth client flow is desirable but the acceptance criteria only require the stdio GitHub MCP server.

**Compression option.** Dropping MCP and AWS from M3 compresses the plan to about seven weeks ([[MVP Plan]]). If taken, record an ADR and keep CI and identity in M3.

## Prerequisites

- [[M2 Policy Audit and Learn]] is `status: built`: Cedar schema, audit attribution fields and the Rule-of-Two policy exist.
- Throwaway Okta and Entra dev tenants; a GitHub test org with a public and a private repo; an AWS test account with a role and an S3 bucket with a prefix; credentials only in OS keychain or CI secrets.
- The GitHub MCP server (stdio) for the wrap test.
- Read [[Architecture Overview]] (deployment modes: CI identity is the runner OIDC JWT), [[MCP Authorization Spec]], [[Just-in-Time Credential Minting]].

## Ordered task checklist (Proposal)

**CI mode**

- [ ] `integrations/github-action/action.yml`: install the broker, start `brokerd` outside the sandbox in the runner, request the runner's OIDC JWT, and run `broker run -- <agent>`.
- [ ] `crates/brokerd/src/session.rs`: accept a runner OIDC JWT as the identity source for CI sessions; map claims to `User`/`Group`/`Task` entities.
- [ ] `crates/grant/src/txn_token.rs` and `dpop.rs`: the Txn-Token-shaped grant JWT, sender-constrained with DPoP, used when the sandbox and broker are separated ([[Internal Grant JWT]], [[DPoP and mTLS-Bound Tokens]]).
- [ ] `tests/e2e/ci_untrusted_issue/`: a workflow fixture whose trigger text is an attacker-authored issue; assert no long-lived secret is visible in the agent tree (reuse the M1 scanner).

**Identity**

- [ ] `crates/broker-cli/src/cmd/login.rs`: OIDC device-code login to Okta and Entra; cache tokens in `brokerd` memory and keychain; never forward the user's IdP token as-is to an upstream or MCP server ([[CLAUDE]] section 3).
- [ ] Audit: populate `enduser.id` (IdP subject) and groups on every event ([[Audit Recorder and Event Schema]]).

**MCP guard (crate `mcpguard`)**

- [ ] `crates/mcpguard/src/wrap.rs`: `broker mcp wrap -- <cmd>` launches the command in its own standard-tier sandbox as an `McpServer` principal with sentinel env vars and its own egress policy.
- [ ] `crates/mcpguard/src/relay.rs`: `broker mcp connect <name>` stub that the agent's MCP config points at; the pinned command comes only from user or org config, never the repo ([[I5 Config Outside Writable Mounts]]).
- [ ] `crates/mcpguard/src/manifest_pin.rs`: hash `tools/list` names, schemas and descriptions before relaying; any change revokes the server's grants until re-approved ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)).
- [ ] `crates/mcpguard/src/tools_call.rs` and `crates/l7/src/adapters/mcp.rs`: authorize each `tools/call` with its arguments (`mcp.call_tool`); JSON-RPC parser gets `tests/fuzz/fuzz_targets/jsonrpc.rs`.
- [ ] Stdio secrets: replace env secrets with sentinels and swap them back only on the server's egress to its upstream API.

**AWS (crate `creds`)**

- [ ] `crates/creds/src/issuers/aws_sts.rs`: `AssumeRole` with an inline session policy compiled from the Cedar grant (≤2,048 chars inline plus up to 10 ARNs), `DurationSeconds` 900 s by default, `SourceIdentity` set to the user or agent ID ([AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)).
- [ ] `crates/creds/src/issuers/sigv4.rs`: re-sign requests with the minted session credentials at egress.

**Trifecta and GitHub verbs**

- [x] `crates/policy/src/trifecta.rs`: `sensitive_read` flips on a private-repo read (visibility known from the proxied API) or a high-risk credential; `untrusted_input` flips on public issues/PRs, arbitrary web pages or designated ticket sources; `external_effect` is any write-class action. (built as `crates/policy/src/github.rs` and `crates/brokerd/src/l7_pipeline/github.rs`; git clones do not raise `sensitive_read` yet: [[ADR-029 GitHub API Adapter and Session Labels as Built]])
- [x] `crates/l7/src/adapters/github_api.rs`: map REST method/path and GraphQL operations to verbs (`pr.create`, `pr.merge`, `issue.comment`, `contents.write`) so "open a PR but never merge" is one rule ([[GitHub API Adapter]]). (built as `crates/l7/src/github.rs`, REST only; GraphQL denied: [[ADR-029 GitHub API Adapter and Session Labels as Built]])
- [ ] Org policy option: forbid public-sink writes whenever `untrusted_input` is set (Willison's "[A]+[C] without [B]" critique).

**Probes**

- [ ] `tests/e2e/mcp_github_wrap`, `tests/e2e/mcp_rug_pull`, `tests/e2e/toxic_flow_replay`, `tests/e2e/s3_prefix`.

## Components delivered

[[MCP Guard]], [[Internal Grant JWT]], the `aws_sts` issuer in [[Credential Injector and Issuers]], [[GitHub API Adapter]], [[Trifecta Session Labels]] (enforced), identity attribution in [[Audit Recorder and Event Schema]], CI mode of [[Broker CLI and Daemon]].

## Acceptance criteria

| # | Criterion (report) | Test (proposal) | Threshold |
|---|---|---|---|
| D1 | On an untrusted-issue CI fixture, the agent tree sees no long-lived secret | `tests/e2e/ci_untrusted_issue` | 0 canary or job secrets found in env, files, argv, `/proc` |
| D2 | Audit rows carry IdP subject and groups | assertion over audit rows from Okta and Entra device-login sessions | 100% of rows attributed |
| D3 | A wrapped GitHub MCP server can read issues but cannot reach non-allowlisted hosts | `tests/e2e/mcp_github_wrap` | issue read succeeds; every non-allowlisted connection denied |
| D4 | A changed tool description revokes it | `tests/e2e/mcp_rug_pull` (serve a modified `tools/list`) | grants revoked until re-approval; calls denied and logged |
| D5 | A replay of the GitHub MCP toxic flow is stopped at the public write | `tests/e2e/toxic_flow_replay` (public issue → private read → public PR) | public write denied by the Rule-of-Two forbid; logged |
| D6 | S3 read works via minted credentials; writes outside the prefix are denied | `tests/e2e/s3_prefix` | read succeeds; out-of-prefix write denied |
| D7 | No IdP token forwarded as-is | inspect upstream requests in the D2-D6 runs | 0 occurrences |

## Eval layers and probes that must pass

- [[L1 Conformance Suite]]: categories 1 and 2 extended to MCP servers as principals (foreign credentials, env-secret scan of the MCP sandbox), category 9 for the MCP sandbox, and category 10 for writes to `mcp.json` and agent config.
- [[SymCC CI Gates]]: credential confinement for the AWS and GitHub issuers; deny rules stay live for `pr.merge` and forced `git.push`.
- First dry run of [[L2 Injection Benchmarks]] fixtures reused from D5 (the full L2 run is M4).

## Risks

- **CI incident data is thin**: no public post-mortem of an incident in a CI-hosted coding agent exists; the CI risk is inferred from Nx and Amazon Q token root causes ([[Open Questions and Unverified Claims]]).
- **Session-level labels creep**: the trifecta label is coarse and inherits IFC's label-creep problem; mitigate with small tasks and fresh sessions per task ([[ADR-010 Session-Level Trifecta Labels in the MVP]]).
- **MCP servers with ambient credentials**: no data on how often local MCP servers run with full ambient credentials; test with the GitHub server first.
- **Upstream scoping limits**: GitHub has no branch/path scope and GCP Credential Access Boundaries cover Cloud Storage only; the proxy must enforce the rest ([[Risk Register]]).
- **Identity drafts are moving**: ID-JAG and agent-auth drafts are unsettled; M3 uses only OIDC device login and runner OIDC.

## Definition of done

1. D1-D7 pass in CI; test names in the Build log.
2. All earlier tests pass; I1, I5 and I7 tests extended to MCP principals.
3. Conformance corpus covers the MCP surface; 100% of out-of-policy probes denied and logged with a reason.
4. Delivered components `status: built` with Build log entries.
5. [[Build Log]] entry; CI and MCP items in [[Open Questions and Unverified Claims]] annotated.

## How it connects

- depends-on:: [[M2 Policy Audit and Learn]]
- depends-on:: [[MCP Guard]]
- depends-on:: [[AWS STS Session Policies]]
- depends-on:: [[Okta Cross App Access]]
- depends-on:: [[Entra Agent ID]]
- depends-on:: [[Trifecta Session Labels]]
- depends-on:: [[Internal Grant JWT]]
- depends-on:: [[Architecture Overview]]
- mitigates:: [[GitHub MCP Toxic Flow]]
- mitigates:: [[Nx s1ngularity Supply-Chain Attack]]
- mitigates:: [[Amazon Q Extension Compromise]]
- mitigates:: [[postmark-mcp Rug Pull]]
- decided-by:: [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]
- decided-by:: [[ADR-010 Session-Level Trifecta Labels in the MVP]]
- evaluated-by:: [[L1 Conformance Suite]]
- part-of:: [[MVP Plan]]

Next milestone: [[M4 Harden and Ship]].

## Implications for the build

- The agent can name an MCP server but can never choose its command; writing a new `mcp.json` must buy an attacker nothing.
- On `insufficient_scope` from a remote MCP server, pause and show the authority diff rather than widening silently ([[MCP Authorization Spec]]).
- Narrow any user-delegated upstream token immediately (STS session policy, GitHub repository selection) and cache it only in broker memory.

## Open questions

- Current revision of the ID-JAG draft and `draft-ietf-wimse-aims` ([[Okta Cross App Access]]).
- Base rate at which real MCP servers change tool descriptions ([[Measurement Gaps]]).
- Whether agent hook APIs expose enough task context to bind credentials to a task ([[Agent Identity Brokers]]).

## Sources

- Report: milestone row "Weeks 7-8 M3 CI, identity, MCP"; TB7; deployment modes; MCP guard; trifecta context; enterprise identity.
- Research note 05 sections 5.2 M3 and 3.6 CI mode (`broker/setup@v1`).

## Build log

- 2026-09-24: step 1 built: the GitHub API adapter and session trifecta labels ([[ADR-029 GitHub API Adapter and Session Labels as Built]]). D5 passes against a fake GitHub API: `m3_github::d5_toxic_flow_is_stopped_at_the_public_write` (public issue → private read → public PR denied by the Rule of Two, both labels logged); ADR-010's benign case passes (`a_public_issue_then_a_pr_on_that_public_repo_is_allowed`). Remaining: CI mode (D1), identity (D2, needs Okta/Entra dev tenants), MCP Guard (D3, D4), AWS STS (D6), and D7 across them.
