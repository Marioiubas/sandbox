---
title: "ADR-005 Mint Credentials Per Task"
aliases: ["ADR-005"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/credentials, topic/identity, control/cred-out, control/task-tok, boundary/tb4, invariant/i1, invariant/i7, invariant/i9, milestone/m1, milestone/m3]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Mint per-task credentials wherever providers allow and fall back to static sentinel swap; reject static-swap-only and env-var secrets."
related: ["[[Just-in-Time Credential Minting]]", "[[Sentinel Swap Pattern]]", "[[Credential Injector and Issuers]]", "[[GitHub App Installation Tokens]]", "[[AWS STS Session Policies]]", "[[Local Credential Proxies]]", "[[ADR-001 Value Lives in the Broker]]", "[[GCP Credential Access Boundaries]]", "[[RFC 8693 Token Exchange]]", "[[Okta Cross App Access]]", "[[Entra Agent ID]]", "[[Agent Identity Brokers]]", "[[Cloud Sandbox Runtimes]]", "[[GitHub MCP Toxic Flow]]", "[[Nx s1ngularity Supply-Chain Attack]]", "[[Amazon Q Extension Compromise]]", "[[Supabase MCP Token Leak]]", "[[Policy Engine and Entity Builder]]", "[[Core Trait Contracts]]", "[[MCP Authorization Spec]]", "[[I1 No Secrets in the Sandbox]]", "[[I7 Reject Foreign Credentials]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[Risk Register]]", "[[M1 Secrets Outside]]", "[[M3 CI Identity and MCP]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[ADR-008 Grant Representation as Entities and Txn-Token JWT]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app", "https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html", "https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials", "https://www.wiz.io/blog/s1ngularity-supply-chain-attack", "https://invariantlabs.ai/blog/mcp-github-vulnerability", "https://aws.amazon.com/security/security-bulletins/AWS-2025-015/", "https://generalanalysis.com/blog/supabase-mcp-blog", "https://github.com/strongdm/leash", "https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/", "https://code.claude.com/docs/en/sandboxing", "https://github.com/Infisical/agent-vault", "https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/", "https://startwithidentity.com/blog/agent-identity-gets-a-protocol/", "https://modelcontextprotocol.io/specification/latest/basic/authorization"]
---

# ADR-005 Mint Credentials Per Task

> Mint per-task credentials wherever providers allow and fall back to static sentinel swap; reject static-swap-only and env-var secrets.

## Status

**Proposed** (2026-09-24). GitHub App minting is delivered in [[M1 Secrets Outside]]. AWS STS minting and OIDC login come in [[M3 CI Identity and MCP]], and OAuth token exchange in phase 3. Not superseded.

## Context

Keeping a secret outside the sandbox is necessary but not sufficient. The remaining question is what the broker attaches upstream: the user's long-lived secret, or a credential minted for this task.

**The incident record is about standing, over-scoped credentials.**

- s1ngularity leaked 1,000+ valid GitHub tokens ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack); [[Nx s1ngularity Supply-Chain Attack]]).
- The GitHub MCP toxic flow used an all-repo PAT to read private repos and leak them through a public PR ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability); [[GitHub MCP Toxic Flow]]).
- An over-scoped CodeBuild GitHub token let an actor ship malicious code in Amazon Q v1.84.0 ([AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/); [[Amazon Q Extension Compromise]]).
- A Supabase `service_role` bypassed row-level security ([General Analysis](https://generalanalysis.com/blog/supabase-mcp-blog); [[Supabase MCP Token Leak]]).

**Native scoping exists, but stops short of the task.**

| Provider | Finest native scope | Lifetime |
|---|---|---|
| GitHub App installation token | Up to 500 selected repositories and per-category read/write permissions; no branch or path scope; omitted fields inherit the whole installation ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)) | 1 hour |
| AWS STS `AssumeRole` | A session policy (≤2,048 characters inline plus up to 10 ARNs) intersected with the role; 50 tags; `SourceIdentity` visible in CloudTrail ([AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)) | 900 s to 43,200 s (1 h when chaining) |
| GCP Credential Access Boundary | Cloud Storage only; ≤10 rules; CEL prefix conditions ([GCP docs](https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials)) | Short-lived |
| Static SaaS API keys | None | Long-lived |

**The field mostly swaps static secrets.**

- Claude Code's `mask` swaps a per-session sentinel for the real value on `injectHosts` ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)).
- Agent Vault substitutes placeholders per host and path ([Agent Vault](https://github.com/Infisical/agent-vault)).
- Leash forwards API keys into the agent container ([Leash](https://github.com/strongdm/leash)).
- E2B and Modal secrets are environment variables that "are not private in the OS" ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/); [[Cloud Sandbox Runtimes]]).
- Only Keycard, Aembit, AgentCore Identity and E2B point toward minting, and none of them also provides a local OS sandbox (research note 05). Keycard issues credentials "scoped to the task, agent, user, and environment" through agent hooks, but it is closed and has no sandbox ([Keycard](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/); [[Agent Identity Brokers]]).
- Anthropic's Cowork gives the VM a per-session scoped-down token while "Credentials stay in the host keychain and never enter the guest" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).

**Demand and identity.**

- Buyers are told to use "time-bound, just-in-time credentials scoped to the specific resources their task requires" ([CSA Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/)).
- IdP delegation "chains inherit the broadest permission unless actively narrowed" ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)).
- MCP servers "MUST NOT accept or transit any other tokens" ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization); [[MCP Authorization Spec]]).

## Decision

**Proposal.** The `creds` crate implements `CredentialIssuer` in two tiers ([[Credential Injector and Issuers]], [[Core Trait Contracts]]).

1. **Mint wherever the provider allows.**
   - `github_app` (M1): an installation token restricted to the session repo, with the minimal permissions object derived from the grant (for example `contents: write`) and upstream TTL ≤1 h ([[GitHub App Installation Tokens]]).
   - `aws_sts` (M3): a session with `DurationSeconds` 900 by default. The inline session policy is compiled from the task's grants, and `SourceIdentity` and session tags carry the user, agent and task IDs ([[AWS STS Session Policies]]).
   - `oauth_exchange` (phase 3): RFC 8693, ID-JAG or Entra OBO. The user-delegated token is obtained at task start, narrowed immediately, and never forwarded as-is ([[RFC 8693 Token Exchange]], [[Okta Cross App Access]], [[Entra Agent ID]]).
   - GCP CAB is later work for Cloud Storage only ([[GCP Credential Access Boundaries]]).
2. **Static sentinel swap as the fallback** (`static`), only for upstreams that cannot mint (static SaaS and LLM API keys). The broker's method and path allowlist is then the scope ([[Sentinel Swap Pattern]], [[ADR-006 Deny Unmatched L7 Requests]]).
3. **Never put a secret in the sandbox's environment**, files, argv or config, in any mode.
4. **Minting happens only on the allow path.** A token is minted or reused only after *every* Cedar request derived from the HTTP request allows, including `credential.use` on that credential ([[Policy Engine and Entity Builder]]).
5. **Cache and lifetime.** Minted tokens are cached in broker memory (`Zeroizing`) keyed by a scope digest. A broader need never reuses a narrower token, and all tokens are dropped at session end. Roots (GitHub App keys, role credentials, static keys) live in Keychain or libsecret.

Testable form:

- The M1 scan finds only sentinels in env, files, argv and `/proc`.
- With a deny policy, e2e tests show zero issuer calls.
- A minted GitHub token's `repositories` list has exactly one entry.
- The STS session policy never exceeds the grant (unit test on the compiler).
- The audit row carries the credential ID and issuer, never the value.

## Alternatives considered

| Alternative | Pros | Cons (evidence) | Why rejected |
|---|---|---|---|
| **Static sentinel swap only** (Claude Code `mask`, Agent Vault, Docker) | Simple; works for any header key; proven by eight products | The secret keeps its upstream scope and lifetime; a broker bug or a mis-scoped rule exposes the full PAT; no user, agent or task binding upstream | Minting bounds blast radius in time and scope; swap is kept only as the fallback |
| **Secrets as environment variables** (Leash, E2B, Modal) | Zero integration work | The secret is inside the boundary ([Leash](https://github.com/strongdm/leash)); readable via `/proc` and by any subprocess | Violates I1 outright |
| **Hook-based JIT without a sandbox** (Keycard) | Task-scoped issuance already exists | Closed; no OS sandbox; depends on vendor hook stability ([[Risk Register]] R12) | The broker must be the only path; covered by [[ADR-001 Value Lives in the Broker]] |
| **Forward the user's IdP token upstream** | No exchange infrastructure | Breaks MCP's no-passthrough rule; inherits the broadest permission | Forbidden by the handoff contract |

## Consequences

**Positive.**

- Every attached credential expires with or before the task, is scoped to one repo or one session policy, and is attributable in upstream logs (CloudTrail `SourceIdentity`).
- A stolen sentinel is useless off-host, and a stolen minted token is short-lived and narrow.

**Negative.**

- Setup cost: the user or org must install a GitHub App and define AWS roles.
- Native scopes stop at repo and permission category (GitHub) or Cloud Storage prefix (GCP), so branch, path and verb enforcement still depends on L7 adapters ([[Risk Register]] R11).
- The broker becomes the credential honeypot (R4). Mitigations: a per-user daemon, keychain roots, memory-only tokens, and a control socket unreachable from the sandbox.
- Upstream revocation at session end is not covered by the record; tokens simply expire.
- Mint latency and provider rate limits are not in the record.

**Follow-up work.**

- Scope-digest cache tests.
- An issuer configuration schema in `broker.toml` (`credential = { kind = "github_app", ... ttl = "30m" }`).
- CloudTrail attribution checks in M3.
- An `insufficient_scope` step-up flow for MCP.

## Revisit triggers

- GitHub adds branch- or path-scoped installation tokens (none found as of the record).
- A provider in the default profile gains native minting (for example an LLM API issuing scoped short-lived keys). Move it out of the static tier.
- Measured mint latency or rate limits break the L4 latency budget. Consider pre-minting per session.
- Dynamic-secret engines (Vault, 1Password, Infisical) are verified and requested by design partners.

## Invariants and components affected

- **Upholds** [[I1 No Secrets in the Sandbox]] (no env-var secrets; minted material stays in broker memory) and [[I7 Reject Foreign Credentials]] (only broker-issued credentials go upstream).
- **Upholds** [[I9 Hash-Chained Audit Outside the Sandbox]] (credential ID and issuer are logged per decision).
- **Weakens none.**
- Components: [[Credential Injector and Issuers]], [[Policy Engine and Entity Builder]], the grant format in [[ADR-008 Grant Representation as Entities and Txn-Token JWT]].

## How it connects

- implements:: [[Just-in-Time Credential Minting]]
- delivered-by:: [[Credential Injector and Issuers]]
- depends-on:: [[GitHub App Installation Tokens]]
- depends-on:: [[AWS STS Session Policies]]
- contrasts-with:: [[Sentinel Swap Pattern]]
- contrasts-with:: [[Local Credential Proxies]]
- competes-with:: [[Agent Identity Brokers]]
- motivated-by:: [[ADR-001 Value Lives in the Broker]]
- mitigates:: [[GitHub MCP Toxic Flow]]
- mitigates:: [[Nx s1ngularity Supply-Chain Attack]]
- mitigates:: [[Amazon Q Extension Compromise]]
- delivered-by:: [[M1 Secrets Outside]]
- delivered-by:: [[M3 CI Identity and MCP]]

## Implications for the build

- M1 needs a throwaway GitHub App on a dev org, with its private key in the OS keychain or CI secrets, never in the repository.
- Structure the code so an issuer is reachable only from the policy engine's allow path, and assert that in a call-graph unit test.
- M3's S3 acceptance test ("read via minted credentials; writes outside the prefix denied") exercises both the session policy and the L7 rule.

## Open questions

- Upstream token revocation at session end (GitHub, AWS) is not in the record.
- Dynamic-secret engines are background knowledge only ([[Open Questions and Unverified Claims]]).
- Whether agent hook APIs expose enough task context to bind credentials more finely than the wrapped process does.

## Sources

- https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials
- https://www.wiz.io/blog/s1ngularity-supply-chain-attack
- https://invariantlabs.ai/blog/mcp-github-vulnerability
- https://aws.amazon.com/security/security-bulletins/AWS-2025-015/
- https://generalanalysis.com/blog/supabase-mcp-blog
- https://github.com/strongdm/leash
- https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/
- https://code.claude.com/docs/en/sandboxing
- https://github.com/Infisical/agent-vault
- https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/
- https://www.anthropic.com/engineering/how-we-contain-claude
- https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/
- https://startwithidentity.com/blog/agent-identity-gets-a-protocol/
- https://modelcontextprotocol.io/specification/latest/basic/authorization
- Report: "No upstream token can say this repo, this path, this method, 15 minutes", "Enterprise identity plugs in at task start", teardown table, decision table row "Credentials", risk table. Research note 03 Q1 and Q3, research note 05 sections 1 and 2.
