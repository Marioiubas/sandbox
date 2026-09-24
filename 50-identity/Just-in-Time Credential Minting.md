---
title: "Just-in-Time Credential Minting"
aliases: ["JIT Minting", "Task-Scoped Tokens", "TASK-TOK", "Identity Binding at Task Start"]
type: "concept"
section: "identity"
summary: "Mint short-lived, audience-bound upstream credentials per task scope digest just before forwarding (GitHub App, STS, OAuth exchange), obtain the user-delegated token from Okta/Entra at task start and narrow it at once; static swap only where providers cannot mint."
tags: [sandbox/identity, concept, topic/credentials, topic/identity, control/task-tok, control/cred-out, boundary/tb4, invariant/i1, invariant/i7, milestone/m1, milestone/m3]
status: proposal
confidence: medium
milestone: M1
created: 2026-09-24
updated: 2026-09-24
related: ["[[ADR-005 Mint Credentials Per Task]]", "[[Credential Injector and Issuers]]", "[[GitHub App Installation Tokens]]", "[[AWS STS Session Policies]]", "[[GCP Credential Access Boundaries]]", "[[Okta Cross App Access]]", "[[Entra Agent ID]]", "[[Sentinel Swap Pattern]]", "[[Agent Identity Brokers]]", "[[Request and Session Lifecycle]]", "[[RFC 8693 Token Exchange]]", "[[Open Questions and Unverified Claims]]", "[[Core Trait Contracts]]", "[[M3 CI Identity and MCP]]", "[[Threat Model Non-Goals]]", "[[Risk Register]]", "[[Policy Engine and Entity Builder]]", "[[I1 No Secrets in the Sandbox]]", "[[M1 Secrets Outside]]", "[[MVP Plan]]"]
---

# Just-in-Time Credential Minting

The broker mints a short-lived, audience-bound upstream credential for each task scope just before forwarding a request that needs it: a repo-scoped GitHub App installation token, a 15-minute AWS STS session with a session policy, an OAuth token exchange. It obtains the user-delegated token from Okta or Entra at task start and narrows it at once, caches everything only in broker memory keyed by a scope digest, and drops it at session end. Static sentinel swap is the fallback only where providers cannot mint. Minting plus a local OS sandbox is the combination no reviewed product offers.

## Why minting, not just swapping

- No upstream token can say "this repo, this path, this method, 15 minutes". The finest native scopes are: GitHub, repo plus permission category for 1 hour ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)); AWS, action and ARN with conditions down to 15 minutes ([AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)); GCP, a Cloud Storage object prefix ([GCP docs](https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials)). So the broker mints the narrowest native credential **and** enforces the rest at L7.
- Minting bounds blast radius in time and scope; a static swapped secret keeps whatever scope and lifetime it had upstream (report decision row "Credentials").
- Most 2026 products substitute a static long-lived secret; only Keycard (task-scoped issuance), Aembit (credential exchange), AgentCore Identity and E2B (workload-identity tokens in header transforms) point toward minting, and none of them also provides the local OS sandbox (research note 05 inference) ([Keycard](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/); [AWS AgentCore Identity](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html); [E2B docs](https://docs.e2b.dev/network/internet-access.md)).
- Buyers ask for it: a CSA note recommends "time-bound, just-in-time credentials scoped to the specific resources their task requires" ([CSA Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/)); CSA's agentic IAM paper calls for JIT credentials "automatically expiring after task completion" ([CSA](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)).

## Issuer tiers

**Proposal** (research note 05 §3.2; report components).

| Tier | Issuer (`CredentialIssuer.kind`) | Native scope | TTL | Milestone |
|---|---|---|---|---|
| mint | `github_app` | ≤500 repos (broker uses 1), permission subset | 1 h upstream; broker cache ≤ task | M1 ([[GitHub App Installation Tokens]]) |
| mint | `aws_sts` | session policy ∩ role, tags, `SourceIdentity` | 900 s default | M3 ([[AWS STS Session Policies]]) |
| mint | `oauth_exchange` | audience + scope per RFC 8693 / ID-JAG / Entra OBO | per AS | phase 3 ([[RFC 8693 Token Exchange]]) |
| mint (later) | GCP CAB, GCP/Azure workload-identity federation, Vault dynamic secrets | Storage prefix; provider-specific | short | unscheduled ([[GCP Credential Access Boundaries]]) |
| swap | `static` | none; the broker's method/path allowlist *is* the scope | long-lived | M1 ([[Sentinel Swap Pattern]]) |

Vault, 1Password and Infisical dynamic-secret engines are background knowledge only in the record ([[Open Questions and Unverified Claims]]).

## Where it sits in a request's life

From the report's request life ([[Request and Session Lifecycle]]):

1. `broker run -- claude` → `brokerd` resolves the user from a cached OIDC login, identifies the agent binary by hash, reads the repo remote, and computes the Task entity and its grants.
2. It generates the per-session CA and sentinels and launches the agent.
3. Each outbound request is canonicalised, DNS-checked, TLS-terminated if an L7 rule or credential applies, and classified by a protocol adapter into one or more Cedar requests (for example `http.POST` on a PathPrefix **plus** `credential.use` on the GitHub credential).
4. **Only if all of them allow does the issuer mint or reuse a cached token for that scope digest and attach it.**
5. The response filter runs; the decision and credential ID (never the value) are appended to the hash-chained log.
6. At session end the broker destroys the CA, drops the cached tokens and flushes the audit log.

### The scope digest

**Proposal.** `scope_digest = H(issuer kind ‖ upstream audience ‖ canonical sorted permission set ‖ resource set ‖ session id)`. Two requests that need the same authority reuse one token; a request that needs more authority never reuses a narrower token, and a narrower need never gets a broader cached token (it mints a new, narrower one). `Issued { secret: Zeroizing<..>, expires_at, scope_digest }` from [[Core Trait Contracts]].

## Identity binding at task start

**Proposal** (report "Enterprise identity plugs in at task start").

- Use ID-JAG ([[Okta Cross App Access]]) or Entra OBO ([[Entra Agent ID]]) to obtain the *user-delegated* upstream token at task start.
- Narrow it immediately, with an STS session policy or a GitHub repository selection.
- Cache it only in broker memory; it never enters the sandbox and is never forwarded as-is to an MCP server.
- Rationale: "delegation chains inherit the broadest permission unless actively narrowed" ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)).
- In CI, runner OIDC is exchanged by the broker; job secrets never enter the agent tree ([[M3 CI Identity and MCP]]).

## Threats it addresses and does not

- **Addresses:** long-lived-credential theft (s1ngularity leaked 1,000+ valid GitHub tokens ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack))); over-scoped tokens (the GitHub MCP toxic flow used an all-repo PAT ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability))).
- **Does not address:** misuse inside the granted scope ([[Threat Model Non-Goals]]).
- **Creates:** the broker as credential honeypot. Mitigation: a per-user daemon, keychain-held roots, memory-only minted tokens with short TTLs, and a control socket unreachable from sandboxes ([[Risk Register]]).

## Verdict for the broker

**Proposal.**

- **Use it for:** every upstream that supports minting or downscoping; per-task, per-scope-digest issuance at the moment of first use.
- **Don't use it for:** hosts with no credential rule (no credential is attached at all); pinned clients (passthrough, no injection); replacing L7 enforcement (minting narrows, it does not express branch, path or verb).
- **How we integrate it.** `crates/creds/issuers/{static,github_app,aws_sts,oauth_exchange,vault}` behind `CredentialIssuer`; issuance is triggered only from the policy engine's allow path, never from the adapter directly, so no code path attaches a credential without a Cedar `credential.use` allow ([[Credential Injector and Issuers]]; [[Policy Engine and Entity Builder]]).

## How it connects

- decided-by:: [[ADR-005 Mint Credentials Per Task]]
- delivered-by:: [[Credential Injector and Issuers]]
- depends-on:: [[GitHub App Installation Tokens]]
- depends-on:: [[AWS STS Session Policies]]
- depends-on:: [[GCP Credential Access Boundaries]]
- depends-on:: [[Okta Cross App Access]]
- depends-on:: [[Entra Agent ID]]
- contrasts-with:: [[Sentinel Swap Pattern]] (static fallback)
- competes-with:: [[Agent Identity Brokers]] (Keycard, Aembit, Arcade: identity without an egress sandbox)
- part-of:: [[Request and Session Lifecycle]] (step 4)
- implements:: [[I1 No Secrets in the Sandbox]]
- delivered-by:: [[M1 Secrets Outside]]
- delivered-by:: [[M3 CI Identity and MCP]]

## Implications for the build

- M1: GitHub App minting (repo + permissions, TTL ≤1 h); M3: AWS STS minting with session policy and SigV4; OIDC device login ([[MVP Plan]]).
- Test that no issuer is callable without a prior Cedar allow (unit test on the call graph; e2e with a deny policy shows zero mint calls).
- Test cache semantics: broader need never reuses a narrower token; session end zeroizes and drops all tokens.

## Open questions

- Upstream revocation at session end (GitHub, AWS) is not covered by the record.
- Dynamic-secret engines (Vault, 1Password, Infisical) are background only ([[Open Questions and Unverified Claims]]).

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
