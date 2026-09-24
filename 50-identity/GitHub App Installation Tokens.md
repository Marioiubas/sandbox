---
title: "GitHub App Installation Tokens"
aliases: ["GitHub App Tokens", "Fine-Grained PATs"]
type: "standard"
section: "identity"
summary: "Installation tokens scoped to up to 500 repos and per-category read/write permissions with a 1-hour TTL and no branch or path scope (omitted fields inherit the whole installation); why fine-grained PATs (possibly unlimited lifetime) are avoided for agents."
tags: [sandbox/identity, standard, topic/credentials, topic/git, control/task-tok, control/cred-out, boundary/tb4, invariant/i1, milestone/m1]
status: verified
confidence: high
milestone: M1
created: 2026-09-24
updated: 2026-09-24
related: ["[[Just-in-Time Credential Minting]]", "[[Credential Injector and Issuers]]", "[[Git Smart-HTTP Adapter]]", "[[GitHub API Adapter]]", "[[M1 Secrets Outside]]", "[[GitHub MCP Toxic Flow]]", "[[ADR-005 Mint Credentials Per Task]]", "[[Policy Miner Safeguards]]", "[[Open Questions and Unverified Claims]]", "[[Core Trait Contracts]]", "[[Tech Stack]]", "[[I1 No Secrets in the Sandbox]]"]
---

# GitHub App Installation Tokens

A GitHub App installation access token is minted by the app (authenticated with its private key) for one installation, and can be narrowed at mint time to a list of up to 500 repositories and a subset of the app's permissions, each category read or write. It always expires after one hour, and it has no branch, path or HTTP-method scope; if the repository or permission fields are omitted, it inherits everything the installation has. The broker mints one per task scope, keeps it in memory, and enforces branch, path and verb itself at L7. Fine-grained personal access tokens are avoided for agents because their lifetime can be unlimited.

## What the mint request can say

Documented fields of "create an installation access token for an app" ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)):

| Field | Meaning | Limit |
|---|---|---|
| `repositories` | repository names the token may access | up to 500 |
| `repository_ids` | same, by ID | up to 500 |
| `permissions` | object of permission category → `read` / `write` | subset of the installation's permissions |
| (omitted fields) | token inherits **every** repo and permission of the installation | |
| lifetime | fixed | **expires after 1 hour** |
| branch / path / method | not expressible | |

Illustrative request (assembled from the documented field names; the endpoint path and response shape are standard GitHub REST behaviour but were **not** captured in the record, so confirm them against the cited page before coding):

```http
POST /app/installations/{installation_id}/access_tokens
Authorization: Bearer <app JWT signed with the app private key>
Accept: application/vnd.github+json

{ "repositories": ["web"], "permissions": { "contents": "write", "pull_requests": "write" } }
```

The response carries the token and its expiry timestamp; the broker stores both, never the token on disk.

## What it cannot say, and who enforces the rest

| Desired scope | Native? | Enforced by |
|---|---|---|
| one repo | yes (`repositories`) | GitHub |
| contents write, not admin | yes (`permissions`) | GitHub |
| only `refs/heads/agent/*`, never force | **no** | broker: [[Git Smart-HTTP Adapter]] parses `git-receive-pack` ref updates |
| open a PR but not merge it | **no** (both need `pull_requests: write`) | broker: [[GitHub API Adapter]] maps method+path/GraphQL op to `pr.create` vs `pr.merge` |
| only `/repos/acme/web/contents/docs/*` | **no** | broker: method/path rules |
| 15 minutes | **no** (always 1 h) | broker: cache eviction at task end; the upstream token stays valid until its own expiry |

Anthropic's web sandbox follows the same split: a custom git proxy validates a "custom-built scoped credential", checks the push goes only "to the configured branch", then "attaches the right authentication token before sending the request to GitHub" ([Anthropic](https://www.anthropic.com/engineering/claude-code-sandboxing)).

Research-note inference: the finest scope achievable today is a 1-hour installation token restricted to one repo and a minimal permission set (for example `contents:write` only), with branch, path and method limits coming from L7 inspection of `/repos/{o}/{r}/contents/{path}` and git smart-HTTP.

> [!question] Unverified
> Whether GitHub added any branch-scoped installation-token capability in 2026 was not found ([[Open Questions and Unverified Claims]]). Re-check before M1; if it exists, use it as defence in depth, not as a replacement for the adapter.

## Why not fine-grained PATs

- Fine-grained PATs scope per repo and permission, with no branch or path scoping; infinite lifetime is allowed unless org or enterprise policy caps it; org owners can require approval; several surfaces (Packages, the Checks API, multi-org access) are unsupported ([GitHub docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)).
- A PAT is a *user's* standing credential. The incident record is dominated by exactly that: the GitHub MCP toxic flow used an all-repo PAT to read private repos and leak them via a public PR ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)); s1ngularity leaked 1,000+ valid GitHub tokens ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)); the Amazon Q compromise rode an over-scoped CodeBuild GitHub token ([AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)).
- **Proposal:** the broker supports PATs only through the static `static` issuer as a last resort, behind the same L7 rules, and flags them as `risk: high` in the `Credential` entity.

## Where the token lives and how it flows

**Proposal** (report request life, steps 3–6; research note 05 §3.2).

1. Session start: `brokerd` computes the Task entity (repo from the remote URL, branch prefix, permissions from policy).
2. First request needing GitHub credentials: the adapter emits Cedar requests (`git.push` on the Repo with `ref`/`force` context, plus `credential.use` on the GitHub credential). Only if **all** allow does the `github_app` issuer mint.
3. The issuer signs an app JWT with the app private key (held in the OS keychain or an external manager, never on disk in the repo), calls the mint endpoint with `repositories` = the task repo and `permissions` = the minimal set derived from policy, and caches the result keyed by **scope digest** for the session.
4. Attach: `Authorization` header for REST; HTTP basic credentials for git smart-HTTP (format per GitHub docs, not in the record).
5. Response filter strips any echo of the token; audit logs the credential ID and scope digest, never the value.
6. Session end: drop the cache. **Proposal:** also call GitHub's installation-token revocation endpoint if it exists (background knowledge; not in the record, verify) so the token does not outlive the task by up to an hour.

The policy miner derives the `permissions` object from the operations actually observed ([[Policy Miner Safeguards]]).

## Verdict for the broker

**Proposal.**

- **Use it for:** every GitHub credential the broker attaches, for git smart-HTTP and REST/GraphQL; one repo per session by default.
- **Don't use it for:** branch, path or verb scoping (enforce at L7); anything that requires a token lifetime under one hour upstream; PAT-based flows for agents.
- **How we integrate it.** `issuers/github_app` in `crates/creds`, implementing `CredentialIssuer { kind: "github_app" }` from [[Core Trait Contracts]]; RS256 app-JWT signing with a maintained JWT crate (choice unverified, see [[Tech Stack]]); HTTP via the broker's own hyper client with full TLS verification; `Issued { secret: Zeroizing<..>, expires_at, scope_digest }`. Configuration is the `credential = { kind = "github_app", permissions = {…}, repos = [...], ttl = "30m" }` block in `broker.toml`, where `ttl` is the broker-side cache lifetime, not GitHub's.

## How it connects

- implements:: [[Just-in-Time Credential Minting]]
- delivered-by:: [[Credential Injector and Issuers]] (`github_app` issuer)
- depends-on:: [[Git Smart-HTTP Adapter]] (branch and force rules)
- depends-on:: [[GitHub API Adapter]] (verb rules)
- delivered-by:: [[M1 Secrets Outside]]
- mitigates:: [[GitHub MCP Toxic Flow]] (one repo per session)
- decided-by:: [[ADR-005 Mint Credentials Per Task]]
- depends-on:: [[Policy Miner Safeguards]] (permissions derived from observed operations)

## Implications for the build

- M1 acceptance: push to `agent/x` on the session repo succeeds; pushes to another repo, to `main` or with force are denied and `broker why` explains each ([[M1 Secrets Outside]]). Two of those denials come from GitHub (other repo), two from the adapter (branch, force): test both layers independently.
- Canary scan: the minted token must never appear in env, files, argv, `/proc` or response bodies ([[I1 No Secrets in the Sandbox]]).
- Use a throwaway GitHub App in a dev org for CI; its private key lives in CI secrets, never in the repo.

## Open questions

- Branch-scoped tokens in 2026, token revocation endpoint and the exact response schema must be confirmed from primary docs ([[Open Questions and Unverified Claims]]).

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
