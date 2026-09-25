---
title: "GitHub API Adapter"
aliases: ["github_api adapter", "API Verb Mapping"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/git, topic/policy, topic/ifc, control/task-tok, boundary/tb4, milestone/m3, evidence/conflict]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-25
summary: "Maps GitHub REST method+path or the GraphQL operation to verbs (pr.create, pr.merge, issue.comment, contents.write) so 'open a PR but never merge' is one rule, and reports repository visibility to set the sensitive_read label."
related: ["[[GitHub App Installation Tokens]]", "[[Broker Cedar Schema]]", "[[Example Cedar Policies]]", "[[GitHub MCP Toxic Flow]]", "[[Threat Model Non-Goals]]", "[[Policy Learning Loop]]", "[[Core Trait Contracts]]", "[[Trifecta Session Labels]]", "[[GitLost GitHub Agentic Workflows Leak]]", "[[Git Smart-HTTP Adapter]]", "[[TLS Termination and Per-Session CA]]", "[[Policy Engine and Entity Builder]]", "[[Credential Injector and Issuers]]", "[[Hostname Canonicaliser]]", "[[SymCC CI Gates]]", "[[Credential Broker as Label Authority]]", "[[Lethal Trifecta]]", "[[Agents Rule of Two]]", "[[M1 Secrets Outside]]", "[[M3 CI Identity and MCP]]", "[[Risk Register]]", "[[MCP Guard]]"]
sources: ["https://invariantlabs.ai/blog/mcp-github-vulnerability", "https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html", "https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/", "https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app", "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/", "https://ai.meta.com/blog/practical-ai-agent-security/"]
milestone: M3
---

# GitHub API Adapter

> Maps GitHub REST method+path or the GraphQL operation to verbs (pr.create, pr.merge, issue.comment, contents.write) so 'open a PR but never merge' is one rule, and reports repository visibility to set the sensitive_read label.

## Responsibility

`l7/adapters/github_api`, a `ProtocolAdapter` ([[Core Trait Contracts]]) for `api.github.com` (and GitHub Enterprise hosts by configuration). It does two things no host allowlist can:

1. **Verb semantics.** Turn a REST method+path, or a GraphQL operation, into named verbs, so "allowing a PR to be opened while forbidding its merge becomes a one-line rule" (report).
2. **Label source.** Tell the policy engine when the session has read a private repository (`sensitive_read`) or fetched attacker-writable content such as public issues and PR bodies (`untrusted_input`), because "the broker knows repo visibility from the API it proxies" (report; [[Trifecta Session Labels]]).

**It must never:** allow a request it cannot map (unknown REST route or GraphQL mutation is a deny); derive labels from model output; lower a label; attach a token broader than the grant.

## Why it exists

- **GitHub MCP toxic flow.** A public issue drove an agent holding an all-repo PAT to read private repos and leak them via a public PR ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)); see [[GitHub MCP Toxic Flow]]. The write-back channel sat inside GitHub, so a host allowlist could not see it.
- **GitLost.** A public issue made an org-read agent post a private README; an output scanner was bypassed by prefixing "Additionally," ([The Hacker News](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)); see [[GitLost GitHub Agentic Workflows Leak]]. Output classifiers do not replace scoping.
- **Misuse within granted scope.** A proxy "prevents theft but not misuse" ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)); the report's mitigation is narrow verbs ("PR create ≠ merge"), trifecta approvals and honest non-goals ([[Threat Model Non-Goals]], [[Risk Register]]).
- **Tokens stop at repo and permission.** Installation tokens have per-category read/write permissions but no branch, path or verb scope ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app); [[GitHub App Installation Tokens]]).

## Verb mapping

**Proposal.** A static route table, compiled into the adapter, maps (method, path template) to (verb, resource). Paths are matched against the canonical path from [[Hostname Canonicaliser]], with `{owner}`, `{repo}`, `{number}` and `{path}` captured. The report's example is that a POST to `/repos/acme/web/pulls` is `pr.create`, not `pr.merge`.

| Verb | REST shape (background; verify against GitHub's REST reference) | Default risk |
|---|---|---|
| `repo.read` | `GET /repos/{o}/{r}/...` (read routes) | read |
| `pr.create` | `POST /repos/{o}/{r}/pulls` | write |
| `pr.merge` | `PUT /repos/{o}/{r}/pulls/{n}/merge` | high (irreversible) |
| `issue.comment` | `POST /repos/{o}/{r}/issues/{n}/comments` | write, external sink if repo public |
| `contents.write` | `PUT /repos/{o}/{r}/contents/{path}` | write |
| `gist.create` | `POST /gists` | write, external sink |

> [!note] Background, not in the research record
> Only the verb names and the `/repos/acme/web/pulls` → `pr.create` example are from the report. The other REST shapes and any GraphQL mutation names are GitHub API background knowledge; generate the table from GitHub's published OpenAPI description rather than by hand (the learning plane already maps requests "to known OpenAPI operations such as GitHub's").

**GraphQL.** For `POST /graphql`, parse the document strictly; every top-level mutation field maps to a verb; documents with unknown mutations, multiple operations without an explicit `operationName`, or parse errors are denied. Queries map to read verbs on the repositories they name where determinable, otherwise to a coarse `graphql.read` verb.

**Cedar requests.** Each mapped request yields:

```json
[
  { "action": "http.POST", "resource": "Broker::PathPrefix::\"api.github.com/repos/acme/web/pulls\"",
    "context": { "method": "POST", "path": "/repos/acme/web/pulls", "sni": "api.github.com", "host_header": "api.github.com" } },
  { "action": "pr.create", "resource": "Broker::Repo::\"github.com/acme/web\"", "context": { "session": { "...": "..." } } },
  { "action": "credential.use", "resource": "Broker::Credential::\"github_app:acme\"",
    "context": { "dest_host": "api.github.com", "method": "POST", "path": "/repos/acme/web/pulls" } }
]
```

The verb actions (`pr.create`, `pr.merge`, `issue.comment`, `contents.write`) are not in the report's schema sketch, which only defines `http.*`, `git.*`, `credential.use`, `mcp.call_tool` and `fs.*`; the SymCC gates, however, name `pr.merge` and `pkg.publish` as high-risk actions. **Proposal:** extend [[Broker Cedar Schema]] with a `github.*` action group applying to `Repo`, and update [[SymCC CI Gates]] accordingly.

Example rule ("open a PR but never merge"):

```cedar
permit (principal is Broker::Task, action == Broker::Action::"pr.create", resource is Broker::Repo)
when { resource.full_name == principal.repo };
forbid (principal, action == Broker::Action::"pr.merge", resource) unless { context.session.approved };
```

## Labels (response side)

**Proposal.** After a successful response:

- a read of any resource in a repository whose visibility is private raises `sensitive_read` (visibility is known from the repository metadata the broker fetches or proxies; the broker caches `Repo.visibility` per session);
- a read of issue, PR or comment bodies from a public repository (or from designated sources in org policy) raises `untrusted_input`.

The `Repo` entity carries `visibility` ([[Broker Cedar Schema]]). With both labels live, the Rule-of-Two forbid blocks `http.write` and `git.push` without approval ([[Lethal Trifecta]], [[Agents Rule of Two]]; [Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/); [Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/)), which "would have stopped the GitHub MCP and GitLost flows at the public-write step" (report). This makes the broker the label authority ([[Credential Broker as Label Authority]]).

The `ProtocolAdapter` trait in the report has no response hook; label raising therefore runs in the L7 pipeline using the adapter's route match (see open questions in [[Core Trait Contracts]]).

## Credential

The `github_app` issuer mints a token restricted to the task repository and the permission categories derived from the allowed verbs (for example `pull_requests: write` only if `pr.create` is granted). The [[Policy Learning Loop]] derives this permissions object from observed operations.

## State

Route table (static); per-session repo visibility cache and label state (owned by the policy engine).

## Failure modes and fail-closed behaviour

Unknown route, unknown GraphQL mutation, GraphQL parse error, repository path that does not canonicalise, or visibility lookup failure when a label decision depends on it: deny (or, for visibility, treat as private, which only narrows).

## Security considerations

- Path-parameter smuggling (encoded slashes, dot segments) is rejected by `canon_path`.
- GraphQL aliasing and batching can hide mutations; parse the full document, never regex it.
- Redirects from the API (for example to raw content hosts) are re-evaluated as new requests.

## Performance budget

Route lookup is a trie match; GraphQL parsing is bounded by a body-size limit. Negligible against the warm-connection p50 ≤5 ms budget.

## Invariants upheld

[[I6 Single Canonicaliser]] (canonical paths), [[I3 Probabilistic Components Only Narrow]] (labels only raise, from API facts), [[I7 Reject Foreign Credentials]] (via the L7 pipeline).

## Test plan

- Unit: route table against a fixture list of requests; GraphQL documents with aliases, fragments, multiple operations.
- Property: every route in the OpenAPI-derived table maps to exactly one verb; unknown routes deny.
- Fuzz: GraphQL parser.
- E2E ([[M3 CI Identity and MCP]]): replay of the GitHub MCP toxic flow is stopped at the public write; a wrapped GitHub MCP server can read issues ([[MCP Guard]]).
- Conformance category 1: gist, issue comment on an allowed forge.

## Dependencies

A GraphQL parser crate and GitHub's OpenAPI description (neither selected in the record).

## How it connects

- implements:: [[Core Trait Contracts]]
- depends-on:: [[GitHub App Installation Tokens]]
- depends-on:: [[Broker Cedar Schema]]
- depends-on:: [[Trifecta Session Labels]]
- example-of:: [[Example Cedar Policies]]
- mitigates:: [[GitHub MCP Toxic Flow]]
- mitigates:: [[GitLost GitHub Agentic Workflows Leak]]
- part-of:: [[Policy Learning Loop]]
- motivated-by:: [[Threat Model Non-Goals]]
- delivered-by:: [[M3 CI Identity and MCP]]

## Implications for the build

- Generic method and path rules for `api.github.com` arrive in [[M1 Secrets Outside]]; verb mapping is needed by M2 learning (operation-level entries) and the trifecta labels by M3.

> [!warning] Conflict
> The report lists GitHub REST/GraphQL as one of five MVP adapters, while research note 05's phase-3 list includes "GitHub/GitLab semantic policies (PR create vs merge)". **Proposal:** ship GitHub REST verbs in the MVP (M2–M3) as the report and the M3 acceptance require; defer GraphQL completeness and GitLab to phase 3.

## Open questions

- Schema extension for verb actions (see above) must be settled in [[Broker Cedar Schema]].
- Which GitHub content counts as `untrusted_input` beyond public issues and PRs (discussions, commit messages, READMEs of dependencies).
- Does GraphQL `Repository.issue(number:)` follow an issue transferred to another repository? If it does, a confined read of the old number returns the new repository's content ([[ADR-035 GitHub GraphQL and Host-Wide Read Labels as Built]]).

## Sources

- https://invariantlabs.ai/blog/mcp-github-vulnerability
- https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html
- https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/
- https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
- https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
- https://ai.meta.com/blog/practical-ai-agent-security/
- Report: adapters (GitHub REST and GraphQL), trifecta Proposal, SymCC gates, risk "Misuse within granted scope", learning stage 1; research note 05 sections 3.2 and 5.3.

## Build log

- 2026-09-24 (M3): built for the REST API ([[ADR-029 GitHub API Adapter and Session Labels as Built]]): route table checked against GitHub's REST reference; `protocol = "github"` with `verbs` and `repos`; broker-side visibility lookup with the bound credential and re-decision; labels raised before forwarding. GraphQL is denied until a strict parser maps mutations; the table is hand-written from verified routes (OpenAPI generation arrives with G1). Tests: `l7::github::tests::*`, `policy::cedar::github_tests::*`, `m3_github::*`; fuzz target `github_route`.
- 2026-09-25 (M3): GraphQL built ([[ADR-035 GitHub GraphQL and Host-Wide Read Labels as Built]]): a strict executable-document parser (`code/crates/l7/src/graphql.rs`, `graphql/lex.rs`), JSON-only `POST /graphql` without a query string, operation choice by `operationName` or the only operation, five mutations mapped to `pr.create`, `pr.merge` and `issue.comment` on repositories the broker resolves from node IDs with the bound credential (`brokerd` L7 step 3b), `repository(owner:, name:)` as `repo.read`, and a schema allowlist (`code/crates/l7/src/github/schema.rs`) deciding whether a read stays in one repository; anything else is an unconfined `github.read`. **Fixed (labels):** host-wide `github.read` (search, `/user/repos`, …) never raised `sensitive_read`, so a toxic flow through code search passed the Rule-of-Two forbid; it now does unless the route is known public. Tests: `l7::graphql::tests::*`, `l7::github::graphql::tests::*`, `l7::github::schema::tests::*`, `m3_graphql::*`; fuzz target `graphql`. The conflict above is settled: GraphQL mutations that matter for the MVP ship in M3; the remaining mutations are refused until mapped.
