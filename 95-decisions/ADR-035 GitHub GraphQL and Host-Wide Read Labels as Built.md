---
title: "ADR-035 GitHub GraphQL and Host-Wide Read Labels as Built"
aliases: ["ADR-035"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, topic/mcp, control/audit, boundary/tb3, milestone/m3]
status: built
confidence: medium
created: 2026-09-25
updated: 2026-09-26
summary: "GitHub GraphQL (`POST /graphql`, JSON only, no query string) is parsed strictly and mapped to the REST verbs: five known mutations name their repository by node ID, which the broker resolves itself with the grant's credential; `repository(owner:, name:)` is `repo.read`; `viewer`/`user`/`rateLimit`/introspection are public `github.read`; any selection outside an allowlisted schema subset, and every other root field, is an unconfined `github.read`. Host-wide `github.read` now raises `sensitive_read` unless the route is known to return only public data, closing a Rule-of-Two bypass through search."
related: ["[[GitHub API Adapter]]", "[[ADR-029 GitHub API Adapter and Session Labels as Built]]", "[[Trifecta Session Labels]]", "[[GitHub MCP Toxic Flow]]", "[[M3 CI Identity and MCP]]", "[[MCP Guard]]", "[[Conformance Probe Matrix]]", "[[MOC Decisions]]"]
sources: ["https://docs.github.com/en/graphql/guides/forming-calls-with-graphql", "https://docs.github.com/en/graphql/reference/pulls", "https://docs.github.com/en/graphql/reference/issues", "https://docs.github.com/en/graphql/reference/repos", "https://docs.github.com/en/graphql/reference/users", "https://spec.graphql.org/"]
superseded_by: 
---

# ADR-035 GitHub GraphQL and Host-Wide Read Labels as Built

> GraphQL gets the same verbs as REST, and a read the broker cannot bound to one repository counts as a read of private data.

## Status

built (2026-09-25, M3). Amends [[ADR-029 GitHub API Adapter and Session Labels as Built]] items 1 (GraphQL) and 4 (labels); ADR-029 stays in force otherwise.

## Context

- **GraphQL was refused.** ADR-029 denied `POST /graphql` until a strict parser existed. The real-server run of M3 D3 (CI job `real-mcp`, 2026-09-25) showed what that costs: the GitHub MCP server's `list_issues` uses GraphQL and failed (`github_graphql_unsupported`), and `gh` uses GraphQL for most commands (`gh pr create` is the `createPullRequest` mutation). [[GitHub API Adapter]] already specified the design as a Proposal: parse strictly, map every top-level mutation to a verb, deny unknown mutations, ambiguous operations and parse errors, map queries to read verbs where determinable, otherwise to a coarse read.
- **A label gap (found while reading the adapter).** ADR-029 raised `sensitive_read` only for `repo.read` of a non-public repository. Host-wide reads (`github.read`: `/search/code`, `/user/repos`, `/orgs/{o}/repos`, `/notifications`) never raised it, although they can return private repository content the credential can see. A toxic flow through search (public issue → `GET /search/code?q=org:acme+password` → public PR) therefore passed the Rule-of-Two forbid. Reproduced: `m3_graphql::a_host_wide_search_is_a_sensitive_read` fails with the old rule (`200 200 201`) and passes with the new one (`200 200 403`).
- Facts checked on 2026-09-25 against GitHub's GraphQL reference and guide: the endpoint is `POST https://api.github.com/graphql` with a JSON body holding `query` and optional `variables`; `CreatePullRequestInput.repositoryId: ID!` (plus optional `headRepositoryId`), `MergePullRequestInput.pullRequestId: ID!`, `EnablePullRequestAutoMergeInput.pullRequestId: ID!`, `EnqueuePullRequestInput.pullRequestId: ID!`, `AddCommentInput.subjectId: ID!` (payload `commentEdge`, `subject: Node`); `Query.repository(owner: String!, name: String!, followRenames: Boolean)`; the fields of `Repository`, `RepositoryOwner` (which has `repositories` and `repository`), `Actor`, `User`, `Issue`, `PullRequest`, `IssueComment`, `Label`, `Milestone` and the connection types used below.

## Decision

1. **Endpoint** (`l7::github::graphql_endpoint`): `POST /graphql` on api.github.com, `POST /api/graphql` on GitHub Enterprise. A query string is refused (`github_graphql_invalid`: it could carry a second `query` a server might prefer); other methods are `github_graphql_unsupported`. The request must be `Content-Type: application/json` (optionally `charset=utf-8`), exactly once: a form-encoded body could hold a different `query` for a server that reads forms.
2. **Body** (`l7::github::graphql::map`, at most 1 MiB): one JSON object, duplicate keys rejected at any depth, only `query` (string), `variables` (object or null) and `operationName` (string or null).
3. **Document** (`l7::graphql`, a new parser with property tests and the `graphql` fuzz target): executable definitions only; stricter than the spec where readers could differ: ASCII outside strings; comments of printable ASCII only (no NUL, no Unicode line separators another lexer might end a comment on); no control characters in strings; `\uXXXX` escapes only (surrogates paired); block strings kept raw and never used as values; nesting at most 48; at most 100,000 tokens. Directives are parsed and ignored, so `@skip` never hides a field from the adapter.
4. **Operation choice**: the operation named by `operationName`, or the only operation; duplicate names, an anonymous operation among others, or several operations without a name are refused; subscriptions are refused. Root fields are collected through fragments whose type condition is the root type; a fragment on another type at the root (`query { ...F } fragment F on Mutation`) is refused. Fragment cycles and unknown fragments are refused; shared fragments are walked once (memoised).
5. **Mutations**: every root field except `__typename` must be one of `createPullRequest` → `pr.create`, `mergePullRequest` / `enablePullRequestAutoMerge` / `enqueuePullRequest` → `pr.merge`, `addComment` → `issue.comment`; anything else is `github_graphql_mutation_unknown`. Each takes exactly one argument, `input`; the node ID (`repositoryId`, `pullRequestId`, `subjectId`) comes from the literal object (duplicate fields refused) or from `variables` (or the variable's default), must be a string of `[A-Za-z0-9_=+/-]`, 1–200 bytes; at most 16 mutations per request.
6. **Node resolution** (`brokerd` L7 step 3b): the broker authorizes the request's HTTP action alone to learn which credential the grant admitting this host binds, then asks GitHub itself (`node(id:)` returning the type and `repository { nameWithOwner visibility }`) with that credential, and caches the answer for the session. A verb is filled only when the node has the type it acts on (`Repository` for `pr.create`, `PullRequest` for `pr.merge`, `Issue` or `PullRequest` for `issue.comment`). An unresolved node denies with `github_repo_not_allowed`, the same reason as an ungranted repository, so the agent learns nothing about which IDs exist; the audit row records `node_unresolved`. The final decision must bind the same credential (`ambiguous_credential` otherwise). The repository's visibility from the lookup feeds the labels and the public-sink rules.
7. **Queries**: `repository(owner:, name:)` is `repo.read` on that repository (arguments from literals or variables; anything else refused). `viewer`, `user`, `repositoryOwner`, `rateLimit` and introspection (`__schema`, `__type`) are `github.read` of public data (no labels) when their selection is confined. Every other root field (`search`, `node`, `nodes`, `organization`, …) is an **unconfined** `github.read`.
8. **Confinement** (`l7::github::schema`): an allowlist of (type, field) pairs whose every edge stays inside the repository being read (its issues, pull requests, comments, labels, milestones, default branch name, owner login) or on an actor's public login fields. Any other field (an owner's `repositories`, a PR's `headRepository`, timelines, projects, sub-issues, `... on User { repositories }`), a fragment on an unlisted type, or a selection on a leaf makes the read unconfined, which adds an unconfined `github.read`. Selecting `Issue`, `PullRequest` or `IssueComment` marks the read as carrying bodies. Mutation payloads are walked the same way; a confined payload needs no extra verb (as REST returns the created PR).
9. **Labels** (amends ADR-029 item 4): `github.read` raises `sensitive_read` unless it is known to read public data only: REST routes whose first segment is `rate_limit`, `meta`, `zen`, `octocat`, `emojis`, `versions`, `licenses`, `gitignore` or `codes_of_conduct`, and the confined GraphQL host reads above. On GitHub and S3 hosts the request's HTTP method no longer raises `external_effect` by itself: the verb or operation decides (a GraphQL query is a POST that writes nothing).
10. **Audit**: each GraphQL verb's row names its root field (`graphql`) and, for mutations, the node ID.
11. **Rule of Two on adapted hosts** (added 2026-09-26 after the real-server run): the Rule-of-Two forbid keyed on `http.write`, so every GraphQL *read* (a POST) was refused once both labels were live (seen in CI run 36188997307: `http POST /graphql => rule_of_two; github github.read => allow`). The HTTP action now carries `adapted` (the request has a GitHub or S3 verb), the `rule-of-two` forbid skips adapted HTTP actions, and a new `rule-of-two-verbs` forbid covers every write those adapters map (`pr.create`, `pr.merge`, `issue.comment`, `contents.write`, `gist.create`, `s3.put`, `s3.delete`). Every non-GET request on those hosts that the adapters allow maps to one of these verbs, so no write loses the rule; plain HTTP writes, registry uploads and `git.push` are unchanged. Tests: `policy::cedar::github_tests::verbs_decide_and_the_rule_of_two_fires` (reads by POST pass, writes by any method are stopped, a verb-less POST is still stopped), `m3_graphql::the_toxic_flow_over_graphql_is_stopped_at_the_public_write` (a read after both labels passes, the PR is denied), `policy::cedar::s3_tests::s3_writes_are_subject_to_the_rule_of_two`.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Pass GraphQL through as `http.POST` | A mutation (merge, write) hides in it (ADR-029). |
| Label every GraphQL query as a sensitive read | Breaks ADR-010's benign case for every `gh` user (issue read, `viewer`, then `createPullRequest` on the same public repository). The confinement allowlist keeps that case working and is sound by construction. |
| Model GitHub's whole schema | Tens of thousands of fields; a mistake in one edge would under-label. A small allowlist fails toward over-labelling. |
| Map node IDs by decoding them | Node ID formats are GitHub internals and change; the broker asks GitHub, as it already does for visibility. |
| Resolve node IDs with a separate broker credential | The credential the grant binds is the one whose view matters, and the same one the REST visibility lookup uses. |
| Allow host-wide reads without `sensitive_read` when the task is small | The label is about what the response may contain, not the task. |

## Consequences

- The GitHub MCP server's GraphQL tools and `gh` work under the broker with the same verbs as REST; a grant needs `github.read` for `viewer` lookups and host-wide queries.
- Sessions that search or list across repositories now raise `sensitive_read`, so a later public write after untrusted input needs approval (the Rule of Two); that is the intended narrowing.
- **Transferred issues (resolved):** GraphQL does not resolve an issue by the number it had before a transfer, so a confined read of the old number cannot return another repository's issue; verified 2026-09-26 with the owner's token and the CI test token: `Marioiubas/sandboxpublictest#2` was transferred to `Marioiubas/sandboxprivatetest#1`; GraphQL `repository(sandboxpublictest) { issue(number: 2) }` and `issueOrPullRequest(number: 2)` return `null` with `NOT_FOUND`, even for a token that can read the private repository, while REST `GET /repos/Marioiubas/sandboxpublictest/issues/2` answers `301` to the new location (which the broker does not follow). The CI job `real-mcp` re-checks both answers on every run (`code/tests/e2e/mcp_github_real/transfer_check.sh`) ([[Open Questions and Unverified Claims]]).
- **Residual:** `repository(owner:, name:)` follows renames by default (`followRenames`); a renamed repository resolves to the repository that held the name. The visibility lookup (REST, not following redirects) then reads as unknown, which only narrows.
- Mutations cost one extra GitHub request per new node ID per session.
- **Real server (CI `real-mcp`, run 36186497093):** the GitHub MCP server v1.12.2's `list_issues` works and is logged as `repo.read` on the repository plus an unconfined `github.read`: its query selects `issueFieldValues`, and organisation issue fields can be `ORG_ONLY` (GitHub's `IssueFieldVisibility`: `ALL`, `ORG_ONLY`), so their values on a public repository's issue are not public; its `issue_read` enrichment (`nodes(ids:)` with sub-issue `parent` and `closedByPullRequestsReferences`) can reach other repositories. Both correctly raise `sensitive_read`. With this server, reading an issue therefore counts as a sensitive read, and a later public write after untrusted input needs approval: ADR-010's benign case holds for REST and `gh`, not for this server's issue tools.
- Other mutations (`createIssue`, `updatePullRequest`, `createCommitOnBranch`, reviews, labels) are refused until mapped.

## Invariants affected

Strengthens the Rule-of-Two labels ([[Trifecta Session Labels]]); upholds I1 (lookups use the broker's credential; the sandbox holds a sentinel), I7 and I9 (every GraphQL verb and lookup outcome is logged). Weakens none.

## Tests

`l7::graphql::tests::*` (round-trip property test, rejection corpus, nesting bound, never-panics), `l7::github::graphql::tests::*` (confinement, host reads, mutations and node IDs, unknown and hidden mutations, operation choice, strict body, argument determinability, memoised fragments, the query-never-writes property), `l7::github::schema::tests::*`, `policy::github::tests::label_rules`, `m3_graphql::*` (mapping and denies end to end with node lookups against a fake GitHub; the toxic flow over GraphQL; the search flow over REST and GraphQL; ADR-010's case over GraphQL), fuzz target `graphql`.

## Relationships

- decided-by:: M3 build
- amends:: [[ADR-029 GitHub API Adapter and Session Labels as Built]]
