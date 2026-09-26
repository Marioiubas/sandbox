---
title: "ADR-029 GitHub API Adapter and Session Labels as Built"
aliases: ["ADR-029"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, topic/credentials, invariant/i3, invariant/i1, milestone/m3]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-26
summary: "GitHub REST requests map to verbs from a verified route table (GraphQL denied until parsed); `protocol = \"github\"` grants `verbs` on `repos` (default: the task repository); the broker looks up repository visibility itself with the bound credential and re-decides; session labels are raise-only, raised from API facts before forwarding, logged per decision and as `session.label` events; credential risk comes from config."
related: ["[[GitHub API Adapter]]", "[[Trifecta Session Labels]]", "[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[Broker Cedar Schema]]", "[[Example Cedar Policies]]", "[[GitHub MCP Toxic Flow]]", "[[M3 CI Identity and MCP]]", "[[ADR-035 GitHub GraphQL and Host-Wide Read Labels as Built]]", "[[MOC Decisions]]"]
sources: ["https://docs.github.com/en/rest/pulls/pulls", "https://docs.github.com/en/rest/issues/comments", "https://docs.github.com/en/rest/repos/contents", "https://docs.github.com/en/rest/repos/repos", "https://docs.github.com/en/rest/gists/gists", "https://docs.github.com/en/rest/issues/issues"]
superseded_by: 
---

# ADR-029 GitHub API Adapter and Session Labels as Built

> Every GitHub REST request is a verb or a deny, and the broker, not the model, decides when a session has read something private or something anyone can write.

## Status

built (2026-09-24, M3 step 1). Amended by [[ADR-035 GitHub GraphQL and Host-Wide Read Labels as Built]]: GraphQL is now mapped (item 1), and host-wide `github.read` raises `sensitive_read` unless known public (item 4).

## Context

[[GitHub API Adapter]] and [[Trifecta Session Labels]] specify verbs and labels; [[ADR-010 Session-Level Trifecta Labels in the MVP]] makes the toxic-flow replay the test. Route shapes were checked against GitHub's REST reference on 2026-09-24: `POST /repos/{owner}/{repo}/pulls` (create), `PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge`, `POST /repos/{owner}/{repo}/issues/{issue_number}/comments`, `PUT` and `DELETE /repos/{owner}/{repo}/contents/{path}`, `POST /gists`, `GET /repos/{owner}/{repo}`, whose response carries `private` (boolean, required) and `visibility` (`public` or `private`) ([pulls](https://docs.github.com/en/rest/pulls/pulls), [issue comments](https://docs.github.com/en/rest/issues/comments), [contents](https://docs.github.com/en/rest/repos/contents), [repos](https://docs.github.com/en/rest/repos/repos), [gists](https://docs.github.com/en/rest/gists/gists)).

## Decision

1. **Route table** (`code/crates/l7/src/github.rs`): `GET|HEAD /repos/{o}/{r}[/…]` → `repo.read` (issue and PR paths flagged as bodies); `pr.create`, `pr.merge`, `issue.comment`, `contents.write` on the routes above; `POST /gists` → `gist.create`; other `GET|HEAD` → `github.read` (search flagged as bodies). `POST /graphql` → `github_graphql_unsupported`; everything else → `github_route_unknown`. GitHub Enterprise hosts use the `/api/v3` prefix. The table is hand-written from the verified routes, not generated from the OpenAPI description (a deviation; generation arrives with G1).
2. **Policy** (`protocol = "github"`, `verbs`, `repos`): each request is two Cedar requests, `http.<METHOD>` on the host and the verb on the `Repo` (child of the API host, with its `visibility`) or on the host. `repos` absent means the task repository only; `methods`/`paths` are rejected on a GitHub grant. Schema: `GitHubCtx`, `repo.read`, `github.read`, `gist.create`; record mode permits verbs (`record#github`) with the approval forbids intact.
3. **Visibility**: decide with the session cache; if a repository's visibility is unknown and the decision allowed, the broker reads `GET /repos/{o}/{r}` itself on the same host with the credential the decision bound, caches the answer (failure: `unknown`), and decides again with it; that decision is final (a different credential binding denies).
4. **Labels** (`policy::github::Labels`, raise-only; a property test checks no sequence lowers one): after the final allow and before forwarding, a `repo.read` of a non-public repository raises `sensitive_read`; issue/PR/comment bodies or search results from a non-private source raise `untrusted_input`; any write raises `external_effect`; a credential with `risk = "high"` raises `sensitive_read`. Unknown visibility raises both read labels (it only narrows). Labels are shared with a shadow candidate, recorded on every L7 decision row, and each raise is a `session.label` event naming the request and cause.
5. **Credential risk** comes from config (`risk = "high"`, default `standard`); the entity attribute is no longer hard-coded `high`, which would have raised `sensitive_read` on every brokered call and blocked ADR-010's benign case.
6. **Deny reasons**: an approval-conditional forbid (`needs_approval`, `rule_of_two`) yields to a specific "not granted" explanation, since approval would not help there.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Learn visibility only from proxied `GET /repos/{o}/{r}` responses | MCP servers and agents often read issues and contents without fetching metadata; the toxic flow would go unlabelled. |
| Treat unknown visibility as public | Would under-raise `sensitive_read`; unknown must only narrow. |
| Pass GraphQL through as `http.POST` | A mutation (merge, write) could hide in it; deny until a strict parser maps it. |
| Raise labels after the response | A failed read would be un-labelled while its bytes may still reach the agent; raising before forwarding only narrows. |

## Consequences

- The GitHub MCP toxic flow is stopped at the public write (`m3_github::d5_toxic_flow_is_stopped_at_the_public_write`); a public-issue read followed by a PR on that public repository is allowed.
- `gh` commands that use GraphQL are denied on a GitHub grant until GraphQL parsing lands.
- **Gap:** a clone of a private repository over git smart-HTTP does not raise `sensitive_read` in M3 (the broker has no visibility for git hosts yet); the API path does. Planned: a broker-side visibility lookup for git fetches when the API host is admitted. **Closed 2026-09-26** by [[ADR-036 Git Fetch Visibility by Anonymous Probe]] (an anonymous `info/refs` probe on the git host instead).
- **Not built:** "arbitrary web pages" as untrusted input, the org option forbidding public-sink writes under `untrusted_input`, author-association filtering, and the step-up approval flow (writes that need approval are denied).

## Invariants affected

Upholds I3 (labels only rise, from system facts) and I1 (the visibility lookup attaches the real credential broker-side; the sandbox holds a sentinel). Weakens none.

## Relationships

- decided-by:: M3 build
- motivated-by:: [[GitHub MCP Toxic Flow]], [[ADR-010 Session-Level Trifecta Labels in the MVP]]

## Build log

- 2026-09-24: created and built. Code: `code/crates/l7/src/github.rs`, `code/crates/l7/src/classify.rs`, `code/crates/policy/src/github.rs`, `code/crates/policy/src/cedar/{compile.rs,schema.cedarschema,entities.rs}`, `code/crates/policy/src/{l7.rs,egress.rs,config.rs}`, `code/crates/brokerd/src/l7_pipeline/github.rs`, `code/crates/audit/src/{event.rs,reason.rs}`. Tests: `l7::github::tests::*` (routes, unmapped deny, property test), `policy::github::tests::{labels_never_go_down, label_rules}`, `policy::cedar::github_tests::*` (fail-closed compile, verbs and Rule of Two, Cedar vs explainer property test), `m3_github::*` (D5, the benign case, unmapped/ungranted denies); fuzz target `github_route` (634k runs locally, in the CI smoke).
