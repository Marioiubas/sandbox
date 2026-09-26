---
title: "ADR-040 Label Sources Beyond the Adapters"
aliases: ["ADR-040"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, boundary/tb3, milestone/m3]
status: built
confidence: medium
created: 2026-09-26
updated: 2026-09-26
summary: "Closes seven label gaps a security review proved: maintainer-only GitHub routes are private even on public repositories; commit comments, events, files at pull-request refs, gists, notifications and repositories-by-ID are attacker-writable text; a brokered credential on a host without an adapter reads sensitive data; intranet addresses (private, link-local) and grants marked `sensitive = true` raise `sensitive_read` at admission; push advertisements are git reads; the git visibility probe asks about the exact path fetched; fetching `refs/pull/*` (and any v0 fetch) of a non-private repository is untrusted input."
related: ["[[Trifecta Session Labels]]", "[[ADR-029 GitHub API Adapter and Session Labels as Built]]", "[[ADR-036 Git Fetch Visibility by Anonymous Probe]]", "[[ADR-039 Model API Is Not a Rule-of-Two Sink]]", "[[GitHub API Adapter]]", "[[Git Smart-HTTP Adapter]]", "[[MOC Decisions]]"]
sources: ["https://docs.github.com/en/rest", "https://git-scm.com/docs/protocol-v2"]
superseded_by: 
---

# ADR-040 Label Sources Beyond the Adapters

> A label is raised by what a request can return, not only by what the adapters were first written to recognise.

## Status

built (2026-09-26, M3). Found by a review agent that proved each gap with a failing test (`code/tests/conformance/tests/m3_label_gaps_github.rs`, `m3_label_gaps_git.rs`); the MCP label gap it also found is handled separately.

## Context

The Rule of Two holds only if `sensitive_read` and `untrusted_input` are raised by every path that reads private data or attacker-writable text. ADR-029, ADR-035 and ADR-036 covered GitHub issue/PR reads, host-wide reads and git clones. The review showed the next layer: requests those rules did not see.

## Decision

1. **GitHub REST, private data under public repositories**: only sub-routes on an allowlist (`PUBLIC_ON_PUBLIC` in `code/crates/l7/src/github.rs`: the repository, contents, git, commits, branches, tags, releases, issues, pulls, comments, events, checks, statuses, deployments, archives, and `actions/{runs,workflows,jobs,artifacts}`) take the repository's visibility; every other `/repos/{o}/{r}/…` read (secret-scanning and code-scanning alerts, draft advisories, Dependabot, hooks, keys, invitations, collaborators, traffic, environments, Actions secrets and variables) is private whatever the repository is.
2. **GitHub REST, attacker-writable text**: issues, pulls, comments and events under a repository, files read at a pull request's ref or by commit hash (`?ref=refs/pull/…`, `?ref=<hex>`), and the host-wide `search`, `gists`, `notifications` and `repositories/{id}/…` (where GitHub redirects transferred issues) carry bodies.
3. **Credentialed reads without an adapter**: a request that carried a brokered credential on a host no adapter judges (not GitHub, S3 or git) raises `sensitive_read`, unless every admitting grant is the model API ([[ADR-039 Model API Is Not a Rule-of-Two Sink]]) or says `sensitive = false`.
4. **Intranet and declared-sensitive hosts**: a connection admitted on a `private` or `link_local` address raises `sensitive_read` at admission, spliced or terminated, unless an admitting grant says `sensitive = false`; a grant with `sensitive = true` raises it for any address. Loopback is not an intranet class by default (the broker cannot tell a local service's data apart); mark such grants `sensitive = true`. Repository policy may not set `sensitive`.
5. **Git**: a push's ref advertisement is a git read like a fetch (probe and label). The anonymous probe asks about exactly the path the client used, cached per path: a server may treat `Acme/x` and `acme/x` as different repositories. An upload-pack request that names `refs/pull/*` (protocol v2 `ref-prefix`/`want-ref`), any protocol v0 upload-pack request (its wants are bare object IDs the broker cannot place), or an unreadable one marks the fetch `pull_refs`; such a fetch of a repository not known to be private raises `untrusted_input` (a pull request's head is written by its author; `gh pr checkout` fetches it).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Deny the maintainer-only routes | Legitimate reads for a trusted task; the label is the right tool, and a grant's verbs already bound them. |
| Treat every read of a public repository as untrusted | Over-labels maintainer content (branch files, releases) and breaks ADR-010's benign case for every clone-and-PR flow. |
| Parse responses to place v0 wants | Large and stateful; v0 is not git's HTTP default. Counting v0 fetches as possibly PR content fails closed. |
| Label loopback as intranet | Every local development server and test double would raise `sensitive_read`; the `sensitive` key makes it explicit instead. |

## Consequences

- More sessions reach both labels; writes then need an approval ([[ADR-037 Step-Up Approvals as Built]]), while the model API keeps working (ADR-039).
- **Residual:** a protocol v2 fetch of a pull request's head *by object ID* after an unrestricted ref listing is not recognised; attacker text reached through routes this ADR does not list is not labelled untrusted.
- **Residual:** anonymously readable repositories on an intranet git host count as public (the probe runs from the broker's network).

## Invariants affected

Strengthens the trifecta labels; upholds I1 (the git probe carries no credential) and I4 (repository policy cannot declare sensitivity). Weakens none.

## Tests

`l7::github::tests::routes_map_to_verbs` (restricted routes, bodies, `ref` queries), `l7::git::tests::pull_request_refs_are_recognised_in_upload_pack_requests` and `upload_pack_reader_is_total`, `policy::egress::sensitivity::tests::intranet_addresses_and_declared_grants_are_sensitive`, end to end `m3_label_gaps_github::*` and `m3_label_gaps_git::*`; `m3_git_labels`, `m1_git` and the GitHub suites still pass.
