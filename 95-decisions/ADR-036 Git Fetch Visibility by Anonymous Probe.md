---
title: "ADR-036 Git Fetch Visibility by Anonymous Probe"
aliases: ["ADR-036"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, boundary/tb3, milestone/m3]
status: built
confidence: medium
created: 2026-09-26
updated: 2026-09-26
summary: "A git fetch of a repository not known to be public raises `sensitive_read`. The broker learns visibility with one anonymous `info/refs?service=git-upload-pack` probe on the same git host per repository per session: a 200 upload-pack advertisement means public; 401/403/404, a redirect or a failure leave it not known to be public. Closes ADR-029's gap where cloning a private repository bypassed the Rule of Two."
related: ["[[ADR-029 GitHub API Adapter and Session Labels as Built]]", "[[Git Smart-HTTP Adapter]]", "[[Trifecta Session Labels]]", "[[GitHub MCP Toxic Flow]]", "[[M3 CI Identity and MCP]]", "[[MOC Decisions]]"]
sources: ["https://git-scm.com/docs/http-protocol"]
superseded_by: 
---

# ADR-036 Git Fetch Visibility by Anonymous Probe

> Cloning a private repository is a sensitive read, whichever protocol carried it.

## Status

built (2026-09-26, M3). Closes the gap recorded in [[ADR-029 GitHub API Adapter and Session Labels as Built]] ("a clone of a private repository over git smart-HTTP does not raise `sensitive_read`"), with a different mechanism than the one it planned.

## Context

The Rule of Two fires when a session has both `untrusted_input` and `sensitive_read`. ADR-029 raised `sensitive_read` for GitHub API reads of non-public repositories only; `git.fetch` raised nothing. A toxic flow could therefore read its private data with `git clone` (public issue through the API → clone of a private repository → public pull request) and pass the forbid. ADR-029 planned a visibility lookup through the GitHub API when the API host is admitted, which covers only GitHub and only sessions that also admit `api.github.com`.

Git's smart HTTP protocol (git-scm.com, "http-protocol", checked 2026-09-26): smart clients "MUST discover references by making a parameterized request for the info/refs file" (`GET $GIT_URL/info/refs?service=git-upload-pack`), and the server's "Content-Type MUST be `application/x-$servicename-advertisement`"; access control is standard HTTP authentication in front of the git server. A repository that anyone may fetch therefore answers the advertisement to a request without credentials; the 401 that GitHub and the test forge return for others is server behaviour, not part of the protocol document, and any non-200 answer counts as not public.

## Decision

1. **Label**: a `git.fetch` action (upload-pack `info/refs` or `git-upload-pack`) of a repository whose visibility is not `public` raises `sensitive_read` after the allow is logged, like other labels ([[Trifecta Session Labels]]).
2. **Probe**: before raising labels for a request with `git.fetch` actions, the broker sends, once per repository per session, `GET /<owner>/<name>.git/info/refs?service=git-upload-pack` to the same host, over verified TLS to the admitted addresses, **without any credential**. 200 with the upload-pack advertisement content type → `public`; 401, 403 or 404 → `private`; anything else (redirect, other status, timeout after 10 s, connection failure) → `unknown`. Only `public` avoids the label.
3. **Cache**: the result goes into the session's visibility cache keyed by repository (`host[:port]/owner/name`), shared with the GitHub API lookups, so either source informs both.
4. `git.push` is unchanged: pushes raise `external_effect`, and the public-sink rule still treats every push as a public sink (a probe's 401 cannot tell private from nonexistent).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| GitHub API lookup (ADR-029's plan) | GitHub only, and only when the API host is admitted for the session; the probe works on any smart-HTTP host with no extra grant. |
| Label every fetch as sensitive | Cloning public dependencies would then block the benign "read a public issue, open a PR on that public repository" case whenever a public repository was also cloned. |
| Probe with the session's credential | Would show only that the credential can read it, not that anyone can. |
| Probe before deciding the request | The label does not change this request's decision; probing after the allow keeps the decision path unchanged and adds one request only on a repository's first fetch in a session. |

## Consequences

- Cloning or fetching a private repository now counts toward the Rule of Two; a session that has also read untrusted input needs approval for its writes (including pushes). That is the intended narrowing.
- One extra anonymous request per repository per session, to the host the agent is fetching from.
- A host that serves public repositories only to known user agents or only after a redirect reads as `unknown`, which only narrows.

## Invariants affected

Strengthens the trifecta labels; upholds I1 (the probe carries no credential) and I9 (labels are logged as `session.label` events). Weakens none.

## Tests

`m3_git_labels::fetching_a_public_repository_is_not_a_sensitive_read` (the probe is anonymous, the fetch is brokered), `m3_git_labels::fetching_a_private_repository_is_a_sensitive_read` (one label and one probe for two fetches in a session), against the fake GitHub running `git http-backend`; the m1 git scoping tests still pass.

## Relationships

- decided-by:: M3 build
- amends:: [[ADR-029 GitHub API Adapter and Session Labels as Built]]
