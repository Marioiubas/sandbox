---
title: "ADR-033 Public-Sink Rule as Built"
aliases: ["ADR-033"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/trifecta, invariant/i3, milestone/m3]
status: built
confidence: medium
created: 2026-09-25
updated: 2026-09-25
summary: "`[trifecta] deny_public_sinks_after_untrusted_input = true` (user or org policy, off by default) adds Cedar forbids: once untrusted_input is live, write verbs on repositories not known to be private, every git push, gist.create and pkg.publish are denied unless approved (reason public_sink_after_untrusted_input). Unknown visibility counts as public; the forbids survive every engine rebuild and are proved a narrowing by the gates."
related: ["[[ADR-010 Session-Level Trifecta Labels in the MVP]]", "[[Trifecta Session Labels]]", "[[Agents Rule of Two]]", "[[Example Cedar Policies]]", "[[ADR-029 GitHub API Adapter and Session Labels as Built]]", "[[M3 CI Identity and MCP]]", "[[SymCC CI Gates]]", "[[MOC Decisions]]"]
sources: ["https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/"]
superseded_by: 
---

# ADR-033 Public-Sink Rule as Built

> An org can say that a session which has read something anyone could write may not then write anywhere the public can see, without approval.

## Status

built (2026-09-25, M3).

## Context

[[ADR-010 Session-Level Trifecta Labels in the MVP]] item 3 and [[Trifecta Session Labels]] propose an optional org rule answering Willison's point that "[A]+[C] without [B]" is still dangerous ([simonwillison.net](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)). [[Example Cedar Policies]] sketches it as a forbid on `http.write` and `git.push` against a `Repo` with `visibility == "public"`, and notes it cannot compile as written because HTTP actions target `Host`. [[ADR-029 GitHub API Adapter and Session Labels as Built]] left it unbuilt.

## Decision

1. **Switch:** `[trifecta] deny_public_sinks_after_untrusted_input = true` in user or org policy; default off, so ADR-010's benign case (a PR on the public repository whose issue was read) stays allowed. Repository policy may not contain `[trifecta]`.
2. **Public sinks**, as the broker can identify them: the GitHub write verbs `pr.create`, `pr.merge`, `issue.comment` and `contents.write` on a repository whose visibility is not known to be private (unknown counts as public, which narrows); every `git.push` (git actions carry no looked-up visibility yet); `gist.create`; `pkg.publish`. Two Cedar forbids, `public-sink-after-untrusted-input` (on `Repo`) and `public-sink-after-untrusted-input-host`, with `@reason("public_sink_after_untrusted_input")`, both `unless { context.session.approved }` like the Rule of Two, so the future approval flow applies to both (today approval is never set, so they always deny).
3. **Assembly:** the forbids are kept on the compiled policy as option policies and included in every rebuild of the base set (the MCP rebuild dropped them in the first version; the conformance test caught it).
4. **Explanation:** as with the Rule of Two, a more specific reason (for example an ungranted verb) is reported when the explainer finds one.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| On by default | ADR-010 keeps [A]+[C] allowed by default; flipping it is a product decision that needs design-partner data ([[Agents Rule of Two]]). |
| Count only repositories known to be public | Unknown visibility would slip through; fail closed. |
| Classify arbitrary hosts' `http.write` as public sinks | The broker cannot tell which hosts publish; paste sites and tunnels are already forbidden by the ceiling. |
| No approval escape | Would diverge from the Rule of Two's shape; approval is not built, so the effect is the same today. |

## Consequences

- With the option on, a session that reads a public issue cannot push, open PRs outside known-private repositories, create gists or publish packages; users start a new session (one task per session, [[Trifecta Session Labels]]) or wait for step-up approval.
- Tests: `cedar::github_tests::the_org_option_denies_public_sinks_after_untrusted_input` (including through the MCP rebuild), `gates::tests::the_public_sink_option_is_a_proved_narrowing`, `m3_github::with_the_org_option_the_public_pr_after_a_public_issue_is_denied`.
- **Not built:** per-repository visibility for git pushes, web pages as untrusted input, step-up approval.

## Invariants affected

Narrows only; the gates prove turning it on is a narrowing (I3, [[SymCC CI Gates]]). Weakens none.

## Relationships

- decided-by:: M3 build
- implements:: [[ADR-010 Session-Level Trifecta Labels in the MVP]]
