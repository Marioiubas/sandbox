---
title: "Example Cedar Policies"
aliases: ["Cedar Policy Examples"]
type: concept
section: policy
tags: [sandbox/policy, concept, topic/policy, topic/git, topic/mcp, topic/credentials, control/task-tok, control/hitl, milestone/m2]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The five sketch policies (credential host ceiling, task expiry, push only to refs/heads/agent/* on the task repo without force, Rule of Two approval gate, pinned MCP servers only) plus the group-push and publish-requires-approval examples."
related: ["[[Broker Cedar Schema]]", "[[Cedar]]", "[[Trifecta Session Labels]]", "[[Agents Rule of Two]]", "[[Git Smart-HTTP Adapter]]", "[[MCP Guard]]", "[[SymCC CI Gates]]", "[[GitHub MCP Toxic Flow]]", "[[M2 Policy Audit and Learn]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[GitLost GitHub Agentic Workflows Leak]]", "[[postmark-mcp Rug Pull]]", "[[Cursor CurXecute and MCPoison]]", "[[GitHub API Adapter]]", "[[Registry and LLM API Adapters]]", "[[broker.toml Human Policy Layer]]", "[[I7 Reject Foreign Credentials]]", "[[M1 Secrets Outside]]", "[[M3 CI Identity and MCP]]", "[[Lethal Trifecta]]"]
sources: ["https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md", "https://invariantlabs.ai/blog/mcp-github-vulnerability", "https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html", "https://ai.meta.com/blog/practical-ai-agent-security/", "https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks", "https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison", "https://www.anthropic.com/engineering/claude-code-sandboxing", "https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app"]
code: ["code/policies/default.cedar", "code/policies/ceiling.cedar"]
---

# Example Cedar Policies

> The five sketch policies (credential host ceiling, task expiry, push only to refs/heads/agent/* on the task repo without force, Rule of Two approval gate, pinned MCP servers only) plus the group-push and publish-requires-approval examples.

## Summary

These are the reference policies the MVP ships as its default bundle, and the fixtures the policy engine and [[SymCC CI Gates]] are tested against. They are written against [[Broker Cedar Schema]]. **All code below is Proposal; not compiled.** Each policy is paired with the incident it would have stopped and the decision it produces for a worked request.

## The five core policies (verbatim from the report)

```cedar
// Org ceiling: a credential is only ever attached for its declared hosts.
forbid (principal, action == Broker::Action::"credential.use", resource)
unless { resource.allowed_hosts.contains(context.dest_host) };

// Every grant expires with its task.
forbid (principal, action, resource) when { context.session.now >= principal.expires_at };

// Push only to the task repo, only to agent/* branches, never force.
permit (principal is Broker::Task, action == Broker::Action::"git.push", resource is Broker::Repo)
when { resource.full_name == principal.repo
       && context.ref like "refs/heads/agent/*" && !context.force };

// Rule of Two: once untrusted input and a sensitive read are both live,
// writes and pushes need out-of-band approval.
forbid (principal, action in [Broker::Action::"http.write", Broker::Action::"git.push"], resource)
when { context.session.trifecta.untrusted_input && context.session.trifecta.sensitive_read }
unless { context.session.approved };

// Pinned MCP servers only.
forbid (principal, action == Broker::Action::"mcp.call_tool", resource) unless { resource.pinned };
```

Four of the five are `forbid`s. Cedar's proved semantics say a satisfied forbid always denies, and nothing is allowed unless explicitly permitted ([cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)). The forbids are therefore the org's hard floor, and the single `permit` is the only door. Every other permit (for fetch, reads, registry GETs, LLM API calls) comes from the compiled [[broker.toml Human Policy Layer]].

### 1. Credential host ceiling

A credential entity lists `allowed_hosts`. No policy can attach it anywhere else. This is the Cedar half of the Cowork lesson: an attacker-planted API key used against the allowlisted `api.anthropic.com` exfiltrated data because the allowlist was only a destination filter ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). The other half is at the proxy: strip client credentials and reject any credential the broker did not issue ([[I7 Reject Foreign Credentials]], [[Claude Cowork Allowed-Domain Abuse]]). SymCC gate 3 proves this policy has no hole for every brokered credential ([[SymCC CI Gates]]).

### 2. Task expiry

One forbid expires every grant with its task, whatever permits exist. Time is epoch seconds because `datetime` support was not verified ([[Broker Cedar Schema]]).

### 3. Git push scope

GitHub installation tokens cannot scope branches or paths ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)). The [[Git Smart-HTTP Adapter]] parses `git-receive-pack` pkt-lines and emits one `git.push` request per ref update, with `ref` and `force` in context. Anthropic's web sandbox checks pushes against "the configured branch" with a custom git proxy ([Anthropic](https://www.anthropic.com/engineering/claude-code-sandboxing)); this policy is the neutral, declarative form of that check.

### 4. Rule of Two gate

Meta's Rule of Two says a session should combine at most two of: untrusted input, sensitive access and external state change ([Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/)). The broker computes the labels ([[Trifecta Session Labels]]); this forbid makes the rule executable. It would have stopped the GitHub MCP toxic flow, where a public issue drove an agent with an all-repo token to leak private repos through a public PR ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)), and the GitLost flow ([The Hacker News](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)).

### 5. Pinned MCP servers only

A server whose `tools/list` hash changed is unpinned until re-approved, so every call to it is denied. This addresses rug pulls and shadowing ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)) and the MCPoison class, where approval was bound to a name, not content ([Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)). See [[MCP Guard]], [[postmark-mcp Rug Pull]], [[Cursor CurXecute and MCPoison]].

## Additional examples

From the landscape research note (**Proposal; not compiled**; note it uses un-namespaced names and a `resource.repo`/`resource.ref` shape that differs from the schema):

```cedar
permit (principal in Group::"eng", action == Action::"git.push", resource)
when { resource.repo == context.session.repo && resource.ref like "refs/heads/agent/*" };
forbid (principal, action == Action::"pkg.publish", resource) unless { context.approved };
```

Rewritten against [[Broker Cedar Schema]] (**Proposal; not compiled**). A `Task` is not in a `Group`, so group membership is checked through the owner:

```cedar
permit (principal is Broker::Task, action == Broker::Action::"git.push", resource is Broker::Repo)
when { principal.owner in Broker::Group::"eng"
       && resource.full_name == principal.repo
       && context.ref like "refs/heads/agent/*" && !context.force };

// Requires declaring "pkg.publish" in the schema (see Broker Cedar Schema).
forbid (principal, action == Broker::Action::"pkg.publish", resource)
unless { context.session.approved };
```

The identity research note's example intent, read and open PRs on one repo while the task is live (**Proposal; not compiled**):

```cedar
permit (principal is Broker::Task,
        action in [Broker::Action::"http.GET", Broker::Action::"http.POST"],
        resource in Broker::PathPrefix::"api.github.com/repos/acme/web/pulls")
when { principal.repo == "acme/web" };
// expiry is already enforced by the task-expiry forbid above
```

**Proposal:** Two more org-ceiling forbids for the default bundle:

```cedar
// Opening a PR is fine; merging it is irreversible and needs approval.
forbid (principal, action == Broker::Action::"pr.merge", resource) unless { context.session.approved };

// Stricter Willison variant: no public-sink writes at all once untrusted input is live.
forbid (principal, action in [Broker::Action::"http.write", Broker::Action::"git.push"], resource is Broker::Repo)
when { context.session.trifecta.untrusted_input && resource.visibility == "public" };
```

The second one answers the critique that "[A]+[C] without [B]" is still dangerous ([simonwillison.net](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)). As written it would need `http.write` to target a `Repo`, which the schema does not allow (HTTP actions target `Host` and `PathPrefix`), so it must be split per action when compiled.

## Worked decisions

Task `task-01J9`: owner in `eng`, `repo = "acme/web"`, `branch_prefix = "agent/"`, not expired. Session labels start all false.

| # | Request | Relevant policies | Decision | `broker why` reason |
|---|---|---|---|---|
| 1 | `git.push` `acme/web` `refs/heads/agent/fix-1`, `force=false` | push permit | Allow | permit `push-agent-branches` |
| 2 | `git.push` `acme/web` `refs/heads/main` | no permit matches | Deny | no permit (default deny) |
| 3 | `git.push` `acme/web` `refs/heads/agent/x`, `force=true` | permit condition false | Deny | no permit |
| 4 | `git.push` `attacker/web` `refs/heads/agent/x` | `full_name != principal.repo` | Deny | no permit |
| 5 | `credential.use` GitHub App credential for `dest_host = paste.example` | credential ceiling forbid | Deny | forbid `credential-host-ceiling` |
| 6 | Session reads a public issue (`untrusted_input`) and a private repo (`sensitive_read`), then POSTs a PR | Rule of Two forbid | Deny, prompt | forbid `rule-of-two`; approval shows the authority diff |
| 7 | Same as 6 after the user approves out of band | `approved = true` | Allow if a permit exists | permit plus approval id |
| 8 | Any request after `expires_at` | expiry forbid | Deny | forbid `task-expiry` |
| 9 | `mcp.call_tool` on a server whose tool descriptions changed | pinned forbid | Deny | forbid `pinned-mcp-only`; re-approval needed |

Rows 1-4 are the M1 acceptance criteria for push scoping ([[M1 Secrets Outside]]). Row 6 is the M3 toxic-flow replay ([[M3 CI Identity and MCP]], [[GitHub MCP Toxic Flow]]). The seeded-injection test in [[M2 Policy Audit and Learn]] ("post `~/.aws` to a paste site; push to attacker repo") is rows 4 and 5 plus the filesystem deny.

## How it connects

- depends-on:: [[Broker Cedar Schema]]
- depends-on:: [[Cedar]]
- depends-on:: [[Trifecta Session Labels]]
- implements:: [[Agents Rule of Two]]
- depends-on:: [[Git Smart-HTTP Adapter]]
- depends-on:: [[MCP Guard]]
- mitigates:: [[GitHub MCP Toxic Flow]]
- mitigates:: [[GitLost GitHub Agentic Workflows Leak]]
- mitigates:: [[Claude Cowork Allowed-Domain Abuse]]
- mitigates:: [[postmark-mcp Rug Pull]]
- mitigates:: [[Cursor CurXecute and MCPoison]]
- evaluated-by:: [[SymCC CI Gates]]
- delivered-by:: [[M2 Policy Audit and Learn]]

## Implications for the build

- Ship these as `code/policies/` templates and as test fixtures; the worked-decision table becomes a golden test.
- Give every policy an `@id` annotation so decisions and `broker why` name it.
- Declare `pkg.publish`, `pr.merge`, `pr.create` and friends in the schema before writing policies that reference them; SymCC validation will otherwise fail.
- The Rule of Two forbid is only as good as the labels. Label computation tests live with [[Trifecta Session Labels]].

## Open questions

- Should the Willison variant (no public writes after untrusted input) be on by default, or an org opt-in? It costs utility on "fix this public issue and open a PR" tasks.
- How should `approved` be scoped: per request, per verb, or per session for N minutes?

## Sources

- [cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)
- [Invariant Labs: GitHub MCP](https://invariantlabs.ai/blog/mcp-github-vulnerability); [Invariant Labs: tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [The Hacker News: GitLost](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html)
- [Meta AI: Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/); [Willison, Nov 2025](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- [Anthropic: How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude); [Anthropic: Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)
- [Tenable: CurXecute/MCPoison](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)
- [GitHub REST: installation tokens](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)

## Build log

- 2026-09-24: the core policies ship as `code/policies/default.cedar` (credential host ceiling, task expiry, Rule of Two, pinned MCP only, publish and merge need approval) and `code/policies/ceiling.cedar`; the worked-decision table rows 1-5 and 8 are the golden test `golden_worked_decisions`. The push permit itself is compiled from `broker.toml` push rules rather than shipped as a fixed policy.
- 2026-09-24 (M2 step 4): the compiler adds a textual forbid `credential:<id>#confine` per brokered credential (reason `credential_host_ceiling`) beside the entity-based ceiling, so confinement is provable from the policy text; record mode splits into `record#l7` (HTTP, fetch, advertise) and `record#push` (never a forced push) ([[ADR-024 Formal Gates as Built]]).
- 2026-09-24 (M3): the Rule-of-Two forbid is live (labels from the GitHub API adapter); GitHub grants compile to `#http`, `#verbs` and `#host-verbs` permits; record mode adds `record#github` ([[ADR-029 GitHub API Adapter and Session Labels as Built]]).
