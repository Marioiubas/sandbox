---
title: "broker.toml Human Policy Layer"
aliases: ["broker.toml", "TOML Front-End", "TOML to Cedar Compiler"]
type: interface
section: policy
tags: [sandbox/policy, interface, topic/policy, topic/filesystem, topic/egress, topic/git, invariant/i4, invariant/i5, milestone/m2]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The small human-facing TOML (profile filesystem.write and deny_read, egress array-of-tables entries with host, protocol, methods, git allow rules and credential kinds) that compiles to Cedar; empty lists and unmatched requests fail closed; a repository copy can only narrow."
related: ["[[Broker Cedar Schema]]", "[[ADR-007 Cedar with a TOML Front-End]]", "[[I4 Repo Policy Only Narrows]]", "[[Native Config Exporters]]", "[[Registry and LLM API Adapters]]", "[[Git Smart-HTTP Adapter]]", "[[sandbox-runtime Empty Allowlist Bypass]]", "[[Filesystem Control and Rollback]]", "[[M2 Policy Audit and Learn]]", "[[Cedar]]", "[[SymCC CI Gates]]", "[[I5 Config Outside Writable Mounts]]", "[[Credential Injector and Issuers]]", "[[Example Cedar Policies]]", "[[Control Plane and Policy Bundles]]", "[[Claude Code and sandbox-runtime]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[Sandbox Launcher]]", "[[Codex CLI Project Config Autoload]]", "[[Claude Code Pre-Trust Config Execution]]"]
sources: ["https://github.com/advisories/GHSA-9gqj-5w7c-vx47", "https://code.claude.com/docs/en/sandboxing", "https://github.com/anthropic-experimental/sandbox-runtime", "https://nvd.nist.gov/vuln/detail/CVE-2026-21852", "https://github.com/advisories/GHSA-xrxf-jgv3-qmrm", "https://vercel.com/docs/sandbox/concepts/firewall", "https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app"]
---

# broker.toml Human Policy Layer

> The small human-facing TOML (profile filesystem.write and deny_read, egress array-of-tables entries with host, protocol, methods, git allow rules and credential kinds) that compiles to Cedar; empty lists and unmatched requests fail closed; a repository copy can only narrow.

## Summary

Developers should not have to write Cedar to get started. `broker init` writes `.broker/broker.toml` (and `.broker/policy.cedar` for anything TOML cannot say), and the policy compiler turns the TOML into Cedar policies and entities against [[Broker Cedar Schema]]. Cedar stays the single source of truth for decisions and proofs; TOML is only an authoring surface ([[ADR-007 Cedar with a TOML Front-End]]). The compiled output also feeds [[Native Config Exporters]].

## Schema (verbatim example)

From the report's repository-layout section. **Proposal; not compiled.**

```toml
[profile.default]
agent = "auto"
filesystem.write = ["${repo}", "${tmp}"]
filesystem.deny_read = ["~/.ssh", "~/.aws", "~/.config/gh", "~/.netrc", "~/.docker/config.json"]

[[egress]]
host = "api.anthropic.com"
credential = { kind = "static", ref = "keychain:anthropic" }

[[egress]]
host = "github.com"
protocol = "git"
allow = { fetch = ["${repo_remote}"], push = { repo = "${repo_remote}", refs = ["agent/*"], force = false } }
credential = { kind = "github_app", permissions = { contents = "write" }, repos = ["${repo_remote}"], ttl = "30m" }

[[egress]]
host = "registry.npmjs.org"
methods = ["GET", "HEAD"]
```

The landscape note's earlier version omits `force = false` and the last two `deny_read` entries. The report version is canonical.

### Keys

| Key | Type | Meaning | Compiles to |
|---|---|---|---|
| `profile.<name>.agent` | string | `"auto"` detects the agent and applies a built-in profile (claude-code, codex, gemini-cli, cursor-agent) | Launcher profile selection |
| `filesystem.write` | list of paths | Writable roots; variables `${repo}`, `${tmp}` | `fs.write` permits on `Dir` entities; SBPL/bwrap/Landlock rules ([[Sandbox Launcher]]) |
| `filesystem.deny_read` | list of paths | Secret paths the agent may not read | `fs.read` forbids; SBPL deny / bwrap masking |
| `[[egress]] host` | string | One canonical host | `Host` entity + permits |
| `protocol` | `"http"` (default) or `"git"` | Selects the adapter | `http.*` or `git.*` actions |
| `methods` | list | Allowed HTTP methods on the host | `http.<METHOD>` permits; absent means none (see below) |
| `allow.fetch` / `allow.push` | table | Git repo, `refs` globs (relative to `refs/heads/`), `force` | `git.fetch` / `git.push` permits with `GitCtx` conditions |
| `credential.kind` | `static`, `github_app`, `aws_sts`, `oauth_exchange` | Issuer ([[Credential Injector and Issuers]]) | `Credential` entity with `allowed_hosts = [host]` + `credential.use` permit |
| `credential.ref` | string | Keychain or vault reference for static secrets | Issuer config (never compiled into policy) |
| `credential.permissions`, `repos`, `ttl` | table/list/duration | Minting scope | Issuer request body; GitHub caps installation tokens at 1 hour ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)) |

**Proposal:** Additional keys the compiler should accept once their adapters exist: `paths` (templated path prefixes), `verbs` (GitHub semantic verbs such as `pr.create`) and `requires_approval` (verbs that trigger step-up, for example `pr.merge`, `pkg.publish`).

## Contract

### Fail-closed semantics

`sandbox-runtime` CVE-2025-66479: an empty `allowedDomains` meant allow-all ([GHSA](https://github.com/advisories/GHSA-9gqj-5w7c-vx47); [[sandbox-runtime Empty Allowlist Bypass]]). **Proposal:** The compiler guarantees the opposite, and tests it:

- An empty or missing list grants nothing. `methods = []` means no HTTP permit for that host. `filesystem.write = []` means a read-only sandbox.
- An `[[egress]]` entry with no `methods`, no `protocol = "git"` and no `credential` compiles to **L4-only passthrough** for that host (SNI allowed, no L7 permits, no credential). It never compiles to "all methods".
- Any request on an L7-inspected host that matches no rule is **denied**, not passed without a credential. This is the opposite of Vercel's "matchers never block" ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall); [[ADR-006 Deny Unmatched L7 Requests]]).
- Unknown keys, unparsable globs and hosts the canonicaliser rejects are **compile errors**, not warnings.
- `${repo_remote}` that cannot be resolved (no remote, non-GitHub remote for a `github_app` credential) is a compile error, and the session does not start.

### Layering and narrowing

Three layers merge: org (from the signed bundle), user (`~/.config/broker/broker.toml`) and repository (`.broker/broker.toml`). **Proposal:**

- Org and user layers may widen within the org ceiling.
- A repository layer may **only narrow**. The compiled repo policy is checked with `check_implies(P_repo ∧ P_org, P_org)` and rejected if it widens ([[I4 Repo Policy Only Narrows]], [[SymCC CI Gates]]).
- A repository layer may never define a credential. This mirrors Claude Code, where repository settings cannot set `mask` or `tlsTerminate` ([Claude Code docs](https://code.claude.com/docs/en/sandboxing); [[Claude Code and sandbox-runtime]]).

The motivating incidents are repo config that executed or redirected API calls before the trust decision, for example CVE-2026-21852 ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)) and Codex CVE-2025-61260 ([GHSA](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)); see [[Claude Code Pre-Trust Config Execution]] and [[Codex CLI Project Config Autoload]]. The repository file is read by `brokerd` outside the sandbox, only after content-hash approval, and is on a read-only path inside the sandbox ([[I5 Config Outside Writable Mounts]]).

### Filesystem nuances

On Linux, srt accepts only literal paths, and globs are expanded at start, so deny-globs miss files created after start ([sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)). **Proposal:** `deny_read` entries compile to directory-level denials where possible, and the compiler warns when a glob can only be enforced as a start-time snapshot on Linux ([[Filesystem Control and Rollback]]).

## Worked compile

The `github.com` git entry above compiles roughly to (**Proposal; not compiled**):

```cedar
@id("toml:egress[1]:fetch")
permit (principal is Broker::Task, action == Broker::Action::"git.fetch", resource is Broker::Repo)
when { resource.full_name == principal.repo };

@id("toml:egress[1]:push")
permit (principal is Broker::Task, action == Broker::Action::"git.push", resource is Broker::Repo)
when { resource.full_name == principal.repo && context.ref like "refs/heads/agent/*" && !context.force };

@id("toml:egress[1]:cred")
permit (principal is Broker::Task, action == Broker::Action::"credential.use",
        resource == Broker::Credential::"github_app:session")
when { context.dest_host == "github.com" };
```

plus a `Credential` entity with `allowed_hosts = ["github.com"]` and `risk = "high"`, and issuer config `{repos: [acme/web], permissions: {contents: write}, ttl: 30m}`. `${repo_remote}` is resolved at session start into `Task.repo`, so the policy text stays repo-independent and the grant is data.

## Versioning

**Proposal:** A top-level `version = 1` key; the compiler refuses unknown versions. The compiled Cedar must be `check_equivalent` to the previous compile when the TOML is unchanged, which catches compiler regressions ([[SymCC CI Gates]]).

## Tests

- Golden tests: each TOML fixture → expected Cedar text and entities.
- Fail-closed tests: empty lists, missing keys, unknown keys, bad globs, unresolvable variables.
- Narrowing tests: a repo layer adding a host or a push ref is rejected with a counterexample.
- Round trip: TOML → Cedar → exporters → equivalent decisions on a request corpus ([[Native Config Exporters]]).

## How it connects

- depends-on:: [[Broker Cedar Schema]]
- depends-on:: [[Cedar]]
- decided-by:: [[ADR-007 Cedar with a TOML Front-End]]
- decided-by:: [[ADR-006 Deny Unmatched L7 Requests]]
- implements:: [[I4 Repo Policy Only Narrows]]
- implements:: [[I5 Config Outside Writable Mounts]]
- mitigates:: [[sandbox-runtime Empty Allowlist Bypass]]
- mitigates:: [[Codex CLI Project Config Autoload]]
- depends-on:: [[Git Smart-HTTP Adapter]]
- depends-on:: [[Registry and LLM API Adapters]]
- depends-on:: [[Filesystem Control and Rollback]]
- evaluated-by:: [[SymCC CI Gates]]
- delivered-by:: [[M2 Policy Audit and Learn]]
- Feeds: [[Native Config Exporters]]

## Implications for the build

- The TOML→Cedar compiler lives in `code/crates/policy/` and is an M2 deliverable; M0/M1 may hard-code equivalent Cedar.
- Put the fail-closed cases into [[L1 Conformance Suite]] category 1 as well as unit tests; this is exactly the enforcement-layer bug class.
- `broker why` must be able to point a decision back to the TOML line that produced its policy (use the `@id` annotation).

## Open questions

- Should `refs = ["agent/*"]` be relative to `refs/heads/` (as assumed here) or require full ref names?
- Is a per-entry `paths` key enough, or do users need a full OpenAPI-operation list per host?
- How should a user-layer entry that conflicts with an org forbid be reported: compile error or runtime deny with a warning?

## Sources

- [GHSA-9gqj-5w7c-vx47](https://github.com/advisories/GHSA-9gqj-5w7c-vx47)
- [Claude Code docs: sandboxing](https://code.claude.com/docs/en/sandboxing)
- [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- [NVD CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852); [GHSA-xrxf-jgv3-qmrm](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)
- [Vercel firewall docs](https://vercel.com/docs/sandbox/concepts/firewall)
- [GitHub REST: installation tokens](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)

## Build log

- 2026-09-24: M1 keys implemented in `policy::config`/`policy::l7`: `protocol` (`http`, `git`, `registry`), `methods`, `paths` (`*` within a segment, `**` any segments), `allow = { fetch, push = { repo, refs, force } }`, `credential = { kind = static|github_app, … }`, `passthrough`, and user/org-only `[issuers.github_app.<name>]` and `[tls] extra_roots`. Absent `methods`/`paths` mean any; empty lists mean none; `${repo_remote}` unresolved grants nothing. Reference: `code/docs/policy-reference.md`.
