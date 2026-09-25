---
title: "Git Smart-HTTP Adapter"
aliases: ["git adapter", "pkt-line Parser"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/git, topic/egress, topic/credentials, control/task-tok, control/egress, boundary/tb4, invariant/i6, milestone/m1]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Protocol adapter that rewrites SSH remotes to HTTPS, denies port 22, parses info/refs and git-receive-pack pkt-lines into per-ref git.push requests (repo, ref, force), enforces rules such as 'agent/* on the task repo, never force', attaches a repo-scoped installation token and signs commits broker-side."
related: ["[[GitHub App Installation Tokens]]", "[[Example Cedar Policies]]", "[[Core Trait Contracts]]", "[[M1 Secrets Outside]]", "[[Gap Analysis]]", "[[Filesystem Control and Rollback]]", "[[Broker Cedar Schema]]", "[[L1 Conformance Suite]]", "[[TLS Termination and Per-Session CA]]", "[[Credential Injector and Issuers]]", "[[Hostname Canonicaliser]]", "[[Policy Engine and Entity Builder]]", "[[GitHub API Adapter]]", "[[GitHub MCP Toxic Flow]]", "[[Nx s1ngularity Supply-Chain Attack]]", "[[Sandbox Launcher]]", "[[Conformance Probe Matrix]]", "[[Docker Sandboxes]]", "[[Claude Code and sandbox-runtime]]", "[[broker.toml Human Policy Layer]]", "[[Trifecta Session Labels]]", "[[Open Questions and Unverified Claims]]", "[[I5 Config Outside Writable Mounts]]"]
sources: ["https://www.anthropic.com/engineering/claude-code-sandboxing", "https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/", "https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app", "https://invariantlabs.ai/blog/mcp-github-vulnerability", "https://www.wiz.io/blog/s1ngularity-supply-chain-attack"]
milestone: M1
code: ["code/crates/l7/src/git", "code/crates/l7/src/classify.rs", "code/crates/policy/src/repo.rs"]
---

# Git Smart-HTTP Adapter

> Protocol adapter that rewrites SSH remotes to HTTPS, denies port 22, parses info/refs and git-receive-pack pkt-lines into per-ref git.push requests (repo, ref, force), enforces rules such as 'agent/* on the task repo, never force', attaches a repo-scoped installation token and signs commits broker-side.

## Responsibility

`l7/adapters/git_smart_http`, a `ProtocolAdapter` ([[Core Trait Contracts]]). It gives git the per-repo and per-branch semantics no upstream token can express: a GitHub App installation token can be restricted to selected repositories and permission categories, but has "no branch or path scope" and lasts 1 hour ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app); [[GitHub App Installation Tokens]]). The adapter turns every push into one Cedar `git.push` request per ref update, so "push only to `acme/web` refs under `refs/heads/agent/*`, never force" is enforceable before any byte reaches GitHub.

**It must never:** forward a receive-pack request before every ref update is authorized; guess the repository from anything but the canonical request path; treat an unparseable pkt-line stream as allowed; let SSH git bypass the broker; hold signing keys inside the sandbox.

## Precedent and gap

Anthropic's web sandbox validates pushes against "the configured branch" with a custom git proxy that attaches the token outside the sandbox ([Anthropic](https://www.anthropic.com/engineering/claude-code-sandboxing)); see [[Claude Code and sandbox-runtime]]. No neutral product in the record does this, although that absence was not exhaustively verified ([[Gap Analysis]], [[Open Questions and Unverified Claims]]). Docker sbx cannot forward an ssh-agent for signing into the VM ([Andrew Lock](https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/)); see [[Docker Sandboxes]].

## Inputs and outputs

- **Input:** L7 requests to a git host (for example `github.com`) claimed by path shape: `GET /{owner}/{repo}(.git)/info/refs?service=git-upload-pack|git-receive-pack`, `POST .../git-upload-pack`, `POST .../git-receive-pack`.
- **Output:** `Vec<AuthzRequest>`: one `git.fetch` for upload-pack, or one `git.push` per ref update for receive-pack, plus `credential.use` for the bound credential; an audit verb such as `git.push refs/heads/agent/x`.

## Setup inside the sandbox

**Proposal (report).** The launcher writes the sandbox's git config with `url."https://github.com/".insteadOf "git@github.com:"`, and netguard denies port 22, so all git traffic is smart-HTTP through the broker ([[Sandbox Launcher]]). `.git/hooks` and `.git/config` of the repo itself are read-only ([[I5 Config Outside Writable Mounts]]); the insteadOf rule therefore lives in a broker-generated global config inside the sandbox that the agent cannot modify.

## Parsing

> [!note] Background, not in the research record
> The wire details below (service advertisement, pkt-line framing, the command-list form `old-oid SP new-oid SP refname`, NUL-separated capabilities on the first line, the zero OID for create and delete) come from git's protocol documentation, not from the research record. Verify against `gitprotocol-http` and `gitprotocol-pack` before implementation.

**Proposal.**

```rust
pub struct RefUpdate { pub old: ObjectId, pub new: ObjectId, pub refname: String }
pub enum UpdateKind { Create, Delete, FastForward, NonFastForward, Unknown }

pub struct ReceivePack {
    pub repo: RepoId,                 // from the canonical path: host + "owner/repo"
    pub updates: Vec<RefUpdate>,      // from the command list, up to the flush-pkt
    pub capabilities: Vec<String>,
}

fn parse_receive_pack(body: &mut BufferedRequest) -> Result<ReceivePack, GitParseError>;
fn classify_update(u: &RefUpdate, pack: &PackIndexView, upstream: &RefView) -> UpdateKind;
```

- The command list is parsed strictly with a length-checked pkt-line reader; refnames must be valid ref syntax (reject control bytes, `..`, `@{`, trailing `.lock`), and the repository path goes through `canon_path` ([[Hostname Canonicaliser]]).
- **Force detection (Proposal).** `Delete` (new OID zero) and `NonFastForward` are both treated as `force: true`. A update is `FastForward` only if walking commit parents inside the pushed pack from `new` reaches `old`, or if an upstream ancestry check through the [[GitHub API Adapter]] (using the broker's own credential) confirms it. `Unknown` is treated as force, so the rule "never force" fails closed.
- Each ref update becomes:

```json
{ "action": "git.push", "resource": "Broker::Repo::\"github.com/acme/web\"",
  "context": { "session": { "...": "..." }, "ref": "refs/heads/agent/fix-123", "force": false } }
```

matching `GitCtx = { session, ref, force }` in [[Broker Cedar Schema]]. All requests must allow; one denied ref denies the whole push.

## Policy

The report's example rule ([[Example Cedar Policies]]):

```cedar
// Push only to the task repo, only to agent/* branches, never force.
permit (principal is Broker::Task, action == Broker::Action::"git.push", resource is Broker::Repo)
when { resource.full_name == principal.repo
       && context.ref like "refs/heads/agent/*" && !context.force };
```

and the human layer ([[broker.toml Human Policy Layer]]):

```toml
[[egress]]
host = "github.com"
protocol = "git"
allow = { fetch = ["${repo_remote}"], push = { repo = "${repo_remote}", refs = ["agent/*"], force = false } }
credential = { kind = "github_app", permissions = { contents = "write" }, repos = ["${repo_remote}"], ttl = "30m" }
```

The Rule of Two forbid also covers `git.push`: once `untrusted_input` and `sensitive_read` are both live, pushes need approval ([[Trifecta Session Labels]]).

## Credential attachment

Only after all Cedar requests allow, the `github_app` issuer mints (or reuses, per scope digest) an installation token restricted to `repositories = [repo]` and `permissions = { contents: write }` ([[Credential Injector and Issuers]]). If `repositories` or `permissions` were omitted, GitHub would give the token the whole installation's repos and permissions ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)), so the issuer must always set both. The token is attached to the forwarded request and never appears in the sandbox.

## Commit signing

**Proposal.** Commit signing happens broker-side (report). Because signing changes the commit, the broker cannot sign at push time without rewriting history; instead, the sandbox's broker-generated git config points git's signing program at a read-only broker stub that relays the signing payload over the broker channel to `brokerd`, which signs with a key held in the keychain, only for commit and tag payload formats, and logs each signature. The key never enters the sandbox. The exact git configuration keys are background knowledge and need verification.

## State

Per request: buffered command list and pack index view (bounded). Per session: cached installation token per scope digest.

## Failure modes and fail-closed behaviour

- Malformed pkt-line, oversized command list, invalid refname, path not matching `/{owner}/{repo}`: deny.
- Ancestry undeterminable: treat as force (deny under "never force").
- Mint failure: deny.
- Upstream rejects the push: pass the upstream status through; audit records both decisions.

## Security considerations

- The pack itself is not trusted for anything except the ancestry walk; object parsing is bounded and fuzzed.
- Repo identity comes from the canonical path, compared with `principal.repo` computed at `session.start` from the repo remote through the same canonicaliser.
- Tag pushes (`refs/tags/*`) are a separate grant; default deny.
- This adapter addresses incident shapes where pushes to another repository were the leak channel, such as the public-PR write in [[GitHub MCP Toxic Flow]] ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)) and the attacker-created public repos in [[Nx s1ngularity Supply-Chain Attack]] ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)).

## Performance budget

Parsing the command list is small; the ancestry walk is bounded by the pushed pack. Within the new terminated connection budget (p50 ≤15 ms) for typical pushes; large packs are streamed, not buffered whole.

## Invariants upheld

[[I6 Single Canonicaliser]] (repo from canonical path), [[I1 No Secrets in the Sandbox]] (token attached broker-side, signing key outside), [[I7 Reject Foreign Credentials]] (client `Authorization` stripped by the pipeline).

## Test plan

- Unit: pkt-line reader, command-list parser, refname validation, force classification table.
- Property: random ref-update lists; decision is the conjunction of per-ref decisions; `Unknown` never yields `force: false`.
- Fuzz: pkt-line and command-list parser (`cargo-fuzz`), ≥24 h before release.
- E2E ([[M1 Secrets Outside]] acceptance): push to `agent/x` on the session repo succeeds; pushes to another repo, to `main`, or with force are denied, and `broker why` explains each.
- Conformance: category 1 ("push to an attacker repo on github.com") in [[Conformance Probe Matrix]] and [[L1 Conformance Suite]].

## Dependencies

No git library is chosen in the record; a minimal in-house pkt-line reader plus a pack-index reader is the proposal, to keep the parsing surface small.

## How it connects

- implements:: [[Core Trait Contracts]]
- depends-on:: [[GitHub App Installation Tokens]]
- depends-on:: [[Credential Injector and Issuers]]
- depends-on:: [[TLS Termination and Per-Session CA]]
- depends-on:: [[Broker Cedar Schema]]
- example-of:: [[Example Cedar Policies]]
- part-of:: [[Gap Analysis]]
- mitigates:: [[GitHub MCP Toxic Flow]]
- mitigates:: [[Nx s1ngularity Supply-Chain Attack]]
- contrasts-with:: [[Docker Sandboxes]]
- evaluated-by:: [[L1 Conformance Suite]]
- delivered-by:: [[M1 Secrets Outside]]

## Implications for the build

- The agent commits locally and the broker performs the push, which is why only `.git/hooks` and `.git/config` are protected rather than all of `.git` ([[Filesystem Control and Rollback]]).
- GitLab and other forges need their own path shapes; keep forge specifics in data, the pkt-line logic shared.

## Open questions

- Whether GitHub added any branch-scoped installation-token capability in 2026 (none found).
- Force detection without an upstream round trip for pushes whose pack does not contain the old commit.
- Signing-stub design and which git versions honour it.

## Sources

- https://www.anthropic.com/engineering/claude-code-sandboxing
- https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/
- https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
- https://invariantlabs.ai/blog/mcp-github-vulnerability
- https://www.wiz.io/blog/s1ngularity-supply-chain-attack
- Report: "Protocol adapters are the moat" (git smart-HTTP), schema and example policies, `broker.toml`, M1 acceptance; research notes 03 Q1 and Q4, 05 sections 1 and 3.2.

## Implementation notes

- 2026-09-24: force detection is fail-closed per [[ADR-021 L7 Path Choices for M1]]: only an update whose new tip reaches the old tip through parents inside the pushed pack is a fast-forward; deletes, unreadable packs, SHA-256 repositories and ancestry outside the pack count as force. Denied pushes answer with `report-status` so git prints `! [remote rejected] <ref> (broker denied: <reason> (broker why req-…))`.
- 2026-09-24: the repository comes from the canonical request path; `${repo_remote}` is read from the checkout's `.git/config` (worktrees via `commondir`) without running git; the same `RepoId` type names repositories in policy, remotes and requests.

## Build log

- 2026-09-24: built: `l7::git` (`route`, `actions`), `pktline`, `receive_pack` (strict command list, shallow lines, push options, push certificates refused, git-native `report-status` rejection with side-band), `pack` (commit graph from the pushed pack: OFS/REF deltas resolved when their base is a commit in the pack, SHA-1 trailer verified, limits). One `git.push` per ref update; one denied ref denies the push. SSH remotes are rewritten to HTTPS through `GIT_CONFIG_*` in the session env (M0).
- 2026-09-24: tests: `l7::git::*` unit/property tests on real `git pack-objects` output (fast-forward, rewrite, merge, deltified commits, corrupt packs); conformance `b2_push_to_agent_branch_succeeds_with_scoped_token`, `b3_main_force_delete_and_other_repo_are_denied_and_explained`, `cat1_push_to_attacker_repo_mints_nothing` (`tests/conformance/tests/m1_git.rs`) against a fake GitHub running `git http-backend`; fuzz targets `pktline`, `pack`, `delta`.
- 2026-09-24: not built: broker-side commit signing (not an M1 checklist item). Remaining acceptance: B2/B3 against a real throwaway GitHub App (see [[M1 Secrets Outside]]).
- 2026-09-25: `RepoId` lower-cases before stripping one `.git` and refuses names that still end in `.git` (found by fuzz target `remote_url`: `.GIT` was kept by one parse and stripped by the next).
- 2026-09-25: verified against real GitHub (real throwaway GitHub App (app 5073081, installation 164792503 on `Marioiubas/sandboxpublictest` and `Marioiubas/sandboxprivatetest` only; key in `~/.config/broker/gh-app.pem`, mode 0600, outside every writable mount), macOS 26, 2026-09-25): allowed agent-branch push, denied `main`/force/delete/other-repo pushes, private-repo fetch; see [[M1 Secrets Outside]].
