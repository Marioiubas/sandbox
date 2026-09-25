---
title: "Broker Cedar Schema"
aliases: ["Cedar Schema", "Grants as Entities"]
type: interface
section: policy
tags: [sandbox/policy, interface, topic/policy, topic/credentials, invariant/i4, milestone/m2, evidence/unverified]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-25
summary: "The Broker namespace schema sketch (Trifecta and Session types; Group, User, Agent, Task, Host, PathPrefix, Repo, Credential, McpServer, Dir, File; HttpCtx, GitCtx, CredCtx, McpCtx; http.*, git.*, credential.use, mcp.call_tool, fs.* actions), with grants as entities and time as epoch seconds."
related: ["[[Cedar]]", "[[Example Cedar Policies]]", "[[Trifecta Session Labels]]", "[[Policy Engine and Entity Builder]]", "[[broker.toml Human Policy Layer]]", "[[GitHub API Adapter]]", "[[Git Smart-HTTP Adapter]]", "[[MCP Guard]]", "[[Open Questions and Unverified Claims]]", "[[DRIFT]]", "[[Internal Grant JWT]]", "[[Hostname Canonicaliser]]", "[[SymCC CI Gates]]", "[[ADR-008 Grant Representation as Entities and Txn-Token JWT]]", "[[Control Plane and Policy Bundles]]", "[[Provenance-Aware Cedar]]", "[[Sandbox Launcher]]", "[[Credential Injector and Issuers]]", "[[Registry and LLM API Adapters]]"]
sources: ["https://docs.rs/cedar-policy-symcc", "https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md", "https://arxiv.org/html/2506.12104v2", "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html", "https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app", "https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html"]
code: ["code/crates/policy/src/cedar/schema.cedarschema"]
---

# Broker Cedar Schema

> The Broker namespace schema sketch (Trifecta and Session types; Group, User, Agent, Task, Host, PathPrefix, Repo, Credential, McpServer, Dir, File; HttpCtx, GitCtx, CredCtx, McpCtx; http.*, git.*, credential.use, mcp.call_tool, fs.* actions), with grants as entities and time as epoch seconds.

> [!question] Unverified
> The schema below is a **sketch that has not been compiled** against `cedar-policy`. Cedar `datetime`/`duration` availability across SDKs was not verified, so time is modelled as epoch seconds (`Long`). Compile it, validate [[Example Cedar Policies]] against it, and record the result here before code depends on it. Tracked in [[Open Questions and Unverified Claims]].

## Signature (verbatim)

Copied from the report. **Proposal; not compiled.**

```cedarschema
namespace Broker {
  type Trifecta = { untrusted_input: Bool, sensitive_read: Bool, external_effect: Bool };
  type Session  = { id: String, now: Long, approved: Bool, trifecta: Trifecta, mode: String };

  entity Group;
  entity User  in [Group] { idp: String, subject: String };
  entity Agent { vendor: String, binary_sha256: String };
  entity Task  { owner: User, agent: Agent, repo: String, branch_prefix: String, expires_at: Long };
  entity Host  { registrable: String };
  entity PathPrefix in [Host, PathPrefix];
  entity Repo  { host: String, full_name: String, visibility: String };
  entity Credential { issuer: String, allowed_hosts: Set<String>, risk: String };
  entity McpServer  { manifest_sha256: String, pinned: Bool };
  entity Dir  in [Dir];
  entity File in [Dir];

  type HttpCtx = { session: Session, method: String, path: String, sni: String,
                   host_header: String, body_bytes: Long, dest_class: String };
  type GitCtx  = { session: Session, ref: String, force: Bool };
  type CredCtx = { session: Session, dest_host: String, method: String, path: String };
  type McpCtx  = { session: Session, tool: String, args_integrity: String };

  action "http.read", "http.write";
  action "http.GET", "http.HEAD", "http.OPTIONS" in ["http.read"]
    appliesTo { principal: [Task], resource: [Host, PathPrefix], context: HttpCtx };
  action "http.POST", "http.PUT", "http.PATCH", "http.DELETE" in ["http.write"]
    appliesTo { principal: [Task], resource: [Host, PathPrefix], context: HttpCtx };
  action "git.fetch", "git.push"
    appliesTo { principal: [Task], resource: [Repo], context: GitCtx };
  action "credential.use"
    appliesTo { principal: [Task], resource: [Credential], context: CredCtx };
  action "mcp.call_tool"
    appliesTo { principal: [Task], resource: [McpServer], context: McpCtx };
  action "fs.read", "fs.write"
    appliesTo { principal: [Task], resource: [Dir, File], context: { session: Session } };
}
```

## Contract

### Principal: the Task

**Proposal:** The principal of every request is a `Task`. A task carries its `owner` (a `User`, member of IdP `Group`s), its `agent` (vendor and binary hash), the one `repo` it may touch, its `branch_prefix` and its `expires_at`. Keying every decision to the task means every audit row is keyed to user *and* agent at once ([[Audit Recorder and Event Schema]]). `brokerd` builds the task at `session.start` from the cached OIDC login, the agent binary hash and the repo remote ([[Request and Session Lifecycle]]).

### Resources

| Entity | Hierarchy | Built from | Notes |
|---|---|---|---|
| `Host` | root | canonical host from [[Hostname Canonicaliser]] | `registrable` holds the registrable domain; the UID is the canonical LDH name, never the raw SNI |
| `PathPrefix` | `in [Host, PathPrefix]` | templated path segments | `api.github.com/repos/acme/web/pulls` is in `.../repos/acme/web`, which is in `api.github.com` |
| `Repo` | none | [[Git Smart-HTTP Adapter]], [[GitHub API Adapter]] | `visibility` feeds `sensitive_read` ([[Trifecta Session Labels]]) |
| `Credential` | none | issuer config in [[Credential Injector and Issuers]] | `allowed_hosts` is the credential's host ceiling; `risk` drives approvals |
| `McpServer` | none | [[MCP Guard]] | `manifest_sha256` of `tools/list`; `pinned` false after any change |
| `Dir` / `File` | `in [Dir]` | FS grants | compiled to SBPL or Landlock by [[Sandbox Launcher]], not evaluated per syscall |

### Actions

Actions form two groups for HTTP (`http.read` ⊃ GET/HEAD/OPTIONS, `http.write` ⊃ POST/PUT/PATCH/DELETE) so a policy can say "read-only on this host" in one line. Adapter verbs (`git.push`, `mcp.call_tool`, `credential.use`) are separate actions with their own typed context.

**Proposal:** Add GitHub semantic verbs (`pr.create`, `pr.merge`, `issue.comment`, `contents.write`) and `pkg.publish` as actions emitted by [[GitHub API Adapter]] and [[Registry and LLM API Adapters]]. The sketch does not yet declare them, but [[Example Cedar Policies]] and the SymCC "deny rules stay live" gate reference `pkg.publish` and `pr.merge`. Declare them before M2.

### Context

Every context carries `session: Session`: `now` (epoch seconds, set by the broker clock), `approved` (an out-of-band approval is live for this request), `trifecta` (the three session labels) and `mode` (`enforce` or `audit`). The per-protocol part adds what the adapter parsed:

- `HttpCtx`: `method`, templated `path`, `sni`, `host_header`, `body_bytes` and `dest_class` (for example public, link-local, private, metadata). **Proposal:** the entity builder refuses to build a request when `sni`, `host_header` and the CONNECT target disagree, so policies never see an inconsistent triple.
- `GitCtx`: one `ref` and `force` per ref update; a push with three ref updates is three Cedar requests.
- `CredCtx`: the destination the credential would be attached to.
- `McpCtx`: `tool` and `args_integrity`, the provenance hook for [[Provenance-Aware Cedar]].

## Grants are entities, not policy text

**Proposal:** A grant is data in `entities.json`, not a new `permit`. Expiry and revocation are then data updates: the broker rewrites a `Task` entity or drops a `PathPrefix` membership, and no policy is recompiled or re-proved. Policies stay a small, stable, SymCC-checked set; the churn lives in entities. The same grant crosses hosts as a Transaction-Token-shaped JWT whose `tctx` mirrors these attributes ([[Internal Grant JWT]], [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]).

### Task-scoped and time-bound grants

Time-bounding is one forbid that no permit can override (forbid wins, [cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)):

```cedar
// Proposal; not compiled.
forbid (principal, action, resource) when { context.session.now >= principal.expires_at };
```

Task scope is expressed through the principal's attributes (`principal.repo`, `principal.branch_prefix`) and through entity membership. A worked `entities.json` fragment (**Proposal; not compiled**):

```json
[
  { "uid": { "type": "Broker::User", "id": "okta|00u1abc" },
    "attrs": { "idp": "okta", "subject": "00u1abc" },
    "parents": [ { "type": "Broker::Group", "id": "eng" } ] },
  { "uid": { "type": "Broker::Agent", "id": "claude-code" },
    "attrs": { "vendor": "anthropic", "binary_sha256": "<sha256>" }, "parents": [] },
  { "uid": { "type": "Broker::Task", "id": "task-01J9" },
    "attrs": { "owner": { "__entity": { "type": "Broker::User", "id": "okta|00u1abc" } },
               "agent": { "__entity": { "type": "Broker::Agent", "id": "claude-code" } },
               "repo": "acme/web", "branch_prefix": "agent/", "expires_at": 1790000900 },
    "parents": [] },
  { "uid": { "type": "Broker::Credential", "id": "github_app:acme" },
    "attrs": { "issuer": "github_app", "allowed_hosts": ["github.com", "api.github.com"], "risk": "high" },
    "parents": [] }
]
```

Revoking the task is setting `expires_at` to the past, or deleting the entity. Either takes effect on the next request with no bundle rebuild. The upstream token already minted for the task keeps its own TTL: GitHub installation tokens last 1 hour ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)) and STS sessions at least 900 s ([AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)). **Proposal:** on revoke, `brokerd` also drops its cached upstream token so no further request can use it.

## Alternative sketch considered

The identity research note sketched a slightly different model (**Proposal**, not adopted): `User` with `groups`, `Agent` with `model`, `version` and `spiffe_id`, a `Sandbox` entity `in Task`, `Task.approved_scopes: Set<String>`, `expires_at: datetime`, and actions named `http::GET`, `git::push`, `fs::exec`. The report's version drops `datetime` (unverified), drops `fs.exec` from the MVP, and replaces `approved_scopes` with the `Session.approved` flag plus entity membership. **Proposal:** add `spiffe_id` to `Agent` or a `Sandbox` entity when CI and gateway modes need sender-constrained grants ([[Internal Grant JWT]]).

The paper audit's inference that argument provenance, reader sets and trifecta state belong in context, not in new entity types, is reflected in `Trifecta` and `args_integrity`. DRIFT's read/write/execute privilege classes ([DRIFT](https://arxiv.org/html/2506.12104v2)) map onto the `http.read`/`http.write` action groups and `fs.*` ([[DRIFT]]).

## Versioning

**Proposal:** The schema ships inside every signed bundle as `schema.cedarschema` ([[Control Plane and Policy Bundles]]). A schema change is a bundle change and runs every [[SymCC CI Gates]] query, because proofs hold only relative to the schema and request environment the analyzer was given ([docs.rs](https://docs.rs/cedar-policy-symcc)). Removing an attribute or action is a breaking change and needs an ADR. Adding an optional attribute is not.

## Tests

- Compile the schema and validate every policy in [[Example Cedar Policies]] against it in CI.
- Property test: the entity builder never emits a `Host` UID that the canonicaliser would reject.
- Golden tests: one request per action type, with expected decisions under the example policies.
- Revocation test: flip `expires_at` mid-session; the next `git.push` is denied and `broker why` names the expiry forbid.

## How it connects

- implements:: [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]
- depends-on:: [[Cedar]]
- depends-on:: [[Hostname Canonicaliser]]
- part-of:: [[Policy Engine and Entity Builder]]
- evaluated-by:: [[SymCC CI Gates]]
- example-of:: [[Example Cedar Policies]]
- depends-on:: [[Trifecta Session Labels]]
- depends-on:: [[Git Smart-HTTP Adapter]]
- depends-on:: [[GitHub API Adapter]]
- depends-on:: [[MCP Guard]]
- contrasts-with:: [[DRIFT]]
- Human layer that compiles into it: [[broker.toml Human Policy Layer]]

## Implications for the build

- Put the schema in `code/crates/policy/` with a compile test from day one of M2.
- The entity builder is the untested boundary the 2026 out-of-band study flagged; fuzz it ([[Adaptive Evaluation of Deterministic Monitors]]).
- Keep policies few and entities many. A growing policy count is a smell; a growing entity store is normal.
- Record the verified `datetime` status here and in [[Open Questions and Unverified Claims]] before changing `expires_at`.

## Open questions

- Should `Session.now` come from the broker clock only, and how is clock skew handled for grants carried across hosts?
- Should `dest_class` be an enum-like string or separate entity types for link-local, private and metadata ranges?
- Is `args_integrity: String` enough for provenance, or does [[Provenance-Aware Cedar]] need a record per argument?

## Sources

- [docs.rs cedar-policy-symcc](https://docs.rs/cedar-policy-symcc)
- [cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)
- [AgentCore policy docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html) (comparison: schema generated from tool definitions)
- [GitHub REST: installation tokens](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)
- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [DRIFT](https://arxiv.org/html/2506.12104v2)

## Implementation notes

- 2026-09-24: `Host in [Domain, HostCategory]` (+ `ip_literal`), `Domain in [Domain]`, `HostCategory`; `Repo in [Host]` with `authority`/`owner`/`full_name`/`visibility`; no `PathPrefix`: HTTP actions target `Host` and carry `Path = {n, s0..s15}` plus `path_str`; `net.resolve`/`net.connect` with `ConnCtx {port, addr_classes}`; `git.advertise`, `http.OTHER`, `pkg.publish`, `pr.create`, `pr.merge`, `issue.comment`, `contents.write`; `port` in `HttpCtx`/`GitCtx`; `Credential.allowed_domains`, `CredCtx.dest_domains`/`port`/`verb`/`path_str`. Rationale in [[ADR-022 Cedar Schema and Engine as Built]].
- 2026-09-24: `datetime` is a **default feature of the Rust SDK 4.13** (`cedar-policy` features: `ipaddr`, `decimal`, `datetime`); time stays epoch seconds until SymCC support for it is verified.

## Build log

- 2026-09-24: compiled and validated (strict) with `cedar-policy` 4.13.0 as `code/crates/policy/src/cedar/schema.cedarschema`; the default and ceiling policies and every compiler-emitted policy shape validate against it (`schema_and_default_policies_validate`). Changes from the sketch are listed in [[ADR-022 Cedar Schema and Engine as Built]].
- 2026-09-24: `context.session.mode` gains `"shadow"` (enforce semantics for the applied decision; no policy tests for it) ([[ADR-026 Shadow Mode as Built]]).
- 2026-09-24 (M3): `GitHubCtx { session, port, method, path_str }`; `repo.read`, `pr.create`, `pr.merge`, `issue.comment`, `contents.write` on `Repo`; `github.read`, `gist.create` on `Host`; `Repo.visibility` from the broker's lookup; `Credential.risk` from config ([[ADR-029 GitHub API Adapter and Session Labels as Built]]).
- 2026-09-25 (M3): `S3Ctx { session, port, bucket, key }`; `s3.get`, `s3.list`, `s3.put`, `s3.delete` on `Host`; grants compile to `context.bucket == B && context.key like "p*"` ([[ADR-032 AWS STS and S3 Adapter as Built]]).
