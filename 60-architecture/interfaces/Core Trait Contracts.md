---
title: "Core Trait Contracts"
aliases: ["SandboxBackend", "ProtocolAdapter", "CredentialIssuer Trait", "Recorder Trait", "SandboxSpec"]
type: interface
section: architecture
tags: [sandbox/architecture, interface, topic/build, invariant/i1, invariant/i2, invariant/i6, invariant/i9, milestone/m0]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The four Rust traits where crates meet, with SandboxSpec: SandboxBackend (probe, launch, must fail closed), ProtocolAdapter (claims, classify into Cedar requests that must all allow), CredentialIssuer (mint, attach; material never leaves broker memory) and Recorder (append returns chain hash)."
related: ["[[Sandbox Launcher]]", "[[Git Smart-HTTP Adapter]]", "[[Credential Injector and Issuers]]", "[[Audit Recorder and Event Schema]]", "[[Policy Engine and Entity Builder]]", "[[I1 No Secrets in the Sandbox]]", "[[I2 Fail-Closed Launch]]", "[[Repository Layout]]", "[[M0 Contained Run]]", "[[GitHub API Adapter]]", "[[Registry and LLM API Adapters]]", "[[MCP Guard]]", "[[Hostname Canonicaliser]]", "[[Netguard Ingress]]", "[[TLS Termination and Per-Session CA]]", "[[Broker Cedar Schema]]", "[[I6 Single Canonicaliser]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[Tech Stack]]", "[[Internal Grant JWT]]", "[[ADR-015 Rust for the Endpoint and Custom Proxy]]"]
sources: ["https://github.com/omjadas/hudsucker", "https://crates.io/crates/landlock", "https://github.com/craigbalding/safeyolo/issues/620"]
milestone: M0
---

# Core Trait Contracts

> The four Rust traits where crates meet, with SandboxSpec: SandboxBackend (probe, launch, must fail closed), ProtocolAdapter (claims, classify into Cedar requests that must all allow), CredentialIssuer (mint, attach; material never leaves broker memory) and Recorder (append returns chain hash).

## Purpose

These four traits are the module boundaries of the endpoint. Each crate in [[Repository Layout]] implements or consumes exactly one of them, which keeps the custom L7 surface small and lets tests substitute fakes at each seam. The split follows SafeYolo's separation of "service-route validation, credential selection, policy evaluation, inspection and injection" ([SafeYolo #620](https://github.com/craigbalding/safeyolo/issues/620)), which the report recommends copying.

| Trait | Implemented in | Consumed by | Invariants carried |
|---|---|---|---|
| `SandboxBackend` | `launcher/backends/{seatbelt,linux,container,vm}` | `brokerd` session manager | [[I2 Fail-Closed Launch]], [[I1 No Secrets in the Sandbox]] (env) |
| `ProtocolAdapter` | `l7/adapters/{git_smart_http,github_api,npm,pypi,crates,llm_apis,mcp}` | `l7` pipeline | [[I6 Single Canonicaliser]] (takes `CanonicalHost`) |
| `CredentialIssuer` | `creds/issuers/{static,github_app,aws_sts,oauth_exchange,vault}` | `l7` pipeline after authorization | [[I1 No Secrets in the Sandbox]] |
| `Recorder` | `audit` | every crate that decides | [[I9 Hash-Chained Audit Outside the Sandbox]] |

## Signatures (verbatim from the report; Proposal; not compiled)

```rust
/// Isolation backend. Must fail closed.
pub trait SandboxBackend: Send + Sync {
    fn name(&self) -> &'static str;                  // "macos-seatbelt" | "linux-native" | "container" | "vm"
    fn probe(&self) -> anyhow::Result<BackendReport>; // Landlock ABI, userns/AppArmor gate, VZ availability
    fn launch(&self, spec: &SandboxSpec) -> anyhow::Result<SandboxHandle>;
}
pub struct SandboxSpec {
    pub session: SessionId,
    pub argv: Vec<std::ffi::OsString>,
    pub cwd: std::path::PathBuf,
    pub env: std::collections::BTreeMap<String, String>, // sentinels only (I1)
    pub fs: CompiledFsPolicy,                             // from Cedar fs.* grants
    pub egress: EgressEndpoint,                           // Uds(path) | Loopback(port) | Vsock(cid, port)
    pub ca_bundle: std::path::PathBuf,                    // per-session CA merged with public roots
}

/// Turns a parsed request into Cedar requests; all must be allowed.
#[async_trait::async_trait]
pub trait ProtocolAdapter: Send + Sync {
    fn claims(&self, host: &CanonicalHost, head: &http::request::Parts) -> bool;
    async fn classify(&self, req: &mut BufferedRequest, s: &SessionCtx)
        -> anyhow::Result<Vec<AuthzRequest>>;           // e.g. git.push per ref update
}

/// Mints upstream credentials; material never leaves broker memory.
#[async_trait::async_trait]
pub trait CredentialIssuer: Send + Sync {
    fn kind(&self) -> &'static str;                      // "static" | "github_app" | "aws_sts" | "oauth_exchange"
    async fn mint(&self, grant: &Grant) -> anyhow::Result<Issued>; // Issued{secret: Zeroizing<..>, expires_at, scope_digest}
    fn attach(&self, issued: &Issued, req: &mut http::Request<Body>) -> anyhow::Result<()>; // header or SigV4
}

/// Append-only, hash-chained decision log.
pub trait Recorder: Send + Sync {
    fn append(&self, ev: &AuditEvent) -> anyhow::Result<ChainHash>; // hash = H(prev || canonical_json(ev))
}
```

## Supporting types (Proposal; not compiled)

The report names these types without defining them. The sketches below are the default design; field names may change, semantics may not without an ADR.

```rust
pub struct SessionId(pub ulid::Ulid);

pub struct BackendReport {
    pub backend: &'static str,
    pub layers: Vec<LayerStatus>,          // every layer, required or not
    pub landlock_abi: Option<u8>,          // Linux only; probed at runtime
    pub userns_allowed: Option<bool>,      // Ubuntu AppArmor gate
    pub vz_available: Option<bool>,        // macOS hard tier
}
pub struct LayerStatus { pub name: &'static str, pub required: bool, pub ok: bool, pub detail: String }

pub enum EgressEndpoint { Uds(std::path::PathBuf), Loopback(u16), Vsock(u32, u32) }

pub struct CompiledFsPolicy {
    pub read_only_root: bool,
    pub writable: Vec<std::path::PathBuf>,     // ${repo}, ${tmp}
    pub deny_read: Vec<std::path::PathBuf>,    // ~/.ssh, ~/.aws, ...
    pub deny_write: Vec<std::path::PathBuf>,   // mandatory list (I5) plus policy
}

pub struct SandboxHandle { pub pid: u32 /* plus wait/kill handles */ }

/// Only constructible by netguard::canon (I6).
pub struct CanonicalHost { name: String, /* private */ }
pub struct CanonicalPath { path: String }

pub struct SessionCtx {
    pub session: SessionId,
    pub task: TaskRef,                     // Cedar Task entity UID
    pub labels: SessionLabels,             // trifecta, monotone (I3)
    pub mode: Mode,                        // Enforce | Audit
}

pub struct AuthzRequest {
    pub action: String,                    // e.g. "git.push", "http.POST", "credential.use"
    pub resource: cedar_policy::EntityUid,
    pub context: serde_json::Value,        // HttpCtx | GitCtx | CredCtx | McpCtx
    pub verb: Option<String>,              // adapter verb for audit, e.g. "pr.create"
}

pub struct Grant { pub task: TaskRef, pub issuer_ref: String, pub scope: serde_json::Value }
pub struct Issued {
    pub secret: zeroize::Zeroizing<Vec<u8>>,
    pub expires_at: std::time::SystemTime,
    pub scope_digest: [u8; 32],
    pub credential_id: String,             // logged; never the value
}
pub struct ChainHash(pub [u8; 32]);
```

`AuditEvent` is specified in [[Audit Recorder and Event Schema]]; the Cedar actions and context types referenced by `AuthzRequest` are in [[Broker Cedar Schema]].

## Contracts

### SandboxBackend

- `probe()` must report every layer, required or optional, and must not have side effects visible to other sessions.
- `launch()` must return `Err` without spawning the agent if any required layer fails; it must verify the layers after applying them (fail closed, [[I2 Fail-Closed Launch]]).
- `spec.env` may contain only allowlisted variables, sentinels, and CA-bundle variables; implementations must not add variables from the host environment.
- `spec.fs.deny_write` must always include the mandatory list from [[Sandbox Launcher]]; backends must refuse a spec where it is missing.
- The only network route in the child must be `spec.egress`.

### ProtocolAdapter

- `claims()` is pure and fast (no I/O); the pipeline asks adapters in a fixed order and uses the first that claims. Unclaimed L7 requests fall back to the generic HTTP classifier (`http.<METHOD>` on `PathPrefix`).
- `classify()` may buffer and parse the body (pkt-lines, JSON-RPC, GraphQL) but must not forward anything. It returns **all** Cedar requests implied by the request; the pipeline allows only if every one allows, and at least one must be returned (an empty vector is a deny).
- Parse failure returns `Err`, which the pipeline treats as deny ([[CLAUDE]] working rule: unparseable input denies).
- Adapters must use `CanonicalHost`/`CanonicalPath` and never re-parse host strings.

### CredentialIssuer

- `mint()` is called only after all authorization requests, including `credential.use`, allowed. It may return a cached `Issued` for the same `scope_digest` while unexpired.
- `Issued.secret` never leaves broker memory: not logged, not written to disk, not placed in any response. `Debug` for `Issued` redacts the secret.
- `attach()` writes only the headers (or SigV4 signature) for the destination and must be called after client credential headers were stripped ([[I7 Reject Foreign Credentials]]).

### Recorder

- `append()` is synchronous from the caller's point of view: it returns only after the event is durable (SQLite WAL commit) and returns the new chain hash.
- Callers must treat `Err` as deny.
- `hash = H(prev || canonical_json(ev))`; the hash function is part of the on-disk format version.

## Example exchange: git push classified

**Proposal.** A push of `refs/heads/agent/fix-123` to `github.com/acme/web` through [[Git Smart-HTTP Adapter]] yields:

```json
[
  { "action": "git.push", "resource": "Broker::Repo::\"github.com/acme/web\"",
    "context": { "ref": "refs/heads/agent/fix-123", "force": false }, "verb": "git.push refs/heads/agent/fix-123" },
  { "action": "credential.use", "resource": "Broker::Credential::\"github_app:acme\"",
    "context": { "dest_host": "github.com", "method": "POST", "path": "/acme/web.git/git-receive-pack" } }
]
```

Both must allow before the `github_app` issuer mints and attaches a repo-scoped installation token. A push that also updates `refs/heads/main` yields a third `git.push` request that the policy denies, so the whole push is denied.

## Versioning

**Proposal.** Traits live in a small `broker-core` module re-exported by each crate (or in the crate that owns them if the workspace stays flat); changes to trait signatures or supporting-type semantics require an ADR and a note update. The audit hash function and canonical JSON form carry a format version stored in the database header.

## Tests

- Each trait gets a conformance test suite that any implementation must pass (for example `launcher::tests::backend_conformance` runs fault injection against every backend).
- `trybuild` compile-fail tests: constructing `CanonicalHost` outside `netguard`, placing an `Issued` in `SandboxSpec.env`, formatting `Issued` with `{:?}` showing the secret.
- Property test: for random adapter outputs, the pipeline's decision is the conjunction of the individual Cedar decisions.

## How it connects

- part-of:: [[Repository Layout]]
- depends-on:: [[Tech Stack]]
- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[Policy Engine and Entity Builder]]
- depends-on:: [[Broker Cedar Schema]]
- delivered-by:: [[M0 Contained Run]]
- decided-by:: [[ADR-015 Rust for the Endpoint and Custom Proxy]]

Implemented by (each of these notes carries `implements:: [[Core Trait Contracts]]`): [[Sandbox Launcher]] (`SandboxBackend`), [[Git Smart-HTTP Adapter]], [[GitHub API Adapter]], [[Registry and LLM API Adapters]] and [[MCP Guard]] (`ProtocolAdapter`), [[Credential Injector and Issuers]] (`CredentialIssuer`), [[Audit Recorder and Event Schema]] (`Recorder`).

## Implications for the build

- Create these traits in M0 even though only `SandboxBackend` and a minimal `Recorder` have real implementations then; later milestones add implementations, not new seams.
- `async_trait` and `anyhow` are the report's choices; crate versions beyond `hudsucker` ([GitHub](https://github.com/omjadas/hudsucker)) and `landlock` ([crates.io](https://crates.io/crates/landlock)) are unverified ([[Open Questions and Unverified Claims]]).
- Across hosts (CI sidecar, gateway), the `Grant` is carried as an [[Internal Grant JWT]].

## Open questions

- Whether `attach` should be async for issuers that sign bodies (SigV4 with streaming payloads).
- Whether `ProtocolAdapter` needs a response hook (for example to set `sensitive_read` from a GitHub API response); the report's trait has none, so response-derived labels currently live in the L7 pipeline.

## Sources

- https://github.com/omjadas/hudsucker
- https://crates.io/crates/landlock
- https://github.com/craigbalding/safeyolo/issues/620
- Report: "Interfaces" Rust block (verbatim), "Implementation choice", "Tech stack"; research note 05 section 4.

## Build log

- 2026-09-24: `SandboxBackend` (`code/crates/launcher/src/lib.rs`) and `Recorder` (`code/crates/audit/src/lib.rs`) implemented with the documented contracts. `launch` takes the spec by value (it owns the stdio descriptors). `ProtocolAdapter` and `CredentialIssuer` arrive with their first implementations in M1. `CanonicalHost` has private fields and only `netguard::canon` constructs it.
