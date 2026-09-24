---
title: "Credential Injector and Issuers"
aliases: ["creds", "Credential Issuers", "Credential Injector"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/credentials, topic/identity, control/cred-out, control/task-tok, boundary/tb3, boundary/tb4, invariant/i1, invariant/i7, milestone/m1, milestone/m3]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The creds crate: sentinel store plus CredentialIssuer implementations (static, github_app, aws_sts, oauth_exchange, vault) that mint or reuse per scope digest, attach headers or re-sign SigV4, keep material only in broker memory (Zeroizing) and hold roots in Keychain or libsecret."
related: ["[[Just-in-Time Credential Minting]]", "[[Sentinel Swap Pattern]]", "[[GitHub App Installation Tokens]]", "[[AWS STS Session Policies]]", "[[RFC 8693 Token Exchange]]", "[[Core Trait Contracts]]", "[[I1 No Secrets in the Sandbox]]", "[[I7 Reject Foreign Credentials]]", "[[TLS Termination and Per-Session CA]]", "[[Risk Register]]", "[[Policy Engine and Entity Builder]]", "[[Broker CLI and Daemon]]", "[[Audit Recorder and Event Schema]]", "[[Git Smart-HTTP Adapter]]", "[[Registry and LLM API Adapters]]", "[[MCP Guard]]", "[[Okta Cross App Access]]", "[[Entra Agent ID]]", "[[GCP Credential Access Boundaries]]", "[[Request and Session Lifecycle]]", "[[broker.toml Human Policy Layer]]", "[[ADR-005 Mint Credentials Per Task]]", "[[M1 Secrets Outside]]", "[[M3 CI Identity and MCP]]", "[[Conformance Probe Matrix]]", "[[Open Questions and Unverified Claims]]", "[[L4 Product Metrics]]", "[[Policy Learning Loop]]", "[[Repository Layout]]"]
sources: ["https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app", "https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html", "https://www.rfc-editor.org/rfc/rfc8693", "https://code.claude.com/docs/en/sandboxing", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes", "https://docs.runloop.ai/docs/devboxes/agent-gateways", "https://startwithidentity.com/blog/agent-identity-gets-a-protocol/", "https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials"]
milestone: M1
---

# Credential Injector and Issuers

> The creds crate: sentinel store plus CredentialIssuer implementations (static, github_app, aws_sts, oauth_exchange, vault) that mint or reuse per scope digest, attach headers or re-sign SigV4, keep material only in broker memory (Zeroizing) and hold roots in Keychain or libsecret.

## Responsibility

`crates/creds` ([[Repository Layout]]: "sentinel store; issuers/{static,github_app,aws_sts,oauth_exchange,vault}"). It is the only code that ever touches real credential material, and it runs only inside `brokerd`. Two tiers (research note 05 §3.2, **Proposal**):

- **Static swap** (fallback): a sentinel in the sandbox is replaced by a secret held in Keychain, 1Password, Vault or AWS Secrets Manager ([[Sentinel Swap Pattern]]).
- **Minting** (preferred): a GitHub App installation token limited to the granted repos and permissions; AWS `AssumeRole` with an inline session policy compiled from the Cedar grant, with SigV4 re-signing; OAuth 2.0 token exchange or ID-JAG against Okta/Entra; GCP/Azure workload-identity federation later ([[Just-in-Time Credential Minting]]).

From the request life (report): "Only if all of them allow does the issuer mint or reuse a cached token for that scope digest and attach it."

**It must never:** mint or attach without a prior Cedar allow for `credential.use` on that credential; write a secret to disk, logs, audit events, error messages or any response; place a secret in `SandboxSpec.env`; attach a credential to a host outside the credential's `allowed_hosts`; reuse a broader cached token for a narrower need; forward a user's IdP token as-is to an upstream or MCP server; call an issuer from an adapter directly.

## Inputs and outputs

| Input | From | Output | To |
|---|---|---|---|
| `CredentialBinding` (credential UID, issuer, scope) on an allowed decision | [[Policy Engine and Entity Builder]] | `Issued` handle (secret stays in `creds`) | L7 pipeline |
| Stripped request | [[TLS Termination and Per-Session CA]] | Request with header set or SigV4 signature | upstream |
| Header values seen on the wire | L7 strip step | `SentinelCheck::{Valid, Foreign, None}` | I7 check |
| Session start / stop | [[Broker CLI and Daemon]] | Sentinel set for `SandboxSpec.env`; zeroization | launcher |
| Roots (keys, refresh tokens, static secrets) | Keychain or libsecret | in-memory `Zeroizing` buffers | issuers |
| Every mint and reuse | issuers | `credential_id`, issuer, expiry, scope digest (never the value) | [[Audit Recorder and Event Schema]] |

## Interface

The trait is verbatim from the report (**Proposal; not compiled**; see [[Core Trait Contracts]]):

```rust
/// Mints upstream credentials; material never leaves broker memory.
#[async_trait::async_trait]
pub trait CredentialIssuer: Send + Sync {
    fn kind(&self) -> &'static str;                      // "static" | "github_app" | "aws_sts" | "oauth_exchange"
    async fn mint(&self, grant: &Grant) -> anyhow::Result<Issued>; // Issued{secret: Zeroizing<..>, expires_at, scope_digest}
    fn attach(&self, issued: &Issued, req: &mut http::Request<Body>) -> anyhow::Result<()>; // header or SigV4
}
```

Supporting API (**Proposal; not compiled**):

```rust
pub struct Sentinel(String);                       // "brk_s_" + 32 bytes CSPRNG, base32; per session, never reused
pub struct SentinelBinding { session: SessionId, credential: EntityUid, allowed_hosts: Vec<HostPattern>, expires_at: SystemTime }

pub trait SentinelStore: Send + Sync {
    fn issue(&self, session: &SessionId, cred: &EntityUid, env_var: &str) -> Sentinel;
    fn check(&self, session: &SessionId, value: &[u8], dest: &CanonicalHost) -> SentinelCheck; // constant-time compare
    fn drop_session(&self, session: &SessionId);    // zeroize all bindings
}

pub struct TokenCache { /* HashMap<[u8; 32] /*scope_digest*/, Arc<Issued>> */ }
impl TokenCache {
    pub async fn get_or_mint(&self, issuer: &dyn CredentialIssuer, grant: &Grant) -> anyhow::Result<Arc<Issued>>;
}

/// scope_digest = H(kind || upstream audience || sorted permission set || resource set || session id)
pub fn scope_digest(grant: &Grant, session: &SessionId) -> [u8; 32];

impl std::fmt::Debug for Issued { /* prints credential_id, kind, expires_at; never secret */ }
```

The scope digest formula is the one proposed in [[Just-in-Time Credential Minting]]: equal authority reuses one token; a narrower need never receives a broader cached token.

Credential declarations in the human layer ([[broker.toml Human Policy Layer]]): the first two are verbatim from the report, the rest **Proposal**.

```toml
credential = { kind = "static", ref = "keychain:anthropic" }
credential = { kind = "github_app", permissions = { contents = "write" }, repos = ["${repo_remote}"], ttl = "30m" }

# Proposal (M3)
credential = { kind = "aws_sts", role = "arn:aws:iam::123456789012:role/agent-s3", duration = "15m",
               session_policy = "derived", source_identity = "${user}" }

# Org-only issuer configuration (never repo scope)
[issuers.github_app.acme]
app_id = "<app id>"
private_key = "keychain:github-app-acme"
```

## Internal design

### Issuers

**Proposal**, with the provider facts cited.

- **`static`.** Reads the secret from the keychain on first use in a session, keeps it in `Zeroizing<Vec<u8>>`, attaches it to the declared header. Used for LLM API keys and SaaS keys with no native scoping, where "the broker's method/path allowlist *is* the scope" (report).
- **`github_app`.** Creates an installation token with explicit `repositories` (the session repo) and a `permissions` subset; tokens expire after 1 hour, and omitting either field inherits the whole installation, so the issuer always sets both ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app); [[GitHub App Installation Tokens]]). The cache TTL is the smaller of the upstream expiry and the declared `ttl`.
- **`aws_sts`.** `AssumeRole` with `DurationSeconds` 900 s by default (range 900 s to 43,200 s, capped at 1 h when chaining), an inline session policy compiled from the grant (inline `Policy` plus up to 10 `PolicyArns` within 2,048 plaintext characters; effective permissions are the intersection with the role), session tags, and `SourceIdentity` carrying the user or agent ID into CloudTrail ([AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html); [[AWS STS Session Policies]]). `attach` re-signs with SigV4; Claude Code's `mask` also re-signs SigV4 rather than swapping ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)).
- **`oauth_exchange`.** RFC 8693 exchange with `subject_token`, optional `actor_token` and the nested `act` claim ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693); [[RFC 8693 Token Exchange]]); ID-JAG or Entra OBO obtain the user-delegated token at task start, which is narrowed immediately and cached only in memory ([[Okta Cross App Access]], [[Entra Agent ID]]). Rationale: "delegation chains inherit the broadest permission unless actively narrowed" ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)).
- **`vault`.** Dynamic secrets from a secrets manager; background knowledge only in the record ([[Open Questions and Unverified Claims]]).
- **Later.** GCP Credential Access Boundaries cover Cloud Storage only, at most 10 rules ([GCP docs](https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials); [[GCP Credential Access Boundaries]]).

### Call order

1. L7 strips client credentials and calls `SentinelStore::check`; a non-sentinel value is `Foreign` and the request is rejected ([[I7 Reject Foreign Credentials]]).
2. Policy returns `Allow` with a `CredentialBinding` only if `credential.use` allowed (the org ceiling forbids any `dest_host` outside `allowed_hosts`).
3. `TokenCache::get_or_mint` → issuer `mint` on miss; failure denies with `mint_failed`, as LangSmith's callback-issued credentials fail closed ([LangChain](https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes)).
4. `attach`; the pipeline registers the attached secret with the response filter.
5. Audit append with `credential_id`, issuer and `mint|reuse`.

## State

| State | Where | Lifetime |
|---|---|---|
| Sentinel bindings | `brokerd` memory | session |
| Minted tokens (`Arc<Issued>`) | `brokerd` memory | min(upstream expiry, ttl, session) |
| Static secrets read from keychain | `brokerd` memory, `Zeroizing` | session |
| Token metadata (ID, issuer, expiry, digest) | SQLite | audit retention |
| Roots | Keychain or libsecret | persistent |

## Failure modes and fail-closed behaviour

- Keychain locked or item missing: mint fails for that credential with a clear reason; other credentials unaffected.
- Upstream mint error, timeout or unexpected scope in the response: deny; never forward without the credential and never fall back to a broader credential.
- Clock skew near expiry: refresh when fewer than a margin of seconds remain (margin not in the record).
- `brokerd` restart: all tokens and sentinels are gone; sandboxes are killed, so no stale sentinel remains valid.

## Security considerations

- **Honeypot risk.** The report's risk row "Broker becomes the credential honeypot" is mitigated by a per-user daemon, keychain-held roots, memory-only minted tokens with short TTLs, and a control socket unreachable from sandboxes ([[Risk Register]]).
- **Off-host sentinels.** A sentinel is honoured only by this broker, for this session, on its bound hosts; the design follows Runloop's "devbox-bound" gateway tokens ([Runloop](https://docs.runloop.ai/docs/devboxes/agent-gateways)).
- **Allowed-domain abuse.** Binding plus foreign rejection is what stops an attacker's own key on an allowed host ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).
- **Memory hygiene.** `Zeroizing` buffers, no `Clone` on secret types, redacted `Debug`, and no secret in panic messages; consider `mlock` for secret pages (not in the record).
- **Response reflection.** Every attached value is registered with the response filter, including common encodings.

## Performance budget

Attach and reuse are in-memory (microseconds). A first-use mint adds one upstream round trip, which is not measured in the record; the per-scope cache keeps it to once per session and scope. Report mint latency separately in [[L4 Product Metrics]].

## Invariants upheld

[[I1 No Secrets in the Sandbox]] (only sentinels leave `creds`), [[I7 Reject Foreign Credentials]] (sentinel check), I9 (every mint and reuse audited by ID).

## Test plan

- **Unit:** scope-digest equality and inequality cases; GitHub request body always contains `repositories` and `permissions`; STS request carries the compiled session policy and duration; SigV4 re-signing against recorded fixtures.
- **Property:** a narrower grant never receives a cached broader token; a sentinel from session A is never `Valid` in session B or on a host outside its bindings; no code path calls `mint` without an `Allow` for `credential.use` (call-graph test plus e2e with a deny policy showing zero mint calls).
- **Compile-fail (`trybuild`):** `Issued` in `SandboxSpec.env`; `{:?}` on `Issued` exposing the secret; cloning a secret buffer.
- **Fuzz:** header and body sentinel swap must not corrupt framing (Content-Length, chunking).
- **Zeroization:** after `session.stop`, a memory scan of `brokerd` finds no secret bytes for that session.
- **Conformance and E2E:** categories 1 and 2 ([[Conformance Probe Matrix]]); M1 scan finds only sentinels, and a sentinel copied off-host is useless ([[M1 Secrets Outside]]); S3 read via minted credentials and writes outside the prefix denied ([[M3 CI Identity and MCP]]).

## Crates

`creds`; `zeroize`, `ring` or `sha2` for digests, `reqwest` or `hyper` for issuer calls, an AWS SigV4 implementation and a keychain/libsecret binding. None beyond `hudsucker` and `landlock` are verified in the record ([[Open Questions and Unverified Claims]]).

## Delivering milestone

[[M1 Secrets Outside]]: sentinel store, foreign rejection, `static`, `github_app`, token cache, keychain access. [[M3 CI Identity and MCP]]: `aws_sts` with session policy and SigV4. `oauth_exchange` is phase 3.

## How it connects

- implements:: [[Core Trait Contracts]]
- implements:: [[Just-in-Time Credential Minting]]
- implements:: [[Sentinel Swap Pattern]]
- implements:: [[I1 No Secrets in the Sandbox]]
- implements:: [[I7 Reject Foreign Credentials]]
- depends-on:: [[GitHub App Installation Tokens]]
- depends-on:: [[AWS STS Session Policies]]
- depends-on:: [[RFC 8693 Token Exchange]]
- depends-on:: [[Policy Engine and Entity Builder]]
- part-of:: [[TLS Termination and Per-Session CA]]
- mitigates:: [[Risk Register]]
- evaluated-by:: [[Conformance Probe Matrix]]
- delivered-by:: [[M1 Secrets Outside]]
- delivered-by:: [[M3 CI Identity and MCP]]
- decided-by:: [[ADR-005 Mint Credentials Per Task]]

## Implications for the build

- Put `mint` behind a capability type only the policy crate can construct (for example `AllowedBinding`), so the compiler enforces "no mint without allow".
- Issuers derive upstream scope from the same grant that Cedar evaluated; the [[Policy Learning Loop]] derives GitHub `permissions` and STS session policies from observed operations.
- Adapters declare credential header locations; `creds` owns the strip list.

## Open questions

- Upstream revocation of minted tokens at session end (GitHub, AWS) is not covered by the record.
- Dynamic-secret engines (Vault, 1Password, Infisical) are background only.
- Whether `attach` must become async for streaming SigV4 payloads ([[Core Trait Contracts]]).

## Sources

- https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- https://www.rfc-editor.org/rfc/rfc8693
- https://code.claude.com/docs/en/sandboxing
- https://www.anthropic.com/engineering/how-we-contain-claude
- https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes
- https://docs.runloop.ai/docs/devboxes/agent-gateways
- https://startwithidentity.com/blog/agent-identity-gets-a-protocol/
- https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials
- Report: component diagram `creds` line, `CredentialIssuer` trait, request-life step 4, risk "Broker becomes the credential honeypot", tech-stack local-state row, "Enterprise identity plugs in at task start"; research notes 03 Q1 and Q3, 05 §3.2.
