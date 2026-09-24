---
title: "Internal Grant JWT"
aliases: ["Grant JWT", "Session Grant"]
type: interface
section: architecture
tags: [sandbox/architecture, interface, topic/identity, topic/credentials, topic/policy, platform/ci, platform/k8s, platform/cloud, control/task-tok, boundary/tb3, boundary/tb7, invariant/i1, invariant/i7, milestone/m3, evidence/conflict]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "When sandbox and broker are on different hosts (CI sidecar, gateway mode) the grant travels as a Txn-Token-shaped, DPoP-bound JWT (iss, aud, sub, nested act chain, txn, scope, tctx with repo, branch_prefix, allowed method/host/path and labels, 15-minute exp, cnf.jkt); on one laptop it stays Cedar entity data."
related: ["[[Transaction Tokens and Agent Auth Drafts]]", "[[DPoP and mTLS-Bound Tokens]]", "[[RFC 8693 Token Exchange]]", "[[ADR-008 Grant Representation as Entities and Txn-Token JWT]]", "[[Macaroons and Biscuit]]", "[[Architecture Overview]]", "[[Broker Cedar Schema]]", "[[M3 CI Identity and MCP]]", "[[RFC 9396 Rich Authorization Requests]]", "[[Policy Engine and Entity Builder]]", "[[Core Trait Contracts]]", "[[Credential Injector and Issuers]]", "[[Netguard Ingress]]", "[[Trifecta Session Labels]]", "[[Request and Session Lifecycle]]", "[[Revocable Sub-Agent Delegation]]", "[[Cloud Sandbox Runtimes]]", "[[I1 No Secrets in the Sandbox]]", "[[I7 Reject Foreign Credentials]]", "[[Open Questions and Unverified Claims]]", "[[Repository Layout]]"]
sources: ["https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08", "https://www.rfc-editor.org/rfc/rfc8693", "https://www.rfc-editor.org/rfc/rfc9449", "https://www.rfc-editor.org/rfc/rfc8705", "https://www.rfc-editor.org/rfc/rfc9396", "https://www.rfc-editor.org/rfc/rfc8707.html", "https://docs.runloop.ai/docs/devboxes/agent-gateways", "https://doc.biscuitsec.org/getting-started/introduction.html", "https://vercel.com/docs/sandbox/concepts/firewall", "https://datatracker.ietf.org/doc/html/draft-oauth-transaction-tokens-for-agents-04"]
milestone: M3
---

# Internal Grant JWT

> When sandbox and broker are on different hosts (CI sidecar, gateway mode) the grant travels as a Txn-Token-shaped, DPoP-bound JWT (iss, aud, sub, nested act chain, txn, scope, tctx with repo, branch_prefix, allowed method/host/path and labels, 15-minute exp, cnf.jkt); on one laptop it stays Cedar entity data.

## Purpose

The report (**Proposal**): "On a single laptop, nothing token-shaped needs to leave the broker. The sandbox holds a per-session sentinel, and the grant lives in the broker as Cedar entity data. Once the sandbox and the broker are on different hosts (CI sidecar or cloud 'gateway mode'), the grant travels as a Transaction-Token-shaped JWT." It is produced and verified by `crates/grant` ([[Repository Layout]]: "Txn-Token-shaped grant JWT, DPoP binding (CI/gateway)"). The choice of entities in-process and a Txn-Token JWT across hosts, with Biscuit later, is [[ADR-008 Grant Representation as Entities and Txn-Token JWT]].

The grant is a **capability request carrier**, not an upstream credential: it tells a remote broker which Task the traffic belongs to and the ceiling of what that Task may ask for. Upstream tokens are still minted by the broker and never leave it ([[Credential Injector and Issuers]]).

**It must never:** be accepted without a valid sender-constraint proof; widen what the receiving broker's own policy allows; carry an upstream secret or a user's IdP token; live longer than 15 minutes; be accepted by an audience other than the one named in `aud`.

## Schema (verbatim from the report; Proposal; not compiled)

```json
{
  "iss": "https://broker.example/tenant/acme",
  "aud": "broker:acme",
  "sub": "okta|00u1abc",
  "act": { "sub": "agent:claude-code@2.1.x", "act": { "sub": "spiffe://acme/sandbox/7f3c" } },
  "txn": "task-01J9...",
  "scope": "task",
  "tctx": {
    "repo": "github.com/acme/web",
    "branch_prefix": "agent/",
    "allowed": [
      { "method": "GET",  "host": "api.github.com", "path": "/repos/acme/web/**" },
      { "method": "POST", "host": "api.github.com", "path": "/repos/acme/web/pulls" }
    ],
    "labels": { "untrusted_input": false, "sensitive_read": false }
  },
  "iat": 1790000000, "exp": 1790000900,
  "cnf": { "jkt": "<DPoP key thumbprint>" }
}
```

"The grant is sender-constrained with DPoP (or mTLS with a SPIFFE SVID), so a leaked grant is useless outside the issuing sandbox. The same idea underlies Runloop's 'devbox-bound' gateway tokens" ([Runloop](https://docs.runloop.ai/docs/devboxes/agent-gateways)).

## Claim semantics

| Claim | Meaning | Source standard | Cedar mapping ([[Broker Cedar Schema]]) |
|---|---|---|---|
| `iss` | the issuing broker for the tenant | JWT | trusted issuer key from the bundle |
| `aud` | the receiving broker's trust domain | Txn-Token `aud` is the trust domain | must equal local tenant audience |
| `sub` | the human principal from Okta or Entra | Txn-Token required `sub` | `User` entity |
| `act` | delegation chain: agent, then sandbox SPIFFE ID | RFC 8693 nested `act` ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) | `Agent` entity; sandbox identity for audit |
| `txn` | task ID | Txn-Token required `txn` | `Task` entity UID |
| `scope` | always `task` | Txn-Token required `scope` | none |
| `tctx.repo`, `tctx.branch_prefix` | task repo and branch prefix | Txn-Token immutable `tctx` | `Task.repo`, `Task.branch_prefix` |
| `tctx.allowed` | ceiling of method, host, path | RAR-like `actions`/`locations` ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396)) | grant entities on `Host`/`PathPrefix` |
| `tctx.labels` | trifecta floor at issue time | none | initial `session.trifecta` (only more restrictive later) |
| `iat`, `exp` | ≤15 minutes apart | Txn-Tokens are "on the order of minutes or less" | `Task.expires_at` = min(existing, `exp`) |
| `cnf.jkt` | thumbprint of the DPoP key | DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) | proof checked before any entity is built |

Transaction Tokens (draft-08, March 2026) are short-lived JWTs whose required claims are `txn`, `sub`, `scope`, `aud`, `iat`, `exp` and `req_wl`, with optional immutable `tctx` and `rctx`; they are obtained through RFC 8693 exchange with `requested_token_type=urn:ietf:params:oauth:token-type:txn_token` and travel in a `Txn-Token` header ([draft-08](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08)). A companion individual draft exists for agents ([draft-oauth-transaction-tokens-for-agents-04](https://datatracker.ietf.org/doc/html/draft-oauth-transaction-tokens-for-agents-04)). See [[Transaction Tokens and Agent Auth Drafts]].

> [!warning] Conflict
> The report's example omits `req_wl`, which draft-08 lists as required. **Proposal:** add `"req_wl"` naming the requesting workload (the sandbox SPIFFE ID, duplicated from the innermost `act.sub`) so the token is draft-conformant; record the choice in the ADR-008 build log.

## Wire format

**Proposal; not compiled.** Every request from the remote sandbox side to the broker carries:

```http
CONNECT api.github.com:443 HTTP/1.1
Txn-Token: eyJhbGciOiJFUzI1NiIsInR5cCI6InR4bl90b2tlbitqd3QifQ...
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Li4ufX0...
```

DPoP proofs carry `htm`, `htu`, `iat` and `jti`, with the token bound through `cnf.jkt`; mTLS-bound tokens use `cnf.x5t#S256` instead ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449); [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705); [[DPoP and mTLS-Bound Tokens]]). For CONNECT, `htu` is the authority form; for L7 requests after termination, the proof covers the inner request. The JOSE `alg` (ES256 or EdDSA) and `typ` values are design defaults, not in the record.

```rust
// crates/grant (Proposal; not compiled)
pub struct GrantClaims { pub iss: String, pub aud: String, pub sub: String, pub act: Act,
                         pub txn: String, pub scope: String, pub tctx: Tctx, pub iat: u64, pub exp: u64,
                         pub req_wl: Option<String>, pub cnf: Cnf }
pub struct Tctx { pub repo: String, pub branch_prefix: String, pub allowed: Vec<Allowed>, pub labels: Labels }
pub struct Allowed { pub method: String, pub host: String, pub path: String }   // path glob, canonicalised on receipt

pub fn issue(task: &Task, sandbox_jkt: &Thumbprint, key: &SigningKey, now: u64) -> anyhow::Result<String>;
pub fn verify(token: &str, dpop: &str, req: &RequestTarget, trust: &GrantTrust, replay: &JtiCache, now: u64)
    -> Result<VerifiedGrant, GrantError>;
pub fn to_entities(g: &VerifiedGrant) -> anyhow::Result<cedar_policy::Entities>;
```

## Contract

**Proposal.**

1. **Issue.** The broker that holds identity (the runner-side broker in CI with runner OIDC; the tenant broker in gateway mode with vendor OIDC) issues the grant at `session.start`, after computing the Task from its bundle, and re-issues before `exp`. `exp - iat ≤ 900`.
2. **Verify, in order:** JWS signature against the tenant key from the bundle; `iss` and `aud` exact match; `now < exp` and `exp - iat ≤ 900`; DPoP proof signature, `jkt` equals `cnf.jkt`, `htm`/`htu` match the request, `iat` fresh, `jti` unseen; then canonicalise every `tctx.allowed.host` and path with the single canonicaliser ([[Netguard Ingress]]); any failure rejects.
3. **Narrow only.** `to_entities` builds the Task and grant entities; the receiving broker still evaluates its own Cedar policy ([[Policy Engine and Entity Builder]]). A request must be allowed by local policy **and** inside `tctx.allowed`; labels from the grant can only start the session more restricted.
4. **Never a credential.** The grant never authorizes an upstream directly; `credential.use` is decided locally and minted locally.
5. **Foreign-credential rule still applies.** `Txn-Token` and `DPoP` headers are consumed by the broker and stripped before forwarding, like the macOS loopback sentinel ([[I7 Reject Foreign Credentials]]).

## Where the DPoP key lives

**Proposal.** The key belongs on the sandbox side of the hop but outside the agent's process tree: in the host-side bridge or the vendor's redirector for gateway mode, or in a launcher-owned helper whose memory the agent cannot read. If a deployment must put it inside the sandbox, the pair (grant, key) is a sentinel-class capability: valid for ≤15 minutes, only against one broker audience, only within that Task's ceiling. That is weaker than keeping it outside, so the deployment guide must say so ([[I1 No Secrets in the Sandbox]]).

## Versioning

**Proposal.** The `typ` header value versions the format; `tctx` fields are additive; removing or renaming a claim needs an ADR. Biscuit is "deferred to phase 2, for sub-agent delegation: holders can attenuate them offline, and Datalog caveats express argument constraints" ([Biscuit](https://doc.biscuitsec.org/getting-started/introduction.html); [[Macaroons and Biscuit]], [[Revocable Sub-Agent Delegation]]). An RFC 9396 `authorization_details` shape is the alternative form research note 03 mentions for `allowed`.

## Failure modes and fail-closed behaviour

Missing or invalid token or proof, replayed `jti`, expired grant, unknown issuer key, audience mismatch, uncanonicalisable `allowed` entry: reject the connection with a broker error and audit `grant_invalid`. Clock skew tolerance is a small fixed window (value not in the record).

## Security considerations

- **Replay across sandboxes** is prevented by `cnf.jkt`; replay within one sandbox by the `jti` cache and short `exp`.
- **Audience** follows the same logic as RFC 8707 resource pinning ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)): a grant for tenant A's broker is useless at tenant B's.
- **Vendor identity.** In gateway mode the vendor's own OIDC token (for example Vercel's `vercel-sandbox-oidc-token` with `sandbox_id` claims, [Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)) authenticates the host-side hop; the grant binds the Task. Both are checked ([[Cloud Sandbox Runtimes]]).
- **Size and parsing.** The JWT parser is a fuzz target; `allowed` is bounded in length.

## Tests

- **Unit:** verification matrix, one case per failure above; `to_entities` golden output.
- **Property:** mutating any claim invalidates the signature; for random local policies and grants, allowed(request) ⇒ local_allow ∧ inside(`tctx.allowed`).
- **Replay:** the same DPoP proof twice → second rejected; grant from sandbox A with sandbox B's key → rejected.
- **Fuzz:** JWS and DPoP parsers.
- **E2E** ([[M3 CI Identity and MCP]]): CI sidecar fixture where the broker runs as a separate container; the agent tree sees no long-lived secret; a grant copied out of the job is useless.

## How it connects

- implements:: [[Transaction Tokens and Agent Auth Drafts]]
- implements:: [[DPoP and mTLS-Bound Tokens]]
- depends-on:: [[RFC 8693 Token Exchange]]
- depends-on:: [[Broker Cedar Schema]]
- contrasts-with:: [[RFC 9396 Rich Authorization Requests]]
- contrasts-with:: [[Macaroons and Biscuit]]
- part-of:: [[Architecture Overview]]
- delivered-by:: [[M3 CI Identity and MCP]]
- decided-by:: [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]

## Implications for the build

- M3 builds `txn_token.rs` and `dpop.rs`; nothing on the laptop path uses them.
- Keep `to_entities` in `grant` but have it call the same entity-builder helpers as the in-process path, so both representations produce identical Cedar data.
- Signing keys are per tenant broker and rotate through the bundle.

## Open questions

- `req_wl` handling (conflict above) and whether the SPIFFE ID is attested; SPIFFE details are background only in the record.
- DPoP versus mTLS with SVIDs per deployment mode; Kubernetes may favour mTLS.
- Re-issue cadence for long tasks under a 15-minute `exp`, and how label changes propagate between brokers ([[Open Questions and Unverified Claims]]).

## Sources

- https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08
- https://datatracker.ietf.org/doc/html/draft-oauth-transaction-tokens-for-agents-04
- https://www.rfc-editor.org/rfc/rfc8693
- https://www.rfc-editor.org/rfc/rfc9449
- https://www.rfc-editor.org/rfc/rfc8705
- https://www.rfc-editor.org/rfc/rfc9396
- https://www.rfc-editor.org/rfc/rfc8707.html
- https://docs.runloop.ai/docs/devboxes/agent-gateways
- https://doc.biscuitsec.org/getting-started/introduction.html
- https://vercel.com/docs/sandbox/concepts/firewall
- Report: "The internal grant (Proposal)" JSON and paragraph (verbatim), repository layout `grant` crate, decisions table (grant representation); research note 03 Q1 inference "Recommended internal token design" and "Sender-constrain the sandbox→broker hop".

## Build log

- 2026-09-25 (M3): not built yet; `code/crates/grant` now holds the strict JWS parser and RS256 verification it will build on, used for CI identity tokens ([[ADR-031 CI Identity as Built]]).
