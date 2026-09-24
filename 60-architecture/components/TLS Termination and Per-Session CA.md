---
title: "TLS Termination and Per-Session CA"
aliases: ["L4 Fast Path", "L7 Path", "Per-Session CA", "tls crate", "l7 crate", "Response Filter"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/tls, topic/egress, topic/credentials, control/egress, control/cred-out, boundary/tb3, boundary/tb4, invariant/i1, invariant/i6, invariant/i7, milestone/m1, evidence/conflict]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Per-connection path choice: the L4 fast path splices bytes after an SNI peek when no credential or L7 rule applies; the L7 path terminates with a just-in-time per-session CA leaf, enforces CONNECT=SNI=Host, parses h1/h2, authorizes, strips client credentials, injects, re-originates verified TLS and filters responses; CA bundle env vars; QUIC and SNI-less protocols blocked."
related: ["[[ADR-004 Selective TLS Termination with Per-Session CA]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[I7 Reject Foreign Credentials]]", "[[Credential Injector and Issuers]]", "[[Policy Engine and Entity Builder]]", "[[Netguard Ingress]]", "[[Vercel Sandbox]]", "[[Risk Register]]", "[[M1 Secrets Outside]]", "[[Request and Session Lifecycle]]", "[[Hostname Canonicaliser]]", "[[I1 No Secrets in the Sandbox]]", "[[I6 Single Canonicaliser]]", "[[Core Trait Contracts]]", "[[Git Smart-HTTP Adapter]]", "[[GitHub API Adapter]]", "[[Registry and LLM API Adapters]]", "[[MCP Guard]]", "[[Sandbox Launcher]]", "[[Audit Recorder and Event Schema]]", "[[Conformance Probe Matrix]]", "[[L4 Product Metrics]]", "[[Cloud Sandbox Runtimes]]", "[[Docker Sandboxes]]", "[[Sentinel Swap Pattern]]", "[[Open Questions and Unverified Claims]]", "[[ADR-015 Rust for the Endpoint and Custom Proxy]]"]
sources: ["https://vercel.com/docs/sandbox/concepts/firewall", "https://blog.cloudflare.com/sandbox-auth/", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://docs.e2b.dev/network/internet-access.md", "https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o", "https://github.com/omjadas/hudsucker", "https://github.com/craigbalding/safeyolo/issues/620", "https://docs.docker.com/ai/sandboxes/network-policies/", "https://www.memorysafety.org/blog/rustls-performance/", "https://arxiv.org/abs/2405.17737"]
milestone: M1
---

# TLS Termination and Per-Session CA

> Per-connection path choice: the L4 fast path splices bytes after an SNI peek when no credential or L7 rule applies; the L7 path terminates with a just-in-time per-session CA leaf, enforces CONNECT=SNI=Host, parses h1/h2, authorizes, strips client credentials, injects, re-originates verified TLS and filters responses; CA bundle env vars; QUIC and SNI-less protocols blocked.

## Responsibility

Two crates from [[Repository Layout]]: `tls` ("per-session CA, leaf cache, trust-bundle writer") and `l7` ("http1/h2; adapters/..."). Together they take an admitted connection from [[Netguard Ingress]] and either pass it through untouched (L4) or run the eight-step L7 pipeline in which authorization, credential stripping and injection happen. This is the core of trust boundary TB4: real credentials are attached here and nowhere else.

**It must never:** install the CA into the host system trust store; inject a credential on the L4 path or on a pinned-passthrough host; forward a request that no Cedar policy allowed (unmatched L7 requests are denied, [[ADR-006 Deny Unmatched L7 Requests]]); forward client credentials ([[I7 Reject Foreign Credentials]]); relay a response containing an injected secret ([[I1 No Secrets in the Sandbox]]); accept an upstream certificate that fails verification.

## Path choice

**Proposal (report).** For each admitted connection:

- **L4 fast path.** Peek at the SNI. If the host is allowed and no credential or L7 rule applies, splice the bytes without decrypting them. This preserves pinned clients and saves CPU. Vercel does the same, terminating only for domains with `transform` or `forwardURL` rules ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)).
- **L7 path** for hosts with credentials or method and path rules, or claimed by a protocol adapter (git, GitHub API, private registries, LLM APIs, MCP over HTTP).

Decision function (**Proposal; not compiled**):

```rust
pub enum Path { L4Splice, L7Terminate, Deny(Reason) }

fn choose_path(host: &CanonicalHost, sni: Option<&CanonicalHost>, s: &SessionCtx, pol: &PolicyView) -> Path {
    match sni {
        None => Path::Deny(Reason::SniLess),                  // SSH and SNI-less TLS denied by default
        Some(sni) if sni != host => Path::Deny(Reason::ConnectSniMismatch),
        Some(_) if pol.is_pinned_passthrough(host) => Path::L4Splice, // never with credentials
        Some(_) if pol.needs_l7(host, s) => Path::L7Terminate,
        Some(_) => Path::L4Splice,
    }
}
```

## The L7 pipeline

The eight steps are verbatim from the report:

1. Terminate TLS with a leaf certificate minted from a **per-session CA** that is created just in time and destroyed at session end, as Vercel and Cloudflare do ([Cloudflare](https://blog.cloudflare.com/sandbox-auth/)).
2. Require CONNECT target = SNI = `Host`/`:authority`, which blunts domain fronting.
3. Parse HTTP/1.1, HTTP/2 or the protocol adapter's format.
4. Authorize with Cedar.
5. Strip every client-supplied `Authorization`, `x-api-key`, cookie and `Proxy-Authorization` header, and reject any request carrying a credential the broker did not issue. This is the Cowork lesson ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).
6. Inject the minted credential, or re-sign it for AWS SigV4.
7. Re-originate TLS with full verification against public roots.
8. Filter the response so injected secrets are never reflected back.

Also: re-evaluate every redirect hop, and drop credentials on any cross-origin hop. gRPC fits the same model (HTTP/2 with `:path=/pkg.Service/Method`); for WebSockets, policy applies at the upgrade request, and frames after the upgrade are opaque unless a protocol-specific inspector exists (research note 03).

**Proposal: stage wiring.**

```rust
// l7 pipeline per request (Proposal; not compiled)
let head = parse_head(&mut conn).await?;                          // h1 or h2; strict framing
let host = canon_host(head.authority_bytes())?;                   // step 2 inputs, I6
ensure_eq(&conn.connect_host, &conn.sni, &host)?;                 // step 2
let adapter = adapters.iter().find(|a| a.claims(&host, &head)).unwrap_or(&generic_http);
let mut req = BufferedRequest::new(head, body_stream, limits);
let authz = adapter.classify(&mut req, &session).await?;          // step 3
let decision = policy.authorize_all(&session, &authz)?;           // step 4: all must allow
recorder.append(&event_for(&decision))?;                          // write-ahead audit (I9)
if !decision.allowed() { return deny(decision); }
strip_and_check_credentials(&mut req, &session, &host)?;          // step 5, I7
if let Some(binding) = decision.credential() {                    // step 6
    let issued = creds.get_or_mint(binding).await?;
    issuer.attach(&issued, &mut req.as_http_mut())?;
}
let resp = upstream.send_verified(req).await?;                    // step 7: public roots
let resp = response_filter(resp, &issued_secrets_for(&req));      // step 8
```

## Per-session CA and trust bundle

- **Generation.** At `session.start`, `tls` creates a CA key pair and self-signed certificate with `rcgen`; the private key stays in `brokerd` memory. Leaf certificates are minted on first use per host and cached for the session.
- **Distribution.** The CA certificate is merged with public roots into `SandboxSpec.ca_bundle`, and the launcher sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `PIP_CERT`, `CURL_CA_BUNDLE` and the npm `cafile` inside the sandbox ([[Sandbox Launcher]]). Research note 03 adds the Java truststore to the practical compatibility list. **Never** install the CA into the host system trust store.
- **Destruction.** At session end the CA key and leaf cache are dropped (zeroised), so a leaked CA certificate is useless after the session ([[Request and Session Lifecycle]] step 6).
- **Hardening (Proposal).** Leaf lifetimes no longer than the session; consider X.509 name constraints on the CA limited to the session's L7 hosts (not in the record; see open questions).

> [!warning] Conflict
> The deployment-modes table places a "per-user CA key in the OS keychain" on laptops, while the L7 step 1 and the lifecycle describe a per-session CA "created just in time and destroyed at session end". **Proposal:** implement the per-session CA as specified in the L7 steps; if a per-user key is kept in the keychain, it must only sign per-session CAs and never be trusted by the sandbox directly. Record the resolution in an ADR.

## Pinned clients, QUIC, SSH, ECH

- Clients that pin certificates go on a documented passthrough list, with **no** credential injection (report).
- Block QUIC and UDP/443 so clients fall back to TCP, since E2B notes QUIC defeats domain filtering ([E2B docs](https://docs.e2b.dev/network/internet-access.md)).
- Deny SSH and other SNI-less protocols by default; a catch-all `*` lets SSH pass unbrokered at Vercel ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)). Git over SSH is rewritten to HTTPS ([[Git Smart-HTTP Adapter]]).
- Encrypted ClientHello would defeat SNI peeking for sites that enable it; adoption is unmeasured, so this is a watch item ([[Risk Register]]).

## Anti-pattern: "matchers never block"

"A Vercel request that does not match a rule passes through unchanged, just without the credential" ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)). In this broker, method and path rules are authorization decisions, default-deny within an allowed domain ([[ADR-006 Deny Unmatched L7 Requests]], [[Vercel Sandbox]]).

## State

Per session: CA key and certificate, leaf cache, upstream connection pool (keyed by canonical host and credential ID so that a pooled connection never carries another session's credentials), in-flight request metadata.

## Failure modes and fail-closed behaviour

- Leaf minting or TLS handshake failure toward the sandbox: close; client sees a TLS error.
- Upstream certificate verification failure: deny with reason `upstream_tls`; never downgrade.
- Parse failure (malformed h1/h2, ambiguous CL/TE, oversized headers): deny.
- Adapter `classify` error or empty result: deny.
- Mint failure: deny with reason `mint_failed`; do not forward without a credential.
- Audit append failure: deny ([[I9 Hash-Chained Audit Outside the Sandbox]]).

## Security considerations

- **Request smuggling and parser differentials.** Conformance category 8 covers CL/TE framing and h2 downgrade; always re-serialise the request from the parsed form rather than forwarding raw bytes, and reject ambiguous framing ([[Conformance Probe Matrix]]).
- **Domain fronting.** Step 2 compares canonical values from [[Hostname Canonicaliser]].
- **Redirects.** Each `Location` is canonicalised and re-authorized; cross-origin hops lose credentials (category 6).
- **Response filter.** Exact-match search for every secret attached to the request (and its common encodings, for example base64 for basic auth) in headers and body; streaming bodies need a bounded rolling window.
- **Connection reuse.** h2 multiplexing must authorize every stream independently.
- **Custom-proxy risk.** Anthropic's custom proxy "repeatedly introduced vulnerabilities" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)); keep this surface minimal and fuzzed.

## Performance budget

Warm connection added latency p50 ≤5 ms and p95 ≤25 ms; new terminated connection p50 ≤15 ms ([[L4 Product Metrics]]). Reference: a netns, iptables and MITM design with just-in-time certificates added about 14 ms per HTTPS request on an EC2 t3.medium ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)). Rustls has been reported at or above OpenSSL/BoringSSL handshake and throughput performance ([Prossimo](https://www.memorysafety.org/blog/rustls-performance/)). Cache leaf certificates per host per session to keep handshakes cheap.

## Invariants upheld

[[I7 Reject Foreign Credentials]] (step 5), [[I1 No Secrets in the Sandbox]] (step 8, CA key never in the sandbox), [[I6 Single Canonicaliser]] (step 2), [[I9 Hash-Chained Audit Outside the Sandbox]] (write-ahead append).

## Test plan

- Unit: path choice table; header strip list; redirect re-evaluation; response filter with split and encoded secrets.
- Property: for random request heads, the forwarded request never contains a client credential header; decision equals the conjunction of adapter requests.
- Fuzz: h1 head parser, h2 frame handling, chunked decoding.
- Differential: HTTP Garden-style framing comparison ([arXiv 2405.17737](https://arxiv.org/abs/2405.17737)).
- Conformance: categories 1, 2, 5, 6, 7 and 8 of [[Conformance Probe Matrix]]; the M1 acceptance scan and foreign-key probe ([[M1 Secrets Outside]]).
- Compatibility matrix: curl, git, npm, pip, cargo, Node, Python requests, Go (with the `trustd` caveat on macOS), Java.

## Dependencies

`tokio`, `hyper` 1.x, `rustls`, `rcgen`, with `hudsucker` as a reference MITM implementation ([hudsucker](https://github.com/omjadas/hudsucker)); module boundaries follow SafeYolo's separation of route validation, credential selection, policy evaluation, inspection and injection ([SafeYolo #620](https://github.com/craigbalding/safeyolo/issues/620)). Versions beyond `hudsucker` unverified.

## How it connects

- depends-on:: [[Netguard Ingress]]
- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[Policy Engine and Entity Builder]]
- depends-on:: [[Credential Injector and Issuers]]
- depends-on:: [[Core Trait Contracts]]
- implements:: [[I7 Reject Foreign Credentials]]
- implements:: [[Sentinel Swap Pattern]]
- part-of:: [[Request and Session Lifecycle]]
- contrasts-with:: [[Vercel Sandbox]]
- contrasts-with:: [[Docker Sandboxes]]
- mitigates:: [[Risk Register]]
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[L4 Product Metrics]]
- delivered-by:: [[M1 Secrets Outside]]
- decided-by:: [[ADR-004 Selective TLS Termination with Per-Session CA]]
- decided-by:: [[ADR-006 Deny Unmatched L7 Requests]]
- decided-by:: [[ADR-015 Rust for the Endpoint and Custom Proxy]]

## Implications for the build

- M1 delivers the CA, trust-bundle env, selective termination, header and body sentinel swap, foreign-credential rejection and method/path rules.
- Docker's sandbox proxy MITMs by default with opt-out bypass ([Docker docs](https://docs.docker.com/ai/sandboxes/network-policies/)); this design inverts it (L4 by default), so compatibility testing should focus on the L7 host list.
- Keep the pinned-passthrough list in the org ceiling with a reason per entry.

## Open questions

- Per-user keychain CA versus per-session CA (see the conflict callout).
- Name-constrained CA certificates: client support across the compatibility matrix is untested.
- ECH adoption and its effect on SNI peeking; QUIC, gRPC and WebSocket handling by other vendors is undocumented ([[Open Questions and Unverified Claims]]).
- Response filtering for compressed or streamed bodies without unbounded buffering.

## Sources

- https://vercel.com/docs/sandbox/concepts/firewall
- https://blog.cloudflare.com/sandbox-auth/
- https://www.anthropic.com/engineering/how-we-contain-claude
- https://docs.e2b.dev/network/internet-access.md
- https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o
- https://github.com/omjadas/hudsucker
- https://github.com/craigbalding/safeyolo/issues/620
- https://docs.docker.com/ai/sandboxes/network-policies/
- https://www.memorysafety.org/blog/rustls-performance/
- https://arxiv.org/abs/2405.17737
- Report: "L4 by default, L7 only where credentials or verbs matter", "Implementation choice", deployment modes, risk "TLS breakage"; research notes 03 Q4 and 05 sections 3.2 and 3.6.
