---
title: "ADR-021 L7 Path Choices for M1"
aliases: ["ADR-021"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/network, topic/credentials, control/l7, boundary/tb3, boundary/tb4, invariant/i1, invariant/i6, invariant/i7, invariant/i9, milestone/m1]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "M1's L7 path: per-session CA only (no per-user keychain CA), HTTP/1.1 via hyper with ALPN http/1.1 (h2 deferred), no broker-followed redirects, cookies rejected and Set-Cookie stripped on terminated hosts, credentials attached by rule, receive-pack bodies buffered up to 256 MiB, 'not provably fast-forward' counts as force, explicit 64 KiB head limit, parser refusals logged."
related: ["[[TLS Termination and Per-Session CA]]", "[[Credential Injector and Issuers]]", "[[Git Smart-HTTP Adapter]]", "[[Registry and LLM API Adapters]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[I1 No Secrets in the Sandbox]]", "[[I6 Single Canonicaliser]]", "[[I7 Reject Foreign Credentials]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[Conformance Probe Matrix]]", "[[M1 Secrets Outside]]", "[[Risk Register]]", "[[MOC Decisions]]"]
sources: []
superseded_by:
code: ["code/crates/brokerd/src/l7_pipeline.rs", "code/crates/l7/src", "code/crates/creds/src", "code/crates/tls/src", "code/crates/policy/src/l7.rs"]
---

# ADR-021 L7 Path Choices for M1

> Settle the open points of the L7 proposal for M1: per-session CA only, HTTP/1.1 only, no broker-followed redirects, no cookies, rule-driven attachment, buffered push inspection, fail-closed force detection.

## Status

Built (2026-09-24) with [[M1 Secrets Outside]].

## Context

[[TLS Termination and Per-Session CA]] leaves a conflict open (per-user keychain CA versus per-session CA) and describes h1 **and** h2 parsing, redirect re-evaluation, cookie stripping and streamed pack parsing as proposals. [[Git Smart-HTTP Adapter]] leaves "force detection without an upstream round trip for pushes whose pack does not contain the old commit" open. Building M1 forced a choice on each.

## Decision

1. **Per-session CA only.** `rcgen` creates the CA at session start; its key never leaves brokerd memory and is dropped at session end. No per-user CA is kept in the keychain. The CA certificate goes into a per-session trust bundle (session CA, `[tls] extra_roots`, Mozilla roots) in the session temp dir, named by `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `PIP_CERT`, npm/cargo/AWS/Deno equivalents, and `NODE_EXTRA_CA_CERTS` (CA only). The host trust store is never touched.
2. **HTTP/1.1 only.** Leaves offer ALPN `http/1.1`; requests are parsed by `hyper` 1.x and re-serialised toward the upstream (never raw-forwarded). HTTP/2 prior-knowledge is refused. h2 parsing is deferred; the fuzz target list grows when it lands.
3. **Terminate only where needed.** A host is terminated when an admitting grant has `protocol`, `methods`, `paths`, `allow` or `credential`; `passthrough = true` forces L4 (and forbids those keys). Everything else stays on the M0 L4 splice.
4. **No broker-followed redirects.** 3xx responses pass through (the `Location` is logged, bounded); the client's next hop is a new request through the full pipeline. Credentials are attached by rule for the destination, so a cross-origin hop carries none; a sentinel sent there is `sentinel_wrong_host`.
5. **Cookies:** on terminated hosts a request `Cookie` is a foreign credential and `Set-Cookie`/`Set-Cookie2`/`Alt-Svc` are stripped from responses.
6. **Attachment by rule.** When the grant that allowed every action of a request declares a credential, the broker attaches it whether or not the client sent the sentinel (git never sends one before a 401). A client credential is accepted only if it is this session's sentinel for this host; every credential header and credential-like query parameter is stripped before forwarding. Two allowing grants with different credentials deny (`ambiguous_credential`).
7. **Push inspection is buffered**, up to 256 MiB (gzip-decoded bodies included); larger bodies are denied (`body_too_large`), not streamed unchecked.
8. **Force detection fails closed.** An update is a fast-forward only if walking parents inside the pushed pack from the new tip reaches the old tip; deletes, unreadable packs, SHA-256 repositories and ancestry outside the pack are force. Under `force = false` such pushes are denied; no upstream ancestry call is made.
9. **Limits and parser refusals.** Request heads over 64 KiB or 128 fields deny (`head_too_large`); requests hyper refuses to parse are logged as `malformed_request` denies; ambiguous CL/TE framing is answered at most once and the connection closed.
10. **Response filter.** When a secret is attached the request asks for `Accept-Encoding: identity`; bodies are scanned for the secret, its base64/percent forms and the Basic header value with a hold-back window, through a parallel gzip/deflate decoder when needed; other encodings are refused. A match cuts the body and logs `secret_reflected`.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| A per-user CA in the keychain signing per-session CAs | Adds a long-lived key with no M1 requirement for it; the per-session CA is what the L7 steps specify |
| Offer h2 and parse it | Doubles the parser surface in M1; clients fall back to HTTP/1.1 cleanly |
| Follow redirects in the broker | Hides hops from the audit log and re-implements client logic; re-evaluating each client request is simpler and complete |
| Strip (not reject) cookies | Set-Cookie is stripped, so any cookie on a terminated request was planted; rejecting is the I7 reading |
| Stream-parse packs | Needs a resumable inflater and pack index; buffering is simpler and bounded, streaming is future work |
| Ask the forge whether an update is a fast-forward | An extra authenticated round trip on the push path; denying is safe and explainable |

## Consequences

- Pushes whose new commits do not reach the old tip inside the pushed pack (for example re-pushing an existing upstream commit to another branch) are denied under `force = false` with `git_force_push` and `not_provably_fast_forward` in `broker why` (Risk Register R19).
- Streaming responses on credentialed hosts are delayed by at most the hold-back window (under 200 bytes) per chunk.
- Services that need cookies, WebSockets or h2 on a terminated host do not work there; leave such hosts on L4 (no L7 keys) or mark them `passthrough`.

## Invariants affected

- [[I1 No Secrets in the Sandbox]], [[I7 Reject Foreign Credentials]]: upheld (strip, reject, filter).
- [[I6 Single Canonicaliser]]: `Host`, absolute-form authority, path, repository and SNI all compared as canonical values.
- [[I9 Hash-Chained Audit Outside the Sandbox]]: every L7 decision, including parser refusals, is appended before anything is forwarded.

## Relationships

- decided-by:: [[M1 Secrets Outside]]
- motivated-by:: [[TLS Termination and Per-Session CA]], [[Git Smart-HTTP Adapter]]
- supersedes::

## Build log

- 2026-09-24: created and built with M1. Tests listed in the [[M1 Secrets Outside]] build log.
