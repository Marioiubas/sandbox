---
title: "ADR-004 Selective TLS Termination with Per-Session CA"
aliases: ["ADR-004"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/tls, topic/egress, topic/credentials, control/egress, control/cred-out, boundary/tb3, boundary/tb4, invariant/i1, invariant/i6, invariant/i7, milestone/m1, evidence/conflict]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Terminate TLS only for hosts with credentials or L7 rules using a per-session CA; splice everything else at L4; rejecting MITM-everything and SNI-only."
related: ["[[TLS Termination and Per-Session CA]]", "[[Vercel Sandbox]]", "[[Docker Sandboxes]]", "[[Claude Code and sandbox-runtime]]", "[[Risk Register]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[Cloud Sandbox Runtimes]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[Sentinel Swap Pattern]]", "[[Sandbox Launcher]]", "[[Netguard Ingress]]", "[[Credential Injector and Issuers]]", "[[Policy Learning Loop]]", "[[L4 Product Metrics]]", "[[Conformance Probe Matrix]]", "[[I1 No Secrets in the Sandbox]]", "[[I6 Single Canonicaliser]]", "[[I7 Reject Foreign Credentials]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[ADR-003 Topology-Enforced Egress]]", "[[ADR-015 Rust for the Endpoint and Custom Proxy]]", "[[M1 Secrets Outside]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://vercel.com/docs/sandbox/concepts/firewall", "https://blog.cloudflare.com/sandbox-auth/", "https://docs.docker.com/ai/sandboxes/network-policies/", "https://github.com/anthropic-experimental/sandbox-runtime", "https://code.claude.com/docs/en/sandboxing", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://docs.e2b.dev/network/internet-access.md", "https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o"]
---

# ADR-004 Selective TLS Termination with Per-Session CA

> Terminate TLS only for hosts with credentials or L7 rules using a per-session CA; splice everything else at L4; rejecting MITM-everything and SNI-only.

## Status

**Proposed** (2026-09-24). Delivered in [[M1 Secrets Outside]] (per-session CA, trust-bundle env, selective termination). Not superseded. This ADR also records the resolution of the per-user versus per-session CA conflict flagged in [[TLS Termination and Per-Session CA]].

## Context

The broker needs to see the method, path and headers of a request for two reasons: to attach a credential, and to enforce verbs such as "open a PR but not merge it". Under TLS, a proxy sees only the SNI and the CONNECT host. So the product must decide where it decrypts.

**What the vendors do.**

- **Docker Sandboxes MITMs by default.** Its filtering proxy acts as a TLS MITM with its own CA trusted in the sandbox, with `--bypass-host` and `--bypass-cidr` as a raw-tunnel opt-out ([Docker docs](https://docs.docker.com/ai/sandboxes/network-policies/); [[Docker Sandboxes]]).
- **srt and Claude Code are SNI-only by default.** srt's README says filtering is domain-level only and that domain fronting may bypass it ([srt](https://github.com/anthropic-experimental/sandbox-runtime)). Claude Code's built-in proxy "by default, does not terminate or inspect TLS traffic"; its `mask` credentials need `network.tlsTerminate`, which is experimental and requires v2.1.199+ ([Claude Code docs](https://code.claude.com/docs/en/sandboxing); [[Claude Code and sandbox-runtime]]).
- **Vercel terminates selectively.** It SNI-matches ordinary allowed domains without termination and terminates only domains with `transform` or `forwardURL` rules, using a per-sandbox CA created just in time and disposed at stop ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall); [[Vercel Sandbox]]).
- **Cloudflare** gives each sandbox a unique ephemeral CA and key ([Cloudflare](https://blog.cloudflare.com/sandbox-auth/)).

**Why SNI alone is not enough.**

- SNI-only allowlists let a client reach other virtual hosts on shared CDNs (domain fronting) ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)).
- SNI-only filtering cannot see or strip an attacker-planted key sent to an allowed host. In the Cowork incident, an attacker key in a mounted file used the allowlisted api.anthropic.com to exfiltrate; the fix was a MITM proxy that "only passes requests carrying the VM's own provisioned session token" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude); [[Claude Cowork Allowed-Domain Abuse]]).

**Why terminating everything costs.**

- Clients that pin certificates break under interception.
- Every terminated connection costs CPU and a handshake. A netns plus MITM design with just-in-time certificates added about 14 ms per HTTPS request on an EC2 t3.medium ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)).
- The proposed budgets are added latency p50 ≤5 ms and p95 ≤25 ms on a warm connection, and p50 ≤15 ms on a new terminated connection ([[L4 Product Metrics]]).
- QUIC defeats domain filtering ([E2B docs](https://docs.e2b.dev/network/internet-access.md)).

> [!warning] Conflict
> The report's deployment-modes table places a "per-user CA key in the OS keychain" on laptops. Its L7 path and request lifecycle describe a per-session CA "created just in time and destroyed at session end". This ADR resolves the conflict below.

## Decision

**Proposal.** Every connection admitted by [[Netguard Ingress]] takes exactly one of three paths.

1. **L4 splice.** If the SNI is present, equals the canonical CONNECT host, and the host is allowed with no credential, method/path rule or protocol adapter, then splice the bytes without decrypting.
2. **L7 terminate.** If the host has a credential, a method/path rule, or a claiming adapter (git, GitHub API, private registries, LLM APIs, MCP over HTTP), terminate with a leaf minted from the **per-session CA**. Then:
   - require CONNECT target = SNI = `Host`/`:authority`;
   - parse, authorize with Cedar, and strip client credentials;
   - inject the minted credential;
   - re-originate TLS against public roots;
   - filter the response.
3. **Deny.** Deny SNI-less TLS, SSH, IP-literal CONNECT and QUIC/UDP 443 by default.

**CA lifecycle.**

- `tls` generates the CA with `rcgen` at `session.start` and keeps its private key only in `brokerd` memory.
- It writes the certificate into a merged bundle exposed through `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `PIP_CERT`, `CURL_CA_BUNDLE` and the npm `cafile` ([[Sandbox Launcher]]).
- It destroys (zeroises) the key and leaf cache at session end.
- It **never** installs the CA into the host system trust store.

**Conflict resolution (Proposal).** The sandbox trusts only the per-session CA. If a per-user key is kept in the OS keychain at all, it may only sign per-session CAs, and the sandbox never trusts it directly.

**Pinned clients** go on a documented passthrough list with **no** credential injection.

**Learning.** Learn mode terminates only the hosts that will need credentials, which gives the [[Policy Learning Loop]] L7 visibility where it matters.

Testable form:

- A probe to an allowed host with no L7 rule arrives at an echo server with the original client certificate chain.
- A probe to a credentialed host shows a leaf issued by the session CA.
- A CA extracted after session end validates nothing.
- The host trust store is byte-identical before and after `broker run`.
- Conformance categories 5 and 7 (QUIC, SSH, SNI≠Host) are 100% denied ([[Conformance Probe Matrix]]).

## Alternatives considered

| Alternative | Pros | Cons (evidence) | Why rejected |
|---|---|---|---|
| **MITM everything** (Docker default) | Uniform L7 policy and full visibility for audit and learning | Breaks pinned clients; CPU and latency on every connection (~14 ms reference); the whole HTTP parser surface is exposed to all traffic; more plaintext handled by the broker | Pinned clients and CPU favour L4 wherever no credential or verb rule applies |
| **SNI-only** (srt and Claude Code default) | No breakage; cheap; no CA to manage | Cannot inject credentials or enforce verbs; domain fronting ([srt](https://github.com/anthropic-experimental/sandbox-runtime)); cannot reject foreign credentials, the Cowork lesson | Credentials and verbs need L7 |
| **Long-lived per-user CA trusted by the sandbox** | One key; fewer certificate generations | A leaked CA stays valid across sessions; conflicts with the destroy-at-session-end lifecycle | Resolved above: per-session trust only |
| **Install the CA into the system store** | Broadest client compatibility | Every host process would trust the broker's CA | Forbidden by the handoff contract; env-var bundles only |

## Consequences

**Positive.**

- Credentials and verb rules work exactly where they are declared.
- Everything else keeps end-to-end TLS, including pinned clients.
- A leaked session CA is useless after the session.
- The L7 surface, the riskiest custom code, is exercised only by hosts that need it.

**Negative.**

- Two code paths must stay consistent. The path choice itself is security-relevant: a host wrongly classified as L4 silently loses verb enforcement. Mitigation: the path is a pure function of the compiled policy and is unit-tested per rule.
- Clients that ignore the CA env vars fail on L7 hosts. Go TLS on macOS needs `trustd`, which srt calls an exfiltration vector ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).
- Encrypted ClientHello would defeat the SNI peek; adoption is unmeasured ([[Risk Register]] R8).
- Pinned-passthrough hosts can never carry brokered credentials.

**Follow-up work.**

- Compatibility matrix: curl, git, npm, pip, cargo, Node, Python, Go and Java.
- Redirect re-evaluation, with credentials dropped on cross-origin hops.
- A response filter for injected secrets.
- A pinned-passthrough list kept in the org ceiling with a reason per entry.

## Revisit triggers

- ECH adoption makes SNI peeking unreliable for allowed hosts.
- Measured latency on reference machines misses the L4 budgets.
- A vendor-documented bypass of per-session trust bundles appears.
- A client class that matters (for example a major agent's own API client) starts pinning.

## Invariants and components affected

- **Upholds** [[I7 Reject Foreign Credentials]] (step 5 is only possible on the L7 path) and [[I1 No Secrets in the Sandbox]] (the CA key and upstream secrets stay in the broker; the response filter runs).
- **Upholds** [[I6 Single Canonicaliser]] (CONNECT = SNI = Host compares canonical values) and [[I9 Hash-Chained Audit Outside the Sandbox]] (every path choice is logged).
- **Weakens none.**
- Components: [[TLS Termination and Per-Session CA]], [[Netguard Ingress]], [[Sandbox Launcher]] (bundle env), [[Credential Injector and Issuers]].

## How it connects

- implements:: [[TLS Termination and Per-Session CA]]
- implements:: [[Sentinel Swap Pattern]]
- contrasts-with:: [[Docker Sandboxes]]
- contrasts-with:: [[Claude Code and sandbox-runtime]]
- motivated-by:: [[Vercel Sandbox]]
- motivated-by:: [[Cloud Sandbox Runtimes]]
- mitigates:: [[Claude Cowork Allowed-Domain Abuse]]
- depends-on:: [[ADR-003 Topology-Enforced Egress]]
- depends-on:: [[ADR-015 Rust for the Endpoint and Custom Proxy]]
- evaluated-by:: [[L4 Product Metrics]]
- evaluated-by:: [[Conformance Probe Matrix]]
- mitigates:: [[Risk Register]]
- delivered-by:: [[M1 Secrets Outside]]

## Implications for the build

- Build the path-choice function first, with a table test per `broker.toml` rule kind. It decides which hosts get L7 treatment ([[ADR-006 Deny Unmatched L7 Requests]]).
- Cache leaf certificates per host per session.
- Key the upstream connection pool by canonical host and credential ID, so pooled connections never cross sessions.
- Fuzz the ClientHello peek and the h1/h2 parsers from day one.

## Open questions

- ECH adoption, and vendor handling of QUIC, gRPC and WebSocket, are not in the record ([[Open Questions and Unverified Claims]]).
- X.509 name constraints on the session CA are not in the record; client support is untested.
- Response filtering of compressed or streamed bodies without unbounded buffering.

## Sources

- https://vercel.com/docs/sandbox/concepts/firewall
- https://blog.cloudflare.com/sandbox-auth/
- https://docs.docker.com/ai/sandboxes/network-policies/
- https://github.com/anthropic-experimental/sandbox-runtime
- https://code.claude.com/docs/en/sandboxing
- https://www.anthropic.com/engineering/how-we-contain-claude
- https://docs.e2b.dev/network/internet-access.md
- https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o
- Report: "L4 by default, L7 only where credentials or verbs matter", deployment modes, decision table row "TLS", risk "TLS breakage". Research note 03 Q3 and Q4, research note 01 Q5.
