---
title: "ADR-015 Rust for the Endpoint and Custom Proxy"
aliases: ["ADR-015"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/build, topic/egress, topic/tls, invariant/i6, invariant/i7, milestone/m0, milestone/m4]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Write the whole endpoint in Rust as one static binary and build a custom tokio/hyper/rustls/rcgen proxy (hudsucker as reference); reject Go and Envoy/mitmproxy for the product path."
related: ["[[Tech Stack]]", "[[TLS Termination and Per-Session CA]]", "[[Cedar]]", "[[NVIDIA OpenShell]]", "[[OpenAI Codex CLI]]", "[[Local Credential Proxies]]", "[[Risk Register]]", "[[Hostname Canonicaliser]]", "[[Netguard Ingress]]", "[[Git Smart-HTTP Adapter]]", "[[Credential Injector and Issuers]]", "[[Sentinel Swap Pattern]]", "[[Wasmtime and WASI]]", "[[I6 Single Canonicaliser]]", "[[I7 Reject Foreign Credentials]]", "[[I1 No Secrets in the Sandbox]]", "[[L4 Product Metrics]]", "[[M4 Harden and Ship]]", "[[Open Questions and Unverified Claims]]", "[[MOC Decisions]]"]
sources: ["https://www.anthropic.com/engineering/how-we-contain-claude", "https://github.com/advisories/GHSA-9gqj-5w7c-vx47", "https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/", "https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md", "https://github.com/NVIDIA/openshell", "https://thenewstack.io/wassette-microsofts-rust-powered-bridge-between-wasm-and-mcp/", "https://github.com/strongdm/leash", "https://github.com/Infisical/agent-vault", "https://github.com/docker/mcp-gateway", "https://github.com/omjadas/hudsucker", "https://crates.io/crates/landlock", "https://github.com/craigbalding/safeyolo/issues/620", "https://github.com/loocor/MitmRust", "https://www.memorysafety.org/blog/rustls-performance/", "https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o", "https://arxiv.org/html/2403.04651", "https://bytecodealliance.org/articles/wasmtime-security-advisories"]
superseded_by:
---

# ADR-015 Rust for the Endpoint and Custom Proxy

> Write the whole endpoint in Rust as one static binary and build a custom tokio/hyper/rustls/rcgen proxy (hudsucker as reference); reject Go and Envoy/mitmproxy for the product path.

## Status

Proposed (2026-09-24). Takes effect with the M0 workspace skeleton. The proxy's hardening exit is [[M4 Harden and Ship]]: at least 24 hours of fuzzing per target with no crashes, and an external pentest with no open high findings.

## Context

**The proxy is the attack surface.** Enforcement-layer bugs appeared at least seven times in 13 months across four vendors: empty-list semantics, prefix matching, NUL bytes, symlink fallback and `working_directory` ([GHSA](https://github.com/advisories/GHSA-9gqj-5w7c-vx47); report incident section). In the sandbox-runtime NUL-byte bypass, a JavaScript suffix check and libc resolution disagreed about the same hostname ([Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)). Anthropic's own lesson: "Be wary of custom components. Battle-tested hypervisors, syscall filters, and container runtimes have survived more adversarial attention than anything you'll build", and its custom proxy repeatedly introduced vulnerabilities ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). Eleven of Wasmtime's twelve April 2026 advisories were found "using new LLM-based tools" ([Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-security-advisories)), so the broker's proxy should expect the same scrutiny.

**What the proxy must do** is unusual for off-the-shelf proxies ([[TLS Termination and Per-Session CA]]; [[Sentinel Swap Pattern]]):

- make a policy callout per connection and per request;
- create a CA per session just in time and destroy it at session end;
- swap sentinels in headers and bodies, and re-sign AWS SigV4;
- parse git pkt-lines ([[Git Smart-HTTP Adapter]]) and MCP JSON-RPC;
- evaluate Cedar in-process at 4.0–11.0 µs median ([arXiv 2403.04651](https://arxiv.org/html/2403.04651); [[Cedar]]).

**Peers split between Rust and Go.**

- Rust: Codex's sandbox lives in `codex-rs` ([Codex](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md); [[OpenAI Codex CLI]]); OpenShell is primarily Rust ([GitHub](https://github.com/NVIDIA/openshell); [[NVIDIA OpenShell]]); Wassette is described as "Rust-powered" ([The New Stack](https://thenewstack.io/wassette-microsofts-rust-powered-bridge-between-wasm-and-mcp/)).
- Go: Leash is 66.5% Go ([GitHub](https://github.com/strongdm/leash)); Agent Vault is Go ([GitHub](https://github.com/Infisical/agent-vault)); Docker MCP Gateway is Go ([GitHub](https://github.com/docker/mcp-gateway)).

**Rust building blocks exist.** `hudsucker` is an intercepting HTTP/S proxy crate ([GitHub](https://github.com/omjadas/hudsucker)), and the `landlock` crate is published ([crates.io](https://crates.io/crates/landlock)). SafeYolo is replacing its mitmproxy-based credential proxy with focused Rust, explicitly for simplicity rather than speed. It separates route validation, credential selection, policy evaluation, inspection and injection ([SafeYolo #620](https://github.com/craigbalding/safeyolo/issues/620); [[Local Credential Proxies]]). Rustls has been reported at or above OpenSSL and BoringSSL handshake and throughput performance ([Prossimo](https://www.memorysafety.org/blog/rustls-performance/)). Community Rust MITM proxies claim to be "10x faster than mitmproxy", but those figures are self-reported ([MitmRust](https://github.com/loocor/MitmRust)).

**Cost reference.** A netns, iptables and MITM design with just-in-time certificates added about 14 ms per HTTPS request on an EC2 t3.medium ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)). The proposed thresholds are p50 ≤5 ms and p95 ≤25 ms on a warm connection, and p50 ≤15 ms for a new terminated connection ([[L4 Product Metrics]]). **The record contains no neutral benchmark of Envoy, mitmproxy and Rust or Go MITM proxies for this workload.**

## Decision

**Proposal.**

1. **One language, one binary.** The CLI, daemon, launcher, proxy, credential issuers, policy compiler, exporters, audit and learn crates are Rust in one Cargo workspace. They ship as one static binary: musl on Linux, universal2 on macOS ([[Tech Stack]]).
2. **Custom proxy on tokio + hyper 1.x + rustls + rcgen.** Use `hudsucker` as a reference design, and adopt it as a dependency only if its code passes the same review and fuzzing bar. TLS goes through rustls on both legs; leaf certificates are minted from the per-session CA with rcgen.
3. **Cedar in-process** through the `cedar-policy` crate, with no FFI. `cedar-policy-symcc` plus cvc5 runs in CI.
4. **The module split copies SafeYolo:** ingress and canonicalisation (netguard), TLS, L7 parsing and adapters, policy evaluation, credential selection and injection, then response filtering. Each is a separate crate with narrow interfaces ([[Netguard Ingress]], [[Hostname Canonicaliser]], [[Credential Injector and Issuers]]).
5. **Every parser gets proptest and a `cargo-fuzz` target** from its first commit: hostname, URL, HTTP/1.1, h2, pkt-line and JSON-RPC. Secrets live in `Zeroizing` buffers inside broker memory only.
6. **Envoy and mitmproxy are off the product path.** mitmproxy remains allowed for prototyping and as a differential-testing oracle. Envoy remains a candidate only for a phase 2 Kubernetes L4/SNI tier.
7. **The control plane** in `ee/` uses Rust (axum) with Postgres, sharing the Cedar code; its UI is TypeScript/React.

**Testable as:** CI builds a static binary for both targets; a fuzz target exists for every parser listed; the L4 latency thresholds are measured on reference laptops; M4's 24-hour fuzzing run passes.

## Alternatives considered

| Alternative | Pros | Cons | Why rejected |
|---|---|---|---|
| **Go** (`net/http` with `goproxy` or `martian`; gVisor netstack for transparent TCP) | Faster to hire and ship; Leash, Agent Vault and Docker MCP Gateway prove it | Cedar would need the Go port (`cedar-go`, whose parity is unverified) or Wasm/FFI; GC pauses in the proxy path | Loses native verified Cedar; memory-safety parity but weaker fit for the shared policy engine |
| **Envoy with ext_authz or ext_proc** | Battle-tested data plane; aligns with "prefer battle-tested components" | Static-config model fits poorly with per-connection callouts, per-session CAs, sentinel swapping and pkt-line parsing without heavy ext_authz/ext_proc or Wasm filters; a second runtime to ship | The custom logic would live in filters anyway; kept as a possible Kubernetes L4 tier |
| **mitmproxy** | Fastest to prototype; good for record mode | Python runtime on the endpoint; SafeYolo is moving off it for simplicity | Prototyping and test oracle only |
| **TypeScript like srt** | Same stack as the reference sandbox | srt's NUL-byte bypass came from a JavaScript check disagreeing with libc resolution | Not listed as an alternative in the record's tech-stack table; noted for completeness |

## Consequences

- **Easier:** memory-safe parsers on a hostile boundary; no GC pauses; one policy engine shared by endpoint, CI gates and control plane; one artifact to sign, notarise and ship.
- **Harder:** hiring is slower than Go, and custom L7 code is exactly what Anthropic warns about. The mitigations are the single canonicaliser, fuzzing, the public corpus, external pentests, a bounty and a minimal L7 surface ([[Risk Register]], row "The broker's own bugs").
- **Not solved by language choice:** the NUL-byte bypass was a parser differential, not a memory-safety bug. Rust prevents one class. The canonicaliser and differential fuzzing prevent the other ([[I6 Single Canonicaliser]]).
- **Unverified dependencies:** crate versions and maturity beyond `hudsucker` and `landlock` (hyper 1.x, rustls, rcgen, seccompiler, cedar-policy-symcc, rusqlite, opentelemetry) were not verified in the record.

## Revisit triggers

- Measured proxy latency misses the L4 thresholds and profiling points at the stack rather than at the design.
- A critical dependency proves immature or unmaintained.
- `cedar-go` reaches verified feature parity and hiring becomes the binding constraint.
- An OpenShell proxy component becomes reusable under Apache-2.0, making interoperation cheaper than a parallel implementation.
- A neutral benchmark of Envoy, mitmproxy and Rust or Go proxies for agent egress is published.

## Invariants and components affected

- **Upholds [[I6 Single Canonicaliser]]:** one canonicaliser crate feeds every ingress.
- **Upholds [[I7 Reject Foreign Credentials]]:** stripping and rejection happen in the owned L7 path.
- **Upholds [[I1 No Secrets in the Sandbox]]:** secrets are held in zeroized broker memory and never serialised to the sandbox.
- **Weakens nothing.**
- Components: [[Tech Stack]], [[TLS Termination and Per-Session CA]], [[Netguard Ingress]], [[Hostname Canonicaliser]], [[Git Smart-HTTP Adapter]], [[Credential Injector and Issuers]].

## How it connects

- depends-on:: [[Tech Stack]]
- depends-on:: [[TLS Termination and Per-Session CA]]
- depends-on:: [[Cedar]]
- depends-on:: [[Hostname Canonicaliser]]
- motivated-by:: [[OpenAI Codex CLI]] (codex-rs)
- motivated-by:: [[NVIDIA OpenShell]] (Rust)
- motivated-by:: [[Local Credential Proxies]] (SafeYolo module split; Go alternative)
- contrasts-with:: [[Local Credential Proxies]] (Go implementations)
- mitigates:: [[Risk Register]] (row "The broker's own bugs")
- implements:: [[I6 Single Canonicaliser]]
- evaluated-by:: [[L4 Product Metrics]]
- delivered-by:: [[M4 Harden and Ship]] (hardening exit)
- part-of:: [[MOC Decisions]]

## Implications for the build

- Pin the crate set in M0 and record each crate's version and maintenance status in [[Tech Stack]] before code depends on it.
- Stand up `cargo-fuzz` in CI with the first parser, and add an HTTP Garden-style differential harness against curl, requests/httpx and undici once the HTTP path exists.
- Deny `unsafe` in the proxy crates except where a reviewed dependency requires it.
- Benchmark the warm and new-connection paths on reference laptops in M1, before selective termination is widely used.

## Open questions

- Adopt `hudsucker` as a dependency, or reimplement using it as a reference? Decide after code review.
- Which DNS resolver and message-parser crates? Not selected in the record.
- What is the cost of h2 support in the custom stack versus forcing HTTP/1.1 where clients allow it? The dev.to design forced HTTP/1.1.
- Crate maturity remains an open item ([[Open Questions and Unverified Claims]]).

## Sources

- [Anthropic: how we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude)
- [GHSA-9gqj-5w7c-vx47](https://github.com/advisories/GHSA-9gqj-5w7c-vx47)
- [Aonan Guan: NUL-byte allowlist bypass](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)
- [Codex linux-sandbox README](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md)
- [NVIDIA/OpenShell](https://github.com/NVIDIA/openshell)
- [The New Stack: Wassette](https://thenewstack.io/wassette-microsofts-rust-powered-bridge-between-wasm-and-mcp/)
- [strongdm/leash](https://github.com/strongdm/leash)
- [Infisical/agent-vault](https://github.com/Infisical/agent-vault)
- [docker/mcp-gateway](https://github.com/docker/mcp-gateway)
- [omjadas/hudsucker](https://github.com/omjadas/hudsucker)
- [landlock crate](https://crates.io/crates/landlock)
- [SafeYolo #620](https://github.com/craigbalding/safeyolo/issues/620)
- [MitmRust](https://github.com/loocor/MitmRust)
- [Prossimo: rustls performance](https://www.memorysafety.org/blog/rustls-performance/)
- [dev.to: kernel-level egress control](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)
- [Cedar, arXiv 2403.04651](https://arxiv.org/html/2403.04651)
- [Bytecode Alliance: Wasmtime security advisories](https://bytecodealliance.org/articles/wasmtime-security-advisories)
- Report: tech-stack rows "Endpoint language" and "Proxy" and the "Implementation choice" paragraph; research notes 03 Q4 and 05 section 4.
