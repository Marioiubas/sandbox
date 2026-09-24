---
title: "Tech Stack"
aliases: ["Stack", "Packaging"]
type: concept
section: build
tags: [sandbox/build, concept, topic/build, topic/supply-chain, platform/macos, platform/linux, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Tech Stack

> Rust single static binary (tokio, hyper 1.x, rustls, rcgen; hudsucker as reference), cedar-policy in-process and cedar-policy-symcc with cvc5 in CI, bwrap plus landlock plus seccompiler plus nix, generated SBPL, SQLite WAL, OpenTelemetry/OCSF, axum plus Postgres control plane, and signed, notarised, SBOM-carrying packaging.

## Summary

The whole endpoint (CLI, daemon, launcher, proxy, policy compiler, learner) is one Rust workspace producing one static binary per platform. The choice follows from the attack surface: the proxy and its parsers sit on a hostile boundary, and enforcement-layer bugs are the dominant failure class in the incident record ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). The decision is recorded in [[ADR-015 Rust for the Endpoint and Custom Proxy]]; this note is the working bill of materials Claude Code builds against, laid out in [[Repository Layout]].

## Details

### The stack table (verbatim rows from the report; Proposal)

| Layer | Choice | Alternative considered | Reason |
|---|---|---|---|
| Endpoint language | Rust (single static binary: musl on Linux, universal2 on macOS) | Go (faster hiring; Leash, Agent Vault and Docker MCP Gateway use it) | Memory-safe parsers on a hostile boundary; no GC pauses; native Cedar. Peers in this space chose Rust: Codex `codex-rs`, OpenShell, Wassette ([Codex](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md); [OpenShell](https://github.com/NVIDIA/openshell)) |
| Proxy | tokio + hyper 1.x + rustls + rcgen; hudsucker as reference | Envoy with ext_authz; mitmproxy | Per-connection callouts, per-session CAs, pkt-line parsing |
| Policy | `cedar-policy` crate in-process; `cedar-policy-symcc` + cvc5 in CI | OPA/Rego; cedar-go | Verified semantics, analysis; cedar-go feature parity unverified |
| Linux sandbox | bubblewrap invocation + `landlock` crate + seccompiler/libseccomp + `nix` | hakoniwa library ([lib.rs](https://lib.rs/crates/hakoniwa)) | Matches the proven srt/Codex pipeline |
| macOS sandbox | Generated SBPL via `sandbox-exec`; VZ backend later | Network Extension or System Extension | Distribution friction; incumbents share the same dependency |
| Local state | SQLite (WAL) for audit ring, traces, token metadata; secrets in Keychain or libsecret | Embedded KV | Queryable, durable, simple |
| Telemetry | `opentelemetry` + OTLP; OCSF JSON | Vendor SDKs | SIEM neutrality |
| Control plane | axum + Postgres; TypeScript/React UI | Go server | Shared Cedar code |
| Supply chain | Developer ID signing, notarisation, Homebrew tap; nfpm deb/rpm; cosign; CycloneDX SBOM; SLSA provenance | n/a | Enterprise procurement |
| Testing | cargo-fuzz and proptest on canonicaliser, HTTP and pkt-line; public bypass corpus; agent × OS e2e matrix | n/a | Enforcement-layer bugs are the dominant failure class |

### Crate bill of materials

Versions are given only where the record gives them. Everything else is "not in the record" and must be pinned from crates.io at M0 and recorded here (see [[Open Questions and Unverified Claims]]).

| Concern | Crate / tool | Version in the record | Used by (crate in [[Repository Layout]]) | Status of evidence |
|---|---|---|---|---|
| Async runtime | `tokio` | not in the record | all networked crates | background |
| HTTP | `hyper` | 1.x | `netguard`, `l7`, `tls` | report states 1.x |
| TLS | `rustls` | not in the record | `tls`, upstream re-origination | background |
| Per-session CA and leaf certs | `rcgen` | not in the record | `tls` | background |
| MITM reference | `hudsucker` ([GitHub](https://github.com/omjadas/hudsucker)) | not in the record | reference only, not a dependency by default | crate existence verified |
| Policy engine | `cedar-policy` | not in the record | `policy` | background |
| Policy analysis | `cedar-policy-symcc` ([docs.rs](https://docs.rs/cedar-policy-symcc)) | not in the record; solver cvc5 1.3.1 located via the `CVC5` env var (research note 04a, from docs.rs) | `policy` (CI gates), `learn` | docs.rs |
| Landlock | `landlock` ([crates.io](https://crates.io/crates/landlock)) | ABI enum up to ABI 9 on Linux 7.1 ([rust-landlock](https://landlock.io/rust-landlock/landlock/enum.ABI.html)) | `launcher` (linux backend) | crate existence verified |
| seccomp | `seccompiler` or libseccomp bindings | not in the record | `launcher` | background |
| Namespaces, prctl | `nix` | not in the record | `launcher` | background |
| Local store | `rusqlite` (WAL) | not in the record | `audit`, `learn`, `brokerd` | background (research note 05) |
| Telemetry | `opentelemetry`, `opentelemetry-otlp` | not in the record | `audit` | background (research note 05) |
| CLI | `clap` | not in the record | `broker-cli` | background (research note 05) |
| Trait plumbing | `async-trait`, `anyhow`, `http` | not in the record | `launcher`, `l7`, `creds`, `audit` (as used by the trait sketches in [[Core Trait Contracts]]) | trait sketch, not compiled |
| Secret hygiene | `zeroize` (the `Zeroizing` type in the `CredentialIssuer` sketch) | not in the record | `creds` | **Proposal** inference from the sketch |
| Fuzzing and properties | `cargo-fuzz`, `proptest` | not in the record | `tests/fuzz`, every parser crate | report testing row |
| Control plane | `axum`, Postgres | not in the record | `ee/` | report |

A Jan 2026 guide shows seccomp plus Landlock sandboxing of Rust binaries without root ([OneUptime](https://oneuptime.com/blog/post/2026-01-07-rust-sandboxing-seccomp-landlock/view)), which is evidence the Linux layer can be built from these crates.

> [!question] Unverified
> Crate versions and maturity beyond `hudsucker` and `landlock` (hyper 1.x, rustls, rcgen, seccompiler, cedar-policy, cedar-policy-symcc, rusqlite, opentelemetry) were not verified in the record. Before M0 code depends on any of them, pin a version in `code/Cargo.toml`, record it in the table above, and tick the item in [[Open Questions and Unverified Claims]]. The record also contains no neutral benchmark of Envoy, mitmproxy and Rust or Go MITM proxies for this workload, and "faster" Rust proxy claims are self-reported.

### Why a custom Rust proxy (and its module boundaries)

**Proposal.** Write a custom Rust proxy (tokio, hyper 1.x, rustls, rcgen), using `hudsucker` as a reference ([GitHub](https://github.com/omjadas/hudsucker)). Envoy fits the static-config model poorly for per-connection policy callouts, dynamic per-session CAs, sentinel swapping and pkt-line parsing; mitmproxy is best kept for prototyping. SafeYolo is replacing its mitmproxy-based credential proxy with focused Rust, explicitly for simplicity rather than speed, and separates **route validation, credential selection, policy evaluation, inspection and injection** ([SafeYolo #620](https://github.com/craigbalding/safeyolo/issues/620)). Those five stages map onto the crates: route validation in `netguard` ([[Hostname Canonicaliser]], [[Broker DNS Resolver]]), inspection in `l7`, policy evaluation in `policy` ([[Policy Engine and Entity Builder]]), credential selection and injection in `creds` ([[Credential Injector and Issuers]]).

Anthropic's warning applies directly: "Be wary of custom components. Battle-tested hypervisors, syscall filters, and container runtimes have survived more adversarial attention than anything you'll build", and its own custom proxy repeatedly introduced vulnerabilities ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). The mitigation is in the testing row: fuzzing, property tests and the public corpus of [[L1 Conformance Suite]] from week one.

### Go as the rejected alternative

Leash is 66.5% Go, and Agent Vault and Docker MCP Gateway are Go (research note 05, citing their repositories). **Proposal (rejected alternative).** A Go build would use `net/http` with `goproxy` or `martian` for MITM and the gVisor `tcpip` netstack for transparent userspace TCP, but Cedar would need cedar-go, whose feature parity with the Rust crate is unverified.

### Platform sandbox mechanics the stack must drive

- **Linux.** Codex's Linux pipeline uses `--ro-bind / /`, writable roots, read-only re-binds of `.git`, gitdir and `.codex`, `--unshare-user --unshare-pid --unshare-net`, `PR_SET_NO_NEW_PRIVS` and seccomp, and in managed-proxy mode a TCP→UDS→TCP bridge after which seccomp blocks new `AF_UNIX` sockets ([codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)). Codex notes AppArmor configuration may be needed on Ubuntu 24.04+ for bubblewrap ([Codex docs](https://learn.chatgpt.com/codex/sandboxing)). See [[bubblewrap]], [[Landlock]], [[seccomp-bpf]].
- **macOS.** `sandbox-exec` is deprecated ("Consider adopting the App Sandbox instead") with no published removal date; a Linux-VM fallback raised start time from <5 ms to ~800 ms in one project's measurement ([apple/containerization#737](https://github.com/apple/containerization/issues/737)). See [[Seatbelt]] and [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]].

### Build, packaging and signing (Proposal)

The steps below come from research note 05 section 4 and the report's supply-chain row; exact tool invocations are to be decided at [[M4 Harden and Ship]].

1. **Targets.** `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` static binaries; a macOS universal2 binary (x86_64 plus arm64 merged).
2. **Reproducibility inputs.** `Cargo.lock` committed; `cargo build --release --locked` in CI; toolchain pinned in `rust-toolchain.toml`.
3. **macOS signing.** Sign with a Developer ID certificate and the hardened runtime, then notarise via `notarytool` in CI and staple the ticket.
4. **Homebrew.** A tap (`brew install broker/tap/broker`) whose formula points at the notarised artifact.
5. **Linux packages.** `.deb` and `.rpm` built with nfpm, plus a static tarball and an apt/yum repository. The installer must handle the Ubuntu AppArmor userns restriction ([[bubblewrap]]).
6. **Artifact signing and provenance.** cosign signatures on every artifact, SLSA provenance, and a CycloneDX SBOM.
7. **Updates.** Auto-update is opt-in; an MDM-friendly pkg (Jamf/Intune) is phase 2 ([[MVP Plan]]).
8. **CI verification.** cvc5 installed in the CI image for [[SymCC CI Gates]]; nightly `cargo fuzz` jobs; the agent × OS e2e matrix on macOS 15/26 and Ubuntu 22.04/24.04 runners.

### Local state and telemetry (Proposal)

SQLite holds the audit ring buffer, learned traces, token-cache metadata (never secrets) and the policy-bundle cache. Secrets live in the OS keychain (macOS Keychain, libsecret) or external managers. OTel traces are emitted per agent session (a span per request or decision), with OCSF JSON as the canonical SIEM format ([[Audit Recorder and Event Schema]]). The exact OCSF class IDs are unverified.

### Control plane (Proposal)

`ee/` holds an axum plus Postgres server and a TypeScript/React UI, sharing the Cedar code with the endpoint ([[Control Plane and Policy Bundles]]). It is out of scope for M0-M4 except the bundle format.

## Evidence

- Peers in this space chose Rust: Codex `codex-rs`, OpenShell and Wassette ([Codex](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md); [OpenShell](https://github.com/NVIDIA/openshell)).
- Cedar median authorization is 4.0-11.0 µs and 42.8-80.8x faster than Rego in its paper ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)).
- `hakoniwa` is a Rust sandbox library considered as an alternative to direct bwrap invocation ([lib.rs](https://lib.rs/crates/hakoniwa)).

## How it connects

- decided-by:: [[ADR-015 Rust for the Endpoint and Custom Proxy]]
- decided-by:: [[ADR-007 Cedar with a TOML Front-End]]
- decided-by:: [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]
- part-of:: [[Repository Layout]]
- depends-on:: [[Cedar]]
- depends-on:: [[Landlock]]
- depends-on:: [[seccomp-bpf]]
- depends-on:: [[bubblewrap]]
- depends-on:: [[Seatbelt]]
- depends-on:: [[SymCC CI Gates]]
- implements:: [[Audit Recorder and Event Schema]]
- implements:: [[Control Plane and Policy Bundles]]
- delivered-by:: [[M0 Contained Run]]
- delivered-by:: [[M4 Harden and Ship]]
- evaluated-by:: [[L1 Conformance Suite]]
- motivated-by:: [[Open Questions and Unverified Claims]]

## Implications for the build

- At M0, create `code/Cargo.toml` as a workspace, pin every crate version, and record the pins in this note's Build log; do not rely on any version not verified.
- Every parser crate (`netguard`, `l7`) gets a `proptest` suite and a `cargo-fuzz` target in the same PR that introduces the parser ([[L1 Conformance Suite]]).
- Keep `hudsucker` as a reference, not a dependency, unless an ADR records the choice; the five SafeYolo stages must remain separate modules.
- Packaging (notarisation, nfpm, cosign, SBOM, SLSA) is an M4 exit item; set up the CI skeleton for it at M0 so signing keys are never an afterthought.
- Never install the per-session CA into the host trust store; the trust bundle is written per session ([[TLS Termination and Per-Session CA]]).

## Open questions

- Which crate versions to pin, and whether `seccompiler` or libseccomp bindings are the better fit for the filter described in [[seccomp-bpf]].
- Whether `cedar-policy-symcc` supports every Cedar feature the schema uses, and how it scales ([[SymCC CI Gates]]).
- Whether direct bwrap invocation or `hakoniwa` gives a smaller trusted surface (decide by ADR if deviating).
- No neutral proxy benchmark exists; [[L4 Product Metrics]] must produce one.

## Sources

- Report: tech-stack table, "Implementation choice" paragraph, crate-verification caveat.
- Research note 05 section 4 (crate list, Go alternative, packaging, local state, observability, testing).
- Research note 03 Q4 (self-reported proxy performance claims).
