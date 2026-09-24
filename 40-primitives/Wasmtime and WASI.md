---
title: "Wasmtime and WASI"
aliases: ["WASI", "Wasmtime", "WebAssembly Components"]
type: "primitive"
section: "primitives"
summary: "Capability-import runtime (WASI 0.3 default in Wasmtime 46) with no ambient authority: right for purpose-built MCP tools and broker plugins with host-implemented wasi:http, not for shells, git or compilers; 12 advisories incl. 2 critical escapes in Apr 2026."
tags: [sandbox/primitives, primitive, topic/isolation, topic/mcp, topic/egress, platform/linux, platform/macos, control/iso, boundary/tb6, milestone/phase2, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
related: ["[[MCP Gateways]]", "[[Two-Tier Isolation Design]]", "[[MCP Guard]]", "[[Risk Register]]", "[[Tech Stack]]", "[[ADR-012 MCP Servers as Pinned Sandboxed Principals]]", "[[Open Questions and Unverified Claims]]"]
---

# Wasmtime and WASI

Wasmtime runs WebAssembly components whose only authority is what the host explicitly imports into them: a preopened directory, an outgoing-HTTP handler, an environment variable. WASI 0.3 (released 11 June 2026, on by default in Wasmtime 46) adds native async and a reorganised `wasi:http`. That capability model is the purest fit for the broker, but it only covers purpose-built tools, not shells, git, compilers or package managers, and Wasmtime's April 2026 batch of 12 advisories included two critical sandbox escapes.

## Boundary and trusted computing base

- **Mechanism.** A component has no ambient authority; every capability (files via preopened dirs, network via `wasi:http` handlers, clocks, env) is an import the host chooses to provide. Memory safety comes from Wasm's linear-memory bounds, enforced by the JIT-compiled code ([Bytecode Alliance: WASI 0.3](https://bytecodealliance.org/articles/WASI-0.3)).
- **TCB.** The Wasmtime runtime, its code generator (Cranelift or the Winch baseline compiler), and the host implementations of each import. The April 2026 escapes were in the code generators, which is exactly this TCB ([Bytecode Alliance advisories](https://bytecodealliance.org/articles/wasmtime-security-advisories)).
- **Start and overhead.** µs–ms (report primitive table).
- **Licence.** Believed Apache-2.0 with LLVM exception, **not re-verified** in the record ([[Open Questions and Unverified Claims]]).
- **Platforms.** All the broker targets.

## WASI 0.3 (what changed on 11 June 2026)

- Async is native to components, and "the runtime, not each component, [drives] the scheduling" ([Bytecode Alliance: WASI 0.3](https://bytecodealliance.org/articles/WASI-0.3)).
- `wasi:http` is reorganised into `wasi:http/service` and `wasi:http/middleware` worlds, enabling service chaining ([Bytecode Alliance: WASI 0.3](https://bytecodealliance.org/articles/WASI-0.3)).
- Wasmtime 45 supports the release candidate; **Wasmtime 46 ships 0.3.0 on by default**; jco has full support ([Bytecode Alliance: WASI 0.3](https://bytecodealliance.org/articles/WASI-0.3)).
- The launch post does not document socket or thread status for 0.3 ([[Open Questions and Unverified Claims]]).

## Security record

- **9 April 2026: 12 advisories**, two Critical (CVSS 9.0) sandbox escapes ([Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-security-advisories); [GHSA-xx5w-cvp6-jv83](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-xx5w-cvp6-jv83)):
  - CVE-2026-34987: memory access bug in the **Winch** backend.
  - CVE-2026-34971: **aarch64 Cranelift** heap-access miscompile.
- 11 of the 12 were found by the Wasmtime team "using new LLM-based tools", which is "triple the total number of advisories published in all of 2025" ([Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-security-advisories)).
- The lesson the report draws: expect the same LLM-assisted scrutiny of the broker's own proxy ([[Risk Register]]). Apple-silicon laptops are aarch64, so CVE-2026-34971 was directly relevant to the target fleet.

## What can realistically run in Wasm

| Workload | Fits standard WASI (P2/P3)? | Why |
|---|---|---|
| Purpose-built MCP tools (parsers, API clients, formatters) | **Yes** | each import is a capability; `wasi:http` can be host-implemented |
| User-written request filters inside the broker | **Yes** | a plugin engine with no ambient authority (research-note inference) |
| git, language toolchains, npm/pip/cargo with native build steps, shells, test runners | **No** | need fork/exec, full POSIX and native binaries |
| "Full userland" (dynamic linking, clang in the browser) | Only on **WASIX** | non-standard and single-vendor (Wasmer) ([Wasmer: WASIX dynamic linking](https://wasmer.io/posts/dynamic-linking-in-wasm-wasix); [Wasmer: clang in browser](https://wasmer.io/posts/clang-in-browser)) |

So a coding agent's shell stays in a process sandbox or VM, and Wasm hosts the tools beside the broker (research-note inference).

## Wassette: the MCP precedent

- Microsoft Wassette (MIT) is "a security-oriented runtime that runs WebAssembly Components via MCP" on Wasmtime, with "browser-grade isolation of tools"; components load from OCI references such as `oci://ghcr.io/microsoft/time-server-js:latest` ([microsoft/wassette](https://github.com/microsoft/wassette)).
- Capabilities are **deny-by-default**; a `policy.yaml` grants storage URIs, network hosts and env vars ([Wassette concepts](https://microsoft.github.io/wassette/latest/concepts.html); [Microsoft OSS blog](https://opensource.microsoft.com/blog/2025/08/06/introducing-wassette-webassembly-based-tools-for-ai-agents/)).
- v0.4.0 (4 Feb 2026) is marked "Early Development… not production ready" ([microsoft/wassette](https://github.com/microsoft/wassette)).
- The exact `policy.yaml` format was not captured from primary docs ([[Open Questions and Unverified Claims]]).
- Most MCP servers are Node or Python and need a process sandbox, not Wasm (report local-MCP row), which is why [[ADR-012 MCP Servers as Pinned Sandboxed Principals]] makes the process sandbox the default.

## How the broker would host a component

**Proposal.** The broker implements `wasi:http/outgoing-handler` itself. Every outbound request a component makes is then a function call into the broker, which runs the same pipeline as for sandboxed processes: canonicalise, authorize with Cedar, mint and attach the credential host-side, record. The component never sees the credential or a socket. Preopened directories come from the Cedar `fs.*` grants. This is the Wassette model with the broker as the host (research-note inference; the pattern is Wassette's, [microsoft/wassette](https://github.com/microsoft/wassette)).

## Verdict for the broker

**Proposal.**

- **Use it for:** first- and third-party MCP tools rebuilt as components; broker plugins (user-defined request filters); any tool where each import can be expressed as a capability.
- **Don't use it for:** shells, git, compilers, package managers, test runners; the sole boundary on aarch64 without tracking advisories closely; WASIX-dependent workloads.
- **How we integrate it.** Phase 2 or later (no milestone in the MVP plan names it). Embed the `wasmtime` crate in `brokerd`, pin a version at or above the April 2026 fixes, configure **Cranelift, not Winch**, enable only the WASI 0.3 interfaces needed, and implement `wasi:http` host-side through the existing L7 pipeline in [[MCP Guard]]. Track Bytecode Alliance advisories as a release gate ([[Tech Stack]]).

## How it connects

- part-of:: [[Two-Tier Isolation Design]] (hard-tier option for pure-logic MCP tools)
- decided-by:: [[ADR-012 MCP Servers as Pinned Sandboxed Principals]] (process sandbox first, Wasm optional)
- depends-on:: [[MCP Guard]] (host-implemented `wasi:http` goes through the guard)
- contrasts-with:: [[MCP Gateways]] (Wassette, Docker MCP Gateway, ToolHive)
- mitigated-by:: [[Risk Register]] (runtime escapes, LLM-found advisories)
- depends-on:: [[Tech Stack]] (wasmtime crate, Cranelift)

## Implications for the build

- Out of MVP scope; do not add a Wasm dependency to M0–M4 crates.
- When added, run the same conformance probes (credential exposure, egress) against a component as against a process, through the `wasi:http` path.
- Pin Wasmtime and add an advisory check to CI.

## Open questions

- Wasmtime licence, Extism and Spin status, Wassette policy format and WASI 0.3 socket/thread status are not in the record ([[Open Questions and Unverified Claims]]).

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
