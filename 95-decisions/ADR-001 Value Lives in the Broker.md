---
title: "ADR-001 Value Lives in the Broker"
aliases: ["ADR-001"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/market, topic/credentials, topic/policy, topic/learning, topic/isolation, invariant/i1, invariant/i2, invariant/i3, invariant/i9, evidence/secondary]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Put the product's value in the broker (policy, minting, semantics, audit, learning), not in a new isolation primitive, because isolation is mature and shipped by incumbents."
related: ["[[Product Thesis]]", "[[Gap Analysis]]", "[[Two-Tier Isolation Design]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[Just-in-Time Credential Minting]]", "[[Policy Learning Loop]]", "[[Risk Register]]", "[[Sandbox Launcher]]", "[[Native Config Exporters]]", "[[NVIDIA OpenShell]]", "[[Agent Identity Brokers]]", "[[Sentinel Swap Pattern]]", "[[Git Smart-HTTP Adapter]]", "[[GitHub API Adapter]]", "[[Audit Recorder and Event Schema]]", "[[SymCC CI Gates]]", "[[Conformance Probe Matrix]]", "[[I1 No Secrets in the Sandbox]]", "[[I2 Fail-Closed Launch]]", "[[I3 Probabilistic Components Only Narrow]]", "[[I8 No Flag Disables Isolation]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[The Attacker Moves Second]]", "[[ADR-005 Mint Credentials Per Task]]", "[[ADR-014 Apache-2.0 Endpoint with Commercial ee]]", "[[MOC Decisions]]", "[[Repository Layout]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://arxiv.org/html/2510.09023", "https://code.claude.com/docs/en/sandboxing", "https://docs.docker.com/ai/sandboxes/security/defaults/", "https://github.com/NVIDIA/openshell", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://bytecodealliance.org/articles/wasmtime-security-advisories", "https://github.com/anthropic-experimental/sandbox-runtime", "https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md", "https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/", "https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/", "https://arxiv.org/html/2503.18813", "https://arxiv.org/html/2505.23643", "https://github.com/advisories/GHSA-9gqj-5w7c-vx47", "https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/", "https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack", "https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/"]
---

# ADR-001 Value Lives in the Broker

> Put the product's value in the broker (policy, minting, semantics, audit, learning), not in a new isolation primitive, because isolation is mature and shipped by incumbents.

## Status

**Proposed** (2026-09-24). `status: proposal` until M2 ships the first broker-only differentiators (Cedar policy, minting, learning) on top of borrowed sandboxes. Not superseded.

## Context

A small team (2–3 engineers, 10-week MVP) has to choose where to spend its scarce engineering time. Five forces decide it.

1. **Isolation is a solved commodity.** The OS sandboxes the product needs already ship in production agents. srt uses Seatbelt on macOS and bubblewrap with the network namespace removed on Linux ([srt](https://github.com/anthropic-experimental/sandbox-runtime)); Codex's Linux pipeline uses `--ro-bind / /`, `--unshare-net`, `PR_SET_NO_NEW_PRIVS` and seccomp ([codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)). MicroVMs (Firecracker, Cloud Hypervisor, Apple Virtualization.framework) and gVisor cover the hard tier ([[Two-Tier Isolation Design]]). The report's verdict: "The isolation layer needs no new invention. It needs careful composition."
2. **Proxy-side secret injection is no longer a wedge.** By September 2026 eight products put a host-side proxy with a per-sandbox CA in front of the agent and inject secrets so they never enter the sandbox: Claude Code (v2.1.199+), Docker, Vercel, Cloudflare, E2B, Runloop, OpenShell and Agent Vault ([Claude Code docs](https://code.claude.com/docs/en/sandboxing); [Docker docs](https://docs.docker.com/ai/sandboxes/security/defaults/); [NVIDIA OpenShell](https://github.com/NVIDIA/openshell)). Research note 05 concludes a new entrant "has to win on neutrality, credential *minting*, identity, policy lifecycle and fleet operations".
3. **Custom enforcement code is where the bugs are.** Enforcement-layer bugs (empty-list semantics, prefix matching, NUL bytes, symlink fallback) appeared at least seven times in 13 months across four vendors ([GHSA](https://github.com/advisories/GHSA-9gqj-5w7c-vx47); [Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/); [Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)). Anthropic's lesson: "Be wary of custom components. Battle-tested hypervisors, syscall filters, and container runtimes have survived more adversarial attention than anything you'll build" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). Wasmtime shows the scrutiny new isolation code now attracts: 12 advisories in April 2026, two critical sandbox escapes, eleven found "using new LLM-based tools" ([Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-security-advisories)).
4. **Model-side defences do not hold, so authority must be managed outside the model.** Adaptive attacks broke in-band defences at 71–100% ([arXiv 2510.09023](https://arxiv.org/html/2510.09023); [[The Attacker Moves Second]]). CaMeL and FIDES rely on whatever ambient credentials the tool layer holds ([arXiv 2503.18813](https://arxiv.org/html/2503.18813); [arXiv 2505.23643](https://arxiv.org/html/2505.23643)): turning a decision into a narrow credential the model never sees is "the broker's reason to exist".
5. **Buyers ask for authority management, not another sandbox.** A CSA note reports 92% lack full visibility into AI identities and 86% do not enforce access policies for them, and recommends "time-bound, just-in-time credentials scoped to the specific resources their task requires" ([CSA Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/)). The six unowned capabilities are listed in [[Gap Analysis]].

## Decision

**Proposal.** The product's differentiating code lives in the broker; the isolation layer is borrowed and composed. Concretely:

- **Owned (broker crates):** one Cedar policy and one audit stream across agents; per-task credential *minting* ([[Just-in-Time Credential Minting]]); developer-protocol semantics ([[Git Smart-HTTP Adapter]], [[GitHub API Adapter]]); the record-then-restrict loop with SymCC-proved narrowing ([[Policy Learning Loop]], [[SymCC CI Gates]]); one OTel/OCSF audit schema ([[Audit Recorder and Event Schema]]); cross-agent exporters to native vendor configs ([[Native Config Exporters]]).
- **Borrowed (launcher backends):** Seatbelt via generated SBPL, bubblewrap, Landlock, seccomp, and later Virtualization.framework, Firecracker, Cloud Hypervisor and gVisor, each wrapped behind the `SandboxBackend` trait in [[Sandbox Launcher]] ([[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]).
- **Interoperate, not compete, on the sandbox.** Import and export OpenShell policy, or offer minting as an OpenShell provider ([[NVIDIA OpenShell]]).

Testable form:

1. No crate under `code/crates/` implements a hypervisor, VMM, kernel module, syscall-filter language or new namespace mechanism; `launcher` backends only invoke or configure existing primitives (review checklist item plus a dependency audit in CI).
2. Every M0–M3 feature listed in the owned bullet maps to a crate in `policy`, `creds`, `l7`, `audit`, `learn`, `grant` or `mcpguard` ([[Repository Layout]] is the reference tree).
3. The L1 conformance corpus runs unchanged against every backend, so a backend swap cannot silently change the security claim ([[Conformance Probe Matrix]]).

## Alternatives considered

| Alternative | Pros | Cons (evidence) | Why rejected |
|---|---|---|---|
| **Build a new isolation primitive** (custom VMM, novel kernel sandbox) | Full control of the stack; possible start-time or density edge | Incumbents already ship mature primitives; custom components "repeatedly introduced vulnerabilities" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)); LLM-assisted bug hunting now targets new isolation code ([Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-security-advisories)); consumes the whole 10-week budget | Isolation is mature and shipped by incumbents; the unowned gap is neutral authority management (report decision table) |
| **Compete on proxy-side secret injection** | Clear story; fast to build | Eight products ship it by September 2026 | Commoditised; not a wedge ([[Sentinel Swap Pattern]]) |
| **Identity or credential broker without an OS sandbox** (Keycard, Aembit model) | No OS work; credentials already task-scoped ([Keycard](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/)) | Without topology the agent can route around the broker; relies on vendor hooks whose stability is unknown ([[Risk Register]] R12) | The broker is only authoritative if it is the only way out; we borrow the sandbox rather than skip it ([[Agent Identity Brokers]]) |
| **Fight OpenShell head-on on the sandbox** | One product owns the full stack | OpenShell is Apache-2.0, per-binary L7, NVIDIA-backed ([OpenShell](https://github.com/NVIDIA/openshell)) | Differentiate on container-free laptop mode, minting, identity and learning instead |

## Consequences

**Positive.**

- Engineering time goes to the six unowned capabilities; the MVP milestones M1–M3 are almost entirely broker work.
- Vendor sandboxes and managed settings become defence in depth rather than competitors, through exporters.
- The product inherits the adversarial scrutiny already spent on Seatbelt, namespaces, seccomp and Landlock.

**Negative.**

- The product depends on primitives it does not control: `sandbox-exec` is deprecated with no removal date, and Ubuntu 24.04+ gates unprivileged user namespaces ([[Risk Register]] R6, R7).
- The broker itself becomes the attack surface and the credential honeypot (R3, R4). The proxy is exactly the custom component Anthropic warns about; the mitigation is discipline: a single canonicaliser, fuzzing, a public bypass corpus.
- Vendors can bundle the same features (R1). A proxy "prevents theft but not misuse" ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)), so the claim must stay honest ([[Product Thesis]]).

**Follow-up work.**

- Conformance corpus and `cargo-fuzz` targets from M0, for every parser.
- Exporters to Claude Code managed settings and Codex `requirements.toml` in M2.
- An OpenShell policy import/export spike after M2.

## Revisit triggers

- Apple removes `sandbox-exec` without a per-process replacement, and the VZ hedge cannot meet the start-time budget.
- A major agent vendor or OpenShell ships neutral, cross-agent minting plus verified policy learning.
- A platform the product must support (Windows is phase 3) has no borrowable primitive with a documented boundary.

## Invariants and components affected

- **Upholds** [[I1 No Secrets in the Sandbox]] (secrets live in the broker), [[I3 Probabilistic Components Only Narrow]] (value is deterministic enforcement, not a model), [[I9 Hash-Chained Audit Outside the Sandbox]] (audit is a broker asset).
- **Touches** [[I2 Fail-Closed Launch]] and [[I8 No Flag Disables Isolation]]: borrowed primitives must still be probed and fail closed.
- **Weakens none.**
- Components: [[Sandbox Launcher]] stays thin; the broker crates carry the product.

## How it connects

- motivated-by:: [[Product Thesis]]
- motivated-by:: [[Gap Analysis]]
- depends-on:: [[Two-Tier Isolation Design]]
- depends-on:: [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]
- implements:: [[Just-in-Time Credential Minting]]
- implements:: [[Policy Learning Loop]]
- contrasts-with:: [[Agent Identity Brokers]]
- competes-with:: [[NVIDIA OpenShell]]
- mitigates:: [[Risk Register]]
- part-of:: [[MOC Decisions]]

## Implications for the build

- Reject PRs that add isolation mechanisms rather than configure existing ones; route that work to a new ADR.
- Size milestones by broker capability: M1 minting and semantics, M2 policy, audit and learning, M3 identity and MCP ([[ADR-005 Mint Credentials Per Task]]).
- Keep `launcher` backends small and replaceable; `probe()` results go into every session's audit event.
- Licence the endpoint so security teams can audit the boundary ([[ADR-014 Apache-2.0 Endpoint with Commercial ee]]).

## Open questions

- Whether buyers will pay separately rather than accept vendor-bundled controls is indirect evidence only (M&A comparables, Aembit's $20/agent price point) ([[Gap Analysis]]).
- Whether agent vendors will expose stable egress hooks is unknown; the design wraps the process instead ([[Open Questions and Unverified Claims]]).
- "No neutral product parses git smart-HTTP" was not exhaustively verified.

## Sources

- https://arxiv.org/html/2510.09023
- https://code.claude.com/docs/en/sandboxing
- https://docs.docker.com/ai/sandboxes/security/defaults/
- https://github.com/NVIDIA/openshell
- https://www.anthropic.com/engineering/how-we-contain-claude
- https://bytecodealliance.org/articles/wasmtime-security-advisories
- https://github.com/anthropic-experimental/sandbox-runtime
- https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md
- https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/
- https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/
- https://arxiv.org/html/2503.18813
- https://arxiv.org/html/2505.23643
- https://github.com/advisories/GHSA-9gqj-5w7c-vx47
- https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/
- https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack
- https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/
- Report: introduction, "Isolation is a solved commodity", "The gap to own", decision table row "Where value lives", risk table. Research note 05 section 1 inferences and section 2.
