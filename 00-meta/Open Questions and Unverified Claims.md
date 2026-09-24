---
title: "Open Questions and Unverified Claims"
aliases: ["Unverified Claims", "Gaps"]
type: meta
section: meta
tags: [sandbox/meta, meta, evidence/unverified]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Every gap, source conflict and unverified claim from the report and research notes, each linked to the note that must carry the caveat."
related: ["[[Landlock]]", "[[Filesystem Control and Rollback]]", "[[Audit Recorder and Event Schema]]", "[[EchoLeak M365 Copilot Exfiltration]]", "[[sandbox-runtime SOCKS NUL-Byte Bypass]]", "[[Mythos Preview Evaluation Escape]]", "[[Broker Cedar Schema]]", "[[Tech Stack]]", "[[Netguard Ingress]]", "[[Measurement Gaps]]", "[[Macaroons and Biscuit]]", "[[July 2026 Artifactory Egress Incident]]"]
sources: []
---

# Open Questions and Unverified Claims

Everything the research record flags as unverified, single-source, conflicting or missing. **Writers:** put the caveat in the linked note (callout `> [!question] Unverified` or `> [!warning] Conflict`) and tag it. **Claude Code:** before code depends on any item marked ⚙ (build-blocking), verify it from primary docs or by measurement, record the evidence in the linked note, and tick the box here with the date.

Legend: ⚙ build-relevant (verify before relying on it) · ⚠ sources conflict · ◌ single or secondary source · ∅ missing from the record.

Source keys: **R** = the report; **N01-N05** = research notes (01 isolation, 02 paper audit, 03 identity/egress, 04a evaluation, 04b incidents, 05 landscape/architecture); **SB** = scoreboard.

## Build-blocking technical unknowns

- [ ] ⚙ Landlock ABI 10 (UDP) and ABI 11 are documented on kernel.org but the UDP series was still at v5 in June 2026; assume neither is in a released stable kernel; probe the ABI at runtime. → [[Landlock]] (R, N01 Q3) — 2026-09-24: the runtime probe is built; measured ABI 6 on Linux 6.12 (Docker Desktop), ABI 4 on GitHub's Ubuntu 22.04 runner and ABI 7 on its Ubuntu 24.04 runner. ABI 10/11 still unverified; nothing depends on them ([[ADR-017 Landlock Filesystem Layer Required]]).
- [ ] ⚙ Kernel version that enables unprivileged overlayfs inside a user namespace (believed ≥5.11, background knowledge) and APFS `clonefile` behaviour for the macOS clone mode. → [[Filesystem Control and Rollback]] (R, N01 Q6)
- [ ] ⚙ Cedar `datetime`/`duration` availability across SDKs; the schema models time as epoch seconds until verified. The schema sketch has **not been compiled**. → [[Broker Cedar Schema]] (R, N03 Q5) — 2026-09-24 (M2): the Rust SDK `cedar-policy` 4.13.0 enables `datetime` by default (verified in its Cargo features); SymCC support and other SDKs remain unverified, so the schema keeps epoch seconds ([[ADR-022 Cedar Schema and Engine as Built]]).
- [ ] ⚙ Exact OCSF class names and IDs (e.g. HTTP Activity 4002, API Activity 6003 are unverified) and the current OpenTelemetry GenAI/agent semantic conventions. → [[Audit Recorder and Event Schema]] (R, N03 Q5, N05 section 3) — 2026-09-24 (M2): OCSF part resolved from schema.ocsf.io 1.9.0: Network Activity 4001, HTTP Activity 4002 (category 4), API Activity 6003 (category 6) ([[ADR-023 OCSF and OTLP Export as Built]]). OTel GenAI/agent conventions still unverified and not used.
- [ ] ⚙ Crate versions and maturity beyond `hudsucker` and `landlock` (hyper 1.x, rustls, rcgen, seccompiler, cedar-policy, cedar-policy-symcc, rusqlite, opentelemetry). → [[Tech Stack]] (R, N05 section 4) — 2026-09-24: M0 crates pinned and exercised (seccompiler 0.5.0, rusqlite 0.40.2 and others in the [[Tech Stack]] build log); hyper, rustls, rcgen, cedar-policy, cedar-policy-symcc and opentelemetry remain to be pinned when M1/M2 first use them. — 2026-09-24 (M1): hyper 1.11.1, rustls 0.23, rcgen 0.14 pinned and exercised end to end (conformance suite, e2e with Claude Code); hyper's `max_buf_size` found not to bound request heads on a TLS stream (explicit limit added). cedar-policy, cedar-policy-symcc and opentelemetry remain for M2/M3.
- [ ] ⚙ cedar-go feature parity with the Rust `cedar-policy` crate (only matters if Go is reconsidered). → [[ADR-007 Cedar with a TOML Front-End]] (R, N05 section 4)
- [ ] ⚙ SymCC: unsupported Cedar features and scalability limits are not documented on docs.rs; no peer-reviewed SymCC paper located; unclear whether the analysis CLI is Lean-verified end to end. → [[SymCC CI Gates]] (N04a Q5, N02 Q4) — 2026-09-24 (M2): cedar-policy-symcc 0.7.0 with cvc5 1.3.1 compiled and solved every feature the Broker schema uses (`like`, `containsAny`, optional record attributes with `has`, hierarchy `in`, Long arithmetic) with no unsupported-feature error; 24 environments and 155-250 queries take 0.1-0.2 s per shipped profile. Scaling to large policies and Lean coverage of the CLI remain open ([[ADR-024 Formal Gates as Built]]).
- [ ] ⚙ Transparent interception on macOS without a Network Extension is unvalidated; clients that ignore proxy variables simply fail (fail-closed, acceptable for MVP). → [[Netguard Ingress]], [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]] (R, N05 section 3) — 2026-09-24: confirmed fail-closed on macOS 26.5: a direct socket from the sandbox gets EPERM and is also refused by the shim's pre-exec verification.
- [ ] ⚙ Encrypted ClientHello adoption in 2026 and its effect on SNI peeking; how vendors handle QUIC/HTTP3, gRPC and WebSocket. → [[TLS Termination and Per-Session CA]], [[Risk Register]] (R, N01 Q5, N03 Q4) — 2026-09-24 (M1): still unmeasured; QUIC stays blocked (no UDP route), WebSocket upgrades are refused on terminated hosts and h2 is not offered ([[ADR-021 L7 Path Choices for M1]]).
- [ ] ⚙ No neutral benchmark of Envoy vs mitmproxy vs a Rust or Go MITM proxy for this workload; "10x faster" Rust proxy claims are self-reported. → [[ADR-015 Rust for the Endpoint and Custom Proxy]] (R, N03 Q4, N05 section 4)
- [ ] ⚙ GitHub: whether any branch-scoped installation-token capability was added in 2026 (none found). → [[GitHub App Installation Tokens]] (N03 Q1) — 2026-09-24 (M1): none used or found; branch scope is enforced by the broker's git adapter, tested against a fake GitHub. A real throwaway GitHub App run is pending.
- [ ] ⚙ Codex CLI: exact Seatbelt base policy, Windows sandbox mechanism, local network policy and any 2026 credential-injection feature were not retrieved. → [[OpenAI Codex CLI]] (N01 Q3, N03 Q3)
- [ ] ⚙ sandbox-runtime README returned 404 in one session, so its TLS-termination and sentinel-swap claims rest on a secondary blog; Claude Code's docs independently document `mask`. → [[Sentinel Swap Pattern]], [[Claude Code and sandbox-runtime]] (N03 Q3, N05 section 1) — 2026-09-24 (M1): this broker's own sentinel swap is implemented and tested independently of that claim (`creds::sentinel`, B5).
- [ ] ⚙ Whether Claude Code and Cursor hook APIs expose enough task context to bind credentials to a task (as Keycard claims), and whether agent vendors will expose stable egress hooks at all; the design wraps the process instead. → [[Agent Identity Brokers]], [[Risk Register]] (N05 sections 3 and 5)
- [ ] ⚙ Vault, 1Password and Infisical dynamic-secret engines (TTL leases) are background knowledge only. → [[Credential Injector and Issuers]] (N03 Q3)
- [ ] ⚙ SPIFFE/SPIRE (X.509-SVID, JWT-SVID, attestation) treated as background, not cited. → [[DPoP and mTLS-Bound Tokens]] (N03 Q1)
- [ ] ⚙ The bubblewrap licence (believed LGPL-2.0+) and the Wasmtime licence (believed Apache-2.0 with LLVM exception). → [[bubblewrap]], [[Wasmtime and WASI]] (N01 Q7)
- [ ] ⚙ Terminal-Bench 2.0 task count (~89, unverified) and the "4.0.0" version string on the docs page; how SWE-bench and Terminal-Bench set container networking during rollout needs code inspection. → [[L3 Real-Work Utility]] (N04a Q2)
- [ ] ⚙ Exact AgentDojo pipeline/defense hook API names not re-verified. → [[L2 Injection Benchmarks]] (N04a Q1)
- [ ] ⚙ HTTP Garden repository URL and gateway coverage (Squid, Envoy...) not verified. → [[L1 Conformance Suite]] (N04a Q4)

## Source conflicts

- [ ] ⚠ EchoLeak disclosure date: 11-12 June 2025 (most sources) vs 24 July 2025 (Hack The Box); CVSS 9.3 not verified against the MSRC advisory; CSP-bypass chain details not fetched beyond summaries. → [[EchoLeak M365 Copilot Exfiltration]] (R, N04b Q1, N02 Q3)
- [ ] ⚠ NUL-byte bypass fix date: 27 March 2026 (Penligent) vs 1 April 2026 (researcher); affected range 2.0.24-2.1.89 is the researcher's claim. → [[sandbox-runtime SOCKS NUL-Byte Bypass]] (R, N04b Q1, N05 section 1)
- [ ] ⚠ Mythos Preview escape: the system card says the escape was requested and the public posting was not; some press reported the escape itself as unprompted. → [[Mythos Preview Evaluation Escape]] (R, N04b Q1)
- [ ] ⚠ Biscuit timing: the report's internal-grant section defers Biscuit "to phase 2", while its later-phases paragraph puts Biscuit-based sub-agent delegation in phase 3. → [[Macaroons and Biscuit]], [[ADR-008 Grant Representation as Entities and Txn-Token JWT]], [[MVP Plan]] (R)
- [ ] ⚠ M4 latency targets: report L4 says warm-connection added latency p50 ≤5 ms / p95 ≤25 ms and new terminated connection p50 ≤15 ms; research note 05 phrases M4 as p50 ≤5 ms non-terminated and ≤15 ms terminated on a laptop. Use the report's L4 table. → [[M4 Harden and Ship]], [[L4 Product Metrics]] (R, N05 section 5.2)
- [ ] ⚠ CaMeL utility: 77% vs 84% undefended on AgentDojo (authors), 37.71% benign utility in DRIFT's GPT-4o-mini comparison, zero on AgentDyn open-ended tasks. Numbers are model- and benchmark-specific. → [[CaMeL]] (R, N02 Q2 and Q6)
- [ ] ⚠ Progent on ASB: 3.9% ASR (Progent paper) vs 15.8% (DRIFT's comparison). → [[Progent]] (R, N02 Q6)
- [ ] ⚠ Rule of Two vs lethal trifecta: Meta calls [A]+[C] "lower risk"; Willison and the design-patterns paper say it is still dangerous. → [[Agents Rule of Two]] (N02 Q6)
- [ ] ⚠ FlowSeal date: the fetched page showed 12 Sep 2024, conflicting with arXiv ID 2609 (Sep 2026); treat as Sep 2026, unverified. → [[Information Flow Control]] (N02 Q2)
- [ ] ⚠ Codex CLI CVE-2025-61260 fixed version: GHSA metadata lists affected ≤0.23.0 with "no patched versions", which may conflict with the vendor fix. → [[Codex CLI Project Config Autoload]] (N04b Q1)
- [ ] ⚠ Replit counts: AIID's ~4,000 "users" are fabricated records, not deletions; Fortune reports 1,200+ executives and 1,190+ companies. → [[Replit Production Database Deletion]] (N04b Q1)

## Single-source or secondary claims

- [ ] ◌ Amazon Q "wiper" payload intent appears only in secondary reporting (SC Media, PointGuard); AWS advisories do not describe it. → [[Amazon Q Extension Compromise]] (R, N04b Q1)
- [ ] ◌ July 2026 Hugging Face / "ExploitGym" incident: only verified path was a JFrog Artifactory zero-day chain; DNS-tunnelling details unconfirmed; no primary disclosure found. → [[July 2026 Artifactory Egress Incident]] (R, N01 Q5)
- [ ] ◌ Cursor DuneSlide CVE numbers and dates from The Hacker News only; vendor advisory not fetched. → [[Cursor DuneSlide Sandbox Escape]] (N04b Q1)
- [ ] ◌ OpenClaw CVE-2026-25253 details via the Adversa aggregator; GHSA not fetched; other OpenClaw CVEs (CVE-2026-24763, CVE-2026-25157, CVE-2026-22708) unverified. → [[OpenClaw Exposure and Token Theft]] (N04b Q1)
- [ ] ◌ ClawHavoc numbers via The Hacker News (Koi's post now redirects); no primary source for an in-the-wild malicious Claude Code skill. → [[ClawHavoc Malicious Skills]] (N04b Q1)
- [ ] ◌ Secondary performance figures: Cloud Hypervisor boot (~<200 ms), gVisor start (~50 ms), Firecracker snapshot restore (~28 ms), per-VM memory on Apple silicon; no same-hardware 2026 benchmark of all primitives; Firecracker NSDI numbers not re-verified. → [[Cloud Hypervisor]], [[gVisor]], [[Firecracker]], [[Apple Virtualization Framework]], [[Two-Tier Isolation Design]] (R, N01 Q1 and Q7)
- [ ] ◌ Anthropic's "84% fewer permission prompts" has no published methodology (population, baseline, window). → [[L4 Product Metrics]], [[Evaluation Harness]] (R, N04a Q3)
- [ ] ◌ Git smart-HTTP scoping: "no neutral product does this" was not exhaustively verified. → [[Git Smart-HTTP Adapter]], [[Gap Analysis]] (R, N05 section 1)
- [ ] ◌ Unverified news of an AISI evaluation-containment incident (CSA note) and claims that an open-weight model escaped an AISI sandbox in Aug 2026. → [[SandboxEscapeBench]] (N04a Q1)
- [ ] ◌ ToolHive CVE-2026-58197 listed but not reviewed; Pomerium's competitor comparison is self-interested. → [[MCP Gateways]] (N05 section 1)
- [ ] ◌ Market sizing ($1.65B vs $18.7B) and several deal figures rest on single industry sources; the scoreboard excludes some claims entirely. → [[Product Thesis]] (SB)

## Missing from the record

- [ ] ∅ Docker Sandboxes does not document its hypervisor per OS or its start times; Docker sbx and MCP Gateway enterprise pricing and interceptor semantics unknown. → [[Docker Sandboxes]], [[MCP Gateways]] (N01 Q1, N05 section 1)
- [ ] ∅ QEMU `microvm` and krunvm boot and memory figures; Apple Virtualization.framework per-VM memory overhead; realistic coding-agent VM density per laptop. → [[Cloud Hypervisor]], [[Apple Virtualization Framework]], [[Two-Tier Isolation Design]] (N01 Q1 and Q7)
- [ ] ∅ No gVisor Sentry escape CVE found for 2023-2026 (may be indexing, not absence); no 2026 Systrap per-syscall latency; no crun or rootless Podman advisory review. → [[gVisor]], [[Container Runtimes and Escape History]] (N01 Q2)
- [ ] ∅ Apple has made no statement on `sandbox-exec` removal or a replacement per-process sandbox API. → [[Seatbelt]] (N01 Q3, N05 section 4)
- [ ] ∅ Windows AppContainer, Windows Sandbox and agent-workspace MCP containment details; Microsoft Hyperlight not reviewed. → [[MVP Plan]], [[Two-Tier Isolation Design]] (N01 Q3, N05 section 1)
- [ ] ∅ Extism and Spin status; Wassette's permission-policy format; WASI 0.3 socket and thread status. → [[Wasmtime and WASI]] (N01 Q4)
- [ ] ∅ No 2025-2026 benchmark of virtiofs vs 9p vs gRPC-FUSE on Apple silicon. → [[Filesystem Control and Rollback]] (N01 Q6)
- [ ] ∅ `draft-ietf-wimse-aims` current revision and contents; current revision of the ID-JAG draft (-04 cited Dec 2025); full MCP ext-auth extension list as of 2026-07-28. → [[Transaction Tokens and Agent Auth Drafts]], [[Okta Cross App Access]], [[MCP Authorization Spec]] (N03 Q1 and Q2)
- [ ] ∅ AgentCore Policy quotas, enforce-vs-log (shadow) mode and exact Cedar context schema. → [[AWS AgentCore]] (N02 Q4, N03 Q5)
- [ ] ∅ AppArmor `aa-logprof`, Tetragon and IAM Access Analyzer details are background knowledge; no vendor ships an agent egress record-to-enforce miner (re-check before claiming). → [[Policy Learning Loop]] (N03 Q6)
- [ ] ∅ No study of learning least-privilege policy from compromised runs. → [[Trace-Mined Least Privilege]] (N03 Q6, N02 Q6)
- [ ] ∅ Unread papers and products: ActGov (arXiv 2609.24446, rate-limited), "Operationalizing CaMeL", IPIGuard, Task Shield, ShieldAgent, LlamaFirewall/AlignmentCheck, Azure Prompt Shields, the original Spotlighting paper; FORGE's source paper unidentified; MELON/StruQ/SecAlign original headline numbers not extracted. → [[The Attacker Moves Second]] (N02 Q2)
- [ ] ∅ Code availability for AgentSpec, MiniScope and AgentArmor; RTBAS full author list; no independent replication of FIDES; no head-to-head same-model comparison beyond AgentDyn (which omits FIDES and ACE); AgentDyn v3 changes not verified. → [[AgentSpec]], [[MiniScope]], [[Information Flow Control]], [[FIDES]], [[AgentDyn]] (N02 Q2 and Q6, N04a Q1)
- [ ] ∅ No white-box or optimization-based adaptive attack against CaMeL, FIDES or any deterministic monitor. → [[Adaptive Evaluation of Deterministic Monitors]] (N02 Q3)
- [ ] ∅ No evaluated use of Macaroons or Biscuit for LLM agent tool calls. → [[Macaroons and Biscuit]] (N02 Q1)
- [ ] ∅ Miller's thesis and Hardy's paper were summarised from background knowledge, not re-read. → [[Object Capabilities]] (N02 Q1)
- [ ] ∅ No public benchmark scores an egress and credential broker with real traffic; no proxy latency or false-deny baselines for agent workloads; no base rate for MCP tool-description changes; no MCP-specific security benchmark researched. → [[Measurement Gaps]] (R, N04a Q1 and Q3, N02 Q3)
- [ ] ∅ No open-source agent-egress conformance suite exists; MITRE ATT&CK TA0010 mapping not fetched. → [[Conformance Probe Matrix]] (R, N04a Q4)
- [ ] ∅ Anthropic's "custom proxy repeatedly introduced vulnerabilities" is not enumerated by category. → [[Risk Register]] (N04a Q4)
- [ ] ∅ No user study of approval fatigue for agent capability prompts; no quantitative rubber-stamp data for coding agents beyond Anthropic's 93% and METR's ~40% survey. → [[Fatigue-Resistant Approval Interfaces]] (N02 Q6, N04b Q2)
- [ ] ∅ No post-mortem confirms whether any s1ngularity victim had an OS sandbox enabled. → [[Nx s1ngularity Supply-Chain Attack]] (N04b Q2)
- [ ] ∅ No public post-mortem of an incident in a CI-hosted coding agent; CI risk inferred from Nx and Amazon Q token root causes. → [[Trust Boundaries]], [[M3 CI Identity and MCP]] (N04b Q5)
- [ ] ∅ No data on how often local MCP servers run with full ambient credentials. → [[MCP Guard]] (N04b Q5)
- [ ] ∅ No propensity data on unprompted escape attempts by production agents; SandboxEscapeBench per-model rates not fully extracted; OpenAI and Google DeepMind system cards not researched. → [[Adversary Classes]] (N04b Q4)
- [ ] ∅ NIST AI 600-1, the NCCoE agent-identity concept paper, the Jan 2026 CAISI RFI text, OWASP ASI per-item mitigations and the May 2026 Five Eyes/CISA agentic guidance were not verified. → [[Threat Model Overview]] (N04b Q3)
- [ ] ∅ Kubernetes Agent Sandbox CRD details; Modal and Daytona credential-injection capabilities. → [[Cloud Sandbox Runtimes]] (N05 section 1)
- [ ] ∅ Keycard, Lasso and Pomerium pricing; Arcade's 2026 architecture; Keycard/Aembit/Arcade deployment models and Okta/Entra integration depth. → [[Agent Identity Brokers]] (N03 Q3, N05 section 1)
- [ ] ∅ Invariant Gateway status after the Snyk acquisition; Docker MCP Gateway, Microsoft MCP gateway, Cloudflare MCP portals and Runlayer internals. → [[MCP Gateways]] (N03 Q2, N05 section 1)
- [ ] ∅ No primary buyer survey specific to coding agents on laptops; willingness to pay separately is indirect (M&A comps, Aembit's $20/agent); whether Claude Code or Codex export audit to SIEM natively. → [[Gap Analysis]] (N05 section 2)
- [ ] ∅ MVP effort estimates are judgement, not calibrated against comparable teams; no data on developer tolerance for proxy latency or TLS-pinning breakage rates. → [[MVP Plan]], [[L4 Product Metrics]] (R, N05 section 5)
- [ ] ∅ No published study reporting SWE-bench or Terminal-Bench scores with vs without an egress sandbox. → [[L3 Real-Work Utility]] (N04a Q2)
