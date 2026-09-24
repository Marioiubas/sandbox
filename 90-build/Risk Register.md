---
title: "Risk Register"
aliases: ["Risks", "Risk Log"]
type: risk
section: build
tags: [sandbox/build, risk, topic/build, topic/market, topic/tls, topic/learning, topic/approval, platform/macos, platform/linux, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Risk Register

> All risks with evidence and mitigations: vendor bundling, OpenShell as default data plane, the broker's own bugs, credential honeypot, misuse within scope, Seatbelt removal, Linux platform variance, TLS breakage (pinning, QUIC, ECH), learned-policy over-grant, approval fatigue, upstream scoping limits, vendor hook instability, buyer budget.

## Summary

Every risk the record names, with its evidence, a likelihood and impact rating, the mitigation, and the signal that should make the owner act. The **evidence** and **mitigation** columns come from the report's risk table and research note 05 section 5.5. The **likelihood**, **impact** and **trigger** columns are **Proposal** judgements for the build team, not sourced facts; re-rate them at every milestone exit and record changes in [[Build Log]].

Scale: likelihood and impact are High / Medium / Low over the next 12 months.

## Register

| # | Risk | Evidence | Likelihood | Impact | Mitigation (Proposal) | Owner signal / trigger |
|---|---|---|---|---|---|---|
| R1 | Platform vendors bundle the feature | Claude Code ships `mask` with SigV4 re-signing and forbids repository settings from enabling injection ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)); Codex ships a managed proxy with method filtering; Docker sbx ships proxy injection free ([[Gap Analysis]]) | High | High | Be the neutral layer across agents; compile-to-native exporters ([[Native Config Exporters]]); differentiate on minting, identity, semantic git/API scoping, learning and fleet audit; sell to the CISO who runs 3+ agents | A vendor announces minting, git ref scoping or cross-agent policy; a design partner drops the broker for a native feature |
| R2 | OpenShell becomes the default open-source data plane | Apache-2.0, per-binary L7 rules, enforce/audit modes, ~8.7k stars, NVIDIA-backed ([OpenShell](https://github.com/NVIDIA/openshell)) | Medium | High | Container-free laptop mode; interoperate (import/export OpenShell policy); consider offering minting and identity as an OpenShell provider ([[NVIDIA OpenShell]]) | OpenShell adds a laptop mode, minting or learning; partners ask for OpenShell compatibility |
| R3 | The broker's own bugs | Anthropic's custom proxy "repeatedly introduced vulnerabilities" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)); the sandbox-runtime NUL-byte parser differential was exposed ~5.5 months ([Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)); enforcement-layer bugs appeared at least seven times in 13 months across four vendors (report) | High | High | Single canonicaliser ([[Hostname Canonicaliser]]); fuzzing and property tests; public corpus ([[L1 Conformance Suite]]); external pentest; bounty ([[Red-Team Plan]]); minimal L7 surface | Any L1 failure, fuzz crash or pentest high finding; any new adapter added without a fuzz target |
| R4 | Broker becomes the credential honeypot | Design consequence of centralising secrets (report) | Medium | High | Per-user daemon; keychain-held roots; memory-only minted tokens with short TTLs; control socket unreachable from sandboxes ([[Credential Injector and Issuers]], [[Broker CLI and Daemon]]) | A secret value found in SQLite, logs or core dumps; a sandbox reaching `ctl.sock` in any probe |
| R5 | Misuse within granted scope | A proxy "prevents theft but not misuse" ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)) | High | Medium | Narrow verbs (PR create ≠ merge); trifecta approvals; approvals for irreversible verbs; honest non-goals ([[Threat Model Non-Goals]]); never claim to stop injection | A partner incident where a legitimately granted verb did the damage; marketing or docs drift toward "stops prompt injection" |
| R6 | macOS Seatbelt removal | `sandbox-exec` deprecated with no removal timeline; Linux-VM fallback raised start from <5 ms to ~800 ms in one project ([apple/containerization#737](https://github.com/apple/containerization/issues/737)) | Low | High | VZ backend; backend abstraction ([[Seatbelt]], [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]); track the incumbents, who share the dependency | A macOS beta changes `sandbox-exec` behaviour; Claude Code, Codex or Gemini CLI announce a replacement |
| R7 | Linux platform variance | Ubuntu 24.04+ gates unprivileged userns via AppArmor ([srt](https://github.com/anthropic-experimental/sandbox-runtime)); Landlock ABI spread (ABI 9 on Linux 7.1; UDP still in review in June 2026) ([rust-landlock](https://landlock.io/rust-landlock/landlock/enum.ABI.html)) | High | Medium | `broker doctor`; installer AppArmor profile; runtime ABI probing with best-effort Landlock ([[bubblewrap]], [[Landlock]]); CI matrix on every OS release | `probe()` failures in partner telemetry; a new distro release in the CI matrix failing |
| R8 | TLS breakage: pinning, QUIC, possible ECH | Pinned clients break under termination; QUIC defeats domain filtering ([E2B docs](https://docs.e2b.dev/network/internet-access.md)); ECH would defeat SNI peeking, adoption unmeasured (report) | Medium | Medium | L4 passthrough list without injection; block UDP/443; compatibility matrix; terminate only where L7 is needed ([[TLS Termination and Per-Session CA]]) | A common dev tool fails behind the broker; measurable ECH adoption on hosts in partner traffic |
| R9 | Learned policy over-grants or is poisoned | Allowed-domain abuse: a learned "allow api.anthropic.com" would not have stopped the attacker-key exfiltration ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)) | Medium | High | Trusted-input or intersection learning; org ceilings; high-risk verbs never auto-granted; exclude foreign-credential requests; SymCC gates; human PR review; shadow before enforce ([[Policy Miner Safeguards]], [[SymCC CI Gates]]) | A learned rule broader than a registrable domain; a narrowing-gate counterexample approved without review |
| R10 | Approval fatigue | Users approve 93% of Claude Code permission prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)); OWASP lists "Overwhelming HITL" as T10 ([OWASP](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)) | High | Medium | Few prompts; authority diffs, not prose; approvals only for irreversible verbs; no flag disables isolation ([[Fatigue-Resistant Approval Interfaces]], [[I8 No Flag Disables Isolation]]) | Prompts per session rising in [[L4 Product Metrics]]; partners enabling blanket approval |
| R11 | Upstream scoping limits | GitHub installation tokens have no branch or path scope ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)); GCP Credential Access Boundaries cover Cloud Storage only ([GCP docs](https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials)) | High (structural) | Medium | Proxy enforcement for everything native tokens cannot express ([[Git Smart-HTTP Adapter]], [[GCP Credential Access Boundaries]]) | A new provider scope feature (adopt it); a parser bug in an adapter that enforces the missing scope |
| R12 | Vendor hook and API instability | Unknown whether agent vendors will expose stable egress hooks (report; research note 05 gaps) | Medium | Low | Wrap the process rather than depend on hooks; exporters are additive | An exporter target changes format; a vendor removes a config key the exporter uses |
| R13 | Buyer budget | Only 24% of CISOs have a separate AI-security budget line ([Dark Reading](https://www.darkreading.com/cybersecurity-operations/ai-security-spending-jumps-fear-outpaces-proof-value)) (scoreboard) | Medium | Medium | Land via free OSS with devex teams; expand via compliance evidence (SOC 2 / ISO 42001 control mapping) (research note 05) | Design partners unwilling to pay for `ee/` features; procurement asks for compliance evidence the product lacks |
| R14 | Unverified crate maturity (Proposal, from the record's gaps) | Crate versions and maturity beyond `hudsucker` and `landlock` were not verified ([[Tech Stack]]) | Medium | Medium | Pin and evaluate at M0; prefer battle-tested primitives; record choices by ADR | A pinned crate is unmaintained or has an advisory |
| R15 | Schedule risk (Proposal, from the record's gaps) | MVP effort estimates are judgement, not calibrated ([[MVP Plan]]) | Medium | Medium | Compress by dropping MCP and AWS from M3, never by dropping conformance or fuzzing | A milestone exceeds its two-week window by more than a week |

> [!question] Unverified
> ECH adoption in 2026 and its effect on SNI peeking are not measured in the record; how vendors handle QUIC/HTTP3, gRPC and WebSocket is also unverified. Anthropic's "custom proxy repeatedly introduced vulnerabilities" is not enumerated by category, so R3's mitigation may miss a class. Whether agent vendors will expose stable hooks (R12) is unknown.

## How to use this register

- Review at each milestone exit; update likelihood and impact with evidence from L1-L6 results and partner telemetry.
- Every trigger that fires gets a [[Build Log]] entry and, if it changes the design, an ADR in [[MOC Decisions]].
- Risks R3, R4 and R9 map directly to invariants; a trigger on those is treated as a potential security regression ([[CLAUDE]] section 3).

## How it connects

- part-of:: [[MOC Build]]
- motivated-by:: [[Gap Analysis]]
- motivated-by:: [[NVIDIA OpenShell]]
- mitigated-by:: [[Hostname Canonicaliser]]
- mitigated-by:: [[Credential Injector and Issuers]]
- motivated-by:: [[Threat Model Non-Goals]]
- depends-on:: [[Seatbelt]]
- depends-on:: [[bubblewrap]]
- mitigated-by:: [[TLS Termination and Per-Session CA]]
- mitigated-by:: [[Policy Miner Safeguards]]
- mitigated-by:: [[Fatigue-Resistant Approval Interfaces]]
- motivated-by:: [[GCP Credential Access Boundaries]]
- decided-by:: [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]
- evaluated-by:: [[Red-Team Plan]]

## Implications for the build

- R3 is the risk the build controls most directly: no parser without a fuzz target, no adapter without conformance probes.
- R5 constrains wording everywhere: CLI output, docs and code comments must not claim the broker stops injection.
- R9 means the learner's safeguards are part of M2's acceptance, not optional hardening.

## Open questions

- Whether any vendor exposes a stable egress hook the broker could use instead of wrapping.
- Real-world TLS-pinning breakage rates for common dev tools (missing from the record).

## Sources

- Report: risk table; ECH watch item; "custom proxy repeatedly introduced vulnerabilities".
- Research note 05 section 5.5 (parser differential ~5.5 months; buyer budget row; per-OS maintenance) and gaps.
- Scoreboard (24% of CISOs have a separate AI-security budget line).
