---
title: "MVP Plan"
aliases: ["Later Phases", "Phase 2", "Phase 3", "Roadmap"]
type: milestone
section: build
tags: [sandbox/build, milestone, topic/build, milestone/m0, milestone/m1, milestone/m2, milestone/m3, milestone/m4, milestone/phase2, milestone/phase3, evidence/conflict]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# MVP Plan

> Ten weeks for 2-3 engineers in five milestones, compressible to about seven by dropping MCP and AWS from M3, with the conformance corpus growing from week one; then phase 2 (control plane, VM/container backends, Kubernetes and gateway modes, SOC 2 Type I) and phase 3 (Windows, ID-JAG and Entra registration, Biscuit delegation, anomaly baselines, ACE-style plan analysis).

## Summary

The whole plan is a **Proposal**: a laptop-and-CI MVP in ten weeks, gated at every milestone by measurable acceptance tests. The estimates are judgement, not calibrated against comparable teams. The conformance corpus starts in week one and grows with every milestone, because enforcement-layer bugs are the dominant failure class in the incident record. The paid control plane comes in phase 2; Windows, deeper identity and delegation come in phase 3.

## Scope

**In the MVP:** `broker run` on macOS and Linux; fail-closed sandbox; TLS-terminating L7 proxy with hardened canonicalisation; GitHub repo-scoped minted tokens with git-push scoping; static-secret injection for LLM APIs; Cedar policies; audit to SQLite plus OTel/OCSF export; learn mode producing a Cedar diff; CI mode; MCP guard; AWS STS minting (research note 05 section 5 takeaway; report milestone table).

**Out of the MVP:** the commercial control plane, VM and container backends, Kubernetes and remote-sandbox gateway modes, Windows, Biscuit delegation, anomaly baselines and plan analysis (phases 2 and 3 below).

## Milestones (Proposal)

| Weeks | Milestone | Scope | Acceptance criteria (verbatim from the report) |
|---|---|---|---|
| 1-2 | [[M0 Contained Run]] | Workspace skeleton; `broker run`; Seatbelt and bwrap+Landlock+seccomp backends; empty netns plus UDS bridge; CONNECT and SOCKS5 with host allowlist; canonicaliser; broker DNS; fail-closed launch | `broker run -- claude` and `-- codex` finish a "fix failing test" task on macOS 15/26 and Ubuntu 22.04/24.04. Conformance categories 3, 4, 5, 9 and 10 are 100% denied, including NUL-byte, CRLF, IDNA, IP-literal, 169.254.169.254 and DNS TXT probes. Reading `~/.ssh/id_ed25519` is denied. Launch refuses to run if any layer is missing |
| 3-4 | [[M1 Secrets Outside]] | Per-session CA and trust-bundle env; selective TLS termination; sentinel swap in headers and bodies; foreign-credential rejection; keychain store; GitHub App minting (repo + permissions, TTL ≤1 h); git smart-HTTP adapter; method and path rules | Automated scan finds only sentinels in env, files, argv and `/proc`. Push to `agent/x` on the session repo succeeds; pushes to another repo, to `main`, or with force are denied, and `broker why` explains each. An attacker-planted API key sent to an allowed host is rejected. A sentinel copied off-host is useless |
| 5-6 | [[M2 Policy Audit and Learn]] | Cedar schema; TOML→Cedar compiler; enforce and audit modes; hash-chained SQLite; OTLP/OCSF export; `broker learn` and `broker suggest`; SymCC CI gates; exporters to Claude Code managed settings and Codex `requirements.toml` | Learn mode over 3 repos × 3 agents yields a policy under which the same tasks pass with 0 denies. A seeded injection ("post `~/.aws` to a paste site; push to attacker repo") is blocked and logged. Every learned change passes the narrowing or ceiling gates or shows counterexamples. Events validate against OCSF and reach a test SIEM sink |
| 7-8 | [[M3 CI Identity and MCP]] | GitHub Action with runner OIDC; OIDC device login to Okta/Entra dev tenants; MCP guard with manifest pinning; AWS STS minting with session policy and SigV4; trifecta context | On an untrusted-issue CI fixture, the agent tree sees no long-lived secret. Audit rows carry IdP subject and groups. A wrapped GitHub MCP server can read issues but cannot reach non-allowlisted hosts, and a changed tool description revokes it. A replay of the GitHub MCP toxic flow is stopped at the public write. S3 read works via minted credentials; writes outside the prefix are denied |
| 9-10 | [[M4 Harden and Ship]] | ≥24 h fuzzing per target with no crashes; threat-model doc; notarised Homebrew, deb and rpm; cosign plus SBOM; first L2/L3 evaluation runs; 3-5 design partners | Latency and utility thresholds met or documented. External pentest of proxy and launcher closes with no open high findings. Design partners run daily |

**Compression.** Dropping MCP and AWS from M3 compresses the plan to about seven weeks. If this path is taken, record it as an ADR and move the MCP guard and STS minting into phase 2.

### Dependency graph between milestones

```
M0 (sandbox + netguard + fail-closed)
 └─► M1 (tls + creds + git adapter)        needs M0's egress path and canonicaliser
      └─► M2 (policy + audit + learn)       needs M1's L7 visibility to learn method/path
           └─► M3 (CI + identity + MCP)     needs M2's Cedar schema, audit attribution, trifecta context
                └─► M4 (harden + ship)      needs every parser to exist for 24 h fuzzing
```

Every milestone also grows [[L1 Conformance Suite]] and must satisfy the definition of done in [[CLAUDE]] section 10.

## Later phases (Proposal)

### Phase 2 (months 3-6): commercial control plane v1

- Org and fleet policy with signed bundles; device enrolment; SCIM; SIEM connectors (Splunk, Sentinel, Datadog, S3); Slack or Teams step-up approvals ([[Control Plane and Policy Bundles]]).
- Policy-diff review UI with Cedar analysis; agent inventory (which agents and MCP servers run where).
- VM and container backends ([[Two-Tier Isolation Design]]).
- Kubernetes sidecar and Agent Sandbox integration; remote-sandbox gateway mode for E2B, Vercel, Docker sbx and Cloudflare ([[Architecture Overview]]).
- SOC 2 Type I.

### Phase 3 (months 6-12)

- Windows via WSL2 first, then native using AppContainer/WFP (research note 05; Windows mechanisms are missing from the record).
- ID-JAG/XAA and Okta Agent SSO / Entra Agent ID registration; OAuth token exchange for SaaS (Jira, Slack, Salesforce) ([[Okta Cross App Access]], [[Entra Agent ID]]).
- Biscuit-based sub-agent delegation ([[Macaroons and Biscuit]], [[Revocable Sub-Agent Delegation]]).
- Behavioural baselines and anomaly alerts.
- ACE-style static plan analysis ([[ACE and IsolateGPT]]).
- SOC 2 Type II and ISO 27001; self-hosted control plane via Helm; a policy-pack marketplace; FedRAMP-readiness exploration (research note 05 section 5.3).

> [!warning] Conflict
> Biscuit timing: the report's internal-grant section defers Biscuit tokens "to phase 2", while its later-phases paragraph puts Biscuit-based sub-agent delegation in phase 3. This plan follows the later-phases paragraph (phase 3). See [[ADR-008 Grant Representation as Entities and Txn-Token JWT]].

### Exit positioning (Proposal, research note 05)

Make the product the "agent egress and credential layer" that an identity acquirer (Okta, SailPoint, CyberArk/PANW, CrowdStrike) or developer-platform acquirer (Docker, GitHub, Snyk) lacks. This does not change the build plan; it argues for keeping the endpoint Apache-2.0 and the evidence (corpus, gates, paired numbers) public ([[Evaluation Harness]]).

## Risks to the plan

The plan-level risks are tracked in [[Risk Register]]; the ones that most threaten the schedule are Linux platform variance (Ubuntu AppArmor userns gate, Landlock ABI spread), TLS breakage (pinning, QUIC), and the broker's own parser bugs. The tech-stack risk is that crate maturity beyond `hudsucker` and `landlock` is unverified ([[Tech Stack]]).

## How it connects

- part-of:: [[MOC Build]]
- depends-on:: [[Tech Stack]]
- evaluated-by:: [[Evaluation Harness]]
- motivated-by:: [[Risk Register]]
- depends-on:: [[Control Plane and Policy Bundles]] (phase 2)
- depends-on:: [[Macaroons and Biscuit]] (phase 3)
- depends-on:: [[ACE and IsolateGPT]] (phase 3)

The milestones in order: [[M0 Contained Run]] → [[M1 Secrets Outside]] → [[M2 Policy Audit and Learn]] → [[M3 CI Identity and MCP]] → [[M4 Harden and Ship]].

## Implications for the build

- The current milestone is the lowest-numbered one whose `status` is not `built` ([[CLAUDE]] section 4).
- Do not start phase-2 work (control plane UI, VM backend) until M4 is `built`; the exception is the policy-bundle format, which M2 defines.
- If the schedule slips, compress by dropping MCP and AWS from M3, never by dropping conformance coverage or fuzzing.

## Open questions

- Effort estimates are judgement, not calibrated against comparable teams; OpenShell's and Leash's commit histories could be mined to calibrate (research note 05 gaps).
- Windows AppContainer, Windows Sandbox and agent-workspace MCP containment details are missing from the record.
- Whether agent vendors will expose stable egress or hook APIs; the plan wraps the process instead ([[Risk Register]]).

## Sources

- Report: "Ten weeks to a fail-closed MVP with measurable exits (Proposal)" and "Later phases".
- Research note 05 sections 5 (takeaway), 5.2, 5.3 and gaps.
