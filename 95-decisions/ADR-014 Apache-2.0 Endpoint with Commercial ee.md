---
title: "ADR-014 Apache-2.0 Endpoint with Commercial ee"
aliases: ["ADR-014"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/market, topic/build, milestone/m0, milestone/phase2]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "License everything on the endpoint Apache-2.0 and keep the fleet control plane in a commercial ee/ directory; reject AGPL and closed source."
related: ["[[Gap Analysis]]", "[[Control Plane and Policy Bundles]]", "[[Local Credential Proxies]]", "[[Cloud Sandbox Runtimes]]", "[[Docker Sandboxes]]", "[[Repository Layout]]", "[[Product Thesis]]", "[[NVIDIA OpenShell]]", "[[Claude Code and sandbox-runtime]]", "[[Agent Identity Brokers]]", "[[ADR-001 Value Lives in the Broker]]", "[[Policy Learning Loop]]", "[[Audit Recorder and Event Schema]]", "[[L1 Conformance Suite]]", "[[Risk Register]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[MOC Decisions]]"]
sources: ["https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk", "https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/", "https://github.com/Infisical/agent-vault", "https://github.com/NVIDIA/openshell", "https://github.com/strongdm/leash", "https://github.com/anthropic-experimental/sandbox-runtime", "https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/", "https://docs.docker.com/ai/sandboxes/", "https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/", "https://workos.com/blog/arcade-vs-workos-agent-authentication-enterprise-auth", "https://www.darkreading.com/cybersecurity-operations/ai-security-spending-jumps-fear-outpaces-proof-value", "https://bytecodealliance.org/articles/wasmtime-security-advisories"]
superseded_by:
---

# ADR-014 Apache-2.0 Endpoint with Commercial ee

> License everything on the endpoint Apache-2.0 and keep the fleet control plane in a commercial ee/ directory; reject AGPL and closed source.

## Status

Proposed (2026-09-24). Takes effect in M0, when `code/` is created with the workspace licence layout from [[Repository Layout]]. The `ee/` control plane itself is phase 2 ([[Control Plane and Policy Bundles]]).

## Context

The product is a security boundary that sits between a company's agents and its credentials. Buyers must be able to read it, and the market has just shown what happens when a sandbox's licence moves under them.

- **Daytona went closed-source in June 2026.** Its public repository is frozen at v0.190.0 under AGPL-3.0. The stated reason was protecting isolation code from "AI-assisted exploit discovery", and the analysis frames the unmaintained AGPL fork as security debt for self-hosters ([bex.co](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk); [[Cloud Sandbox Runtimes]]).
- **Docker Sandboxes is free but closed.** It "will remain free to use, including commercially", with a licence that is "not final yet" ([INNOQ](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/); [[Docker Sandboxes]]). Docker sells a subscription that lets admins "centrally manage sandbox network, filesystem, and MCP policies" ([Docker docs](https://docs.docker.com/ai/sandboxes/)): a free endpoint with a paid control plane.
- **Open peers set the bar.** NVIDIA OpenShell is Apache-2.0 ([GitHub](https://github.com/NVIDIA/openshell)), StrongDM Leash is Apache-2.0 ([GitHub](https://github.com/strongdm/leash)), and Anthropic's srt is Apache-2.0 ([srt](https://github.com/anthropic-experimental/sandbox-runtime)). E2B's infrastructure is Apache-2.0 with BYOC ([MarkTechPost](https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/)).
- **Open-core precedent.** Infisical Agent Vault ships MIT with enterprise features in an `ee/` directory under a separate licence ([GitHub](https://github.com/Infisical/agent-vault); [[Local Credential Proxies]]).
- **Closing source does not stop AI-assisted discovery.** Eleven of Wasmtime's twelve April 2026 advisories were found by its own team "using new LLM-based tools" ([Bytecode Alliance](https://bytecodealliance.org/articles/wasmtime-security-advisories)). **Inference:** defenders with the source can run the same tools, which argues for openness plus fuzzing rather than obscurity.
- **Buyers.** The ICP splits into platform and devex teams, who want a zero-friction `broker run` and CI actions, and CISOs, who want inventory, central policy, SIEM export and SOC 2 evidence (research note 05, section 2). Only 24% of CISOs have a separate AI-security budget line ([Dark Reading](https://www.darkreading.com/cybersecurity-operations/ai-security-spending-jumps-fear-outpaces-proof-value)), so landing through free OSS matters.
- **Price anchors.** Aembit's AI Teams tier is $20 per agent per month ([Aembit](https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/)). Arcade's Growth tier is $25 per month plus usage ([WorkOS](https://workos.com/blog/arcade-vs-workos-agent-authentication-enterprise-auth)).

## Decision

**Proposal.**

1. **Apache-2.0 for everything that runs on the endpoint:** the CLI and daemon, launcher, proxy (netguard, tls, l7 and adapters), credential injector and issuers, policy compiler, native-config exporters, grant, audit (including the OTLP/OCSF exporter), local learn mode and MCP guard. The public **bypass corpus** is Apache-2.0 as well.
2. **Commercial licence (source-available or proprietary) for `ee/` only:** fleet control plane, SSO/SCIM, SIEM connectors, approvals, retention, compliance reports, the hosted miner at scale and support SLAs.
3. **Security never depends on `ee/`.** All nine invariants are enforced and tested in the Apache-2.0 tree. A laptop or CI runner without `ee/` is fully contained, and audit export to a SIEM through OTLP/OCSF works without it.
4. **Dependency direction is one-way.** Code in `ee/` may depend on the open crates. No open crate may depend on `ee/`.
5. **Governance.** Take a trademark on the product name, and require a CLA or DCO so the `ee/` licence can change later.
6. **Pricing hypothesis, not a commitment:** free OSS; a Team tier at about $15–25 per developer seat per month, priced per human developer because agent counts are ephemeral; Enterprise custom with self-hosting.

**Testable as:** a CI licence check that every crate outside `ee/` declares `Apache-2.0`, that `cargo tree` for the endpoint binary contains no `ee/` crate, and that the full invariant and L1 suites pass with `ee/` removed from the workspace.

## Alternatives considered

| Alternative | Pros | Cons | Why rejected |
|---|---|---|---|
| **AGPL for the endpoint** | Stops closed SaaS forks | Procurement friction; less acquirer-friendly; Daytona's frozen AGPL fork shows the self-hoster risk | Enterprise security teams are the buyer; friction at the boundary costs adoption |
| **Closed source** | Protects the moat; the rationale Daytona gave | The boundary cannot be audited; repeats the Daytona and Docker uncertainty buyers now worry about | Undercuts the product's credibility claim: a public bypass corpus on an auditable proxy |
| **Everything open, including the control plane** | Maximum adoption | No revenue line for the CISO buyer; nothing to fund the team | The ICP split already separates what devex teams use from what CISOs buy |

## Consequences

- **Easier:** security reviews and procurement, since anyone can read and fuzz the boundary. Distribution through Homebrew, deb and rpm is unencumbered. Interoperation with OpenShell (import, export, or acting as its minting provider) stays licence-compatible.
- **Harder:** a competitor, or OpenShell, can absorb the endpoint's features. The moat must come from execution, the `ee/` fleet features and evidence (public corpus, SymCC-gated changes, published utility and containment numbers), not from licence terms ([[ADR-001 Value Lives in the Broker]]).
- **Riskier:** the boundary between endpoint and `ee/` will be tested by every feature request. Features that raise containment go in the open tree by rule 3, even when they would sell.
- **Operational:** CLA or DCO handling for outside contributors.

## Revisit triggers

- OpenShell or another Apache-2.0 project ships minting, identity binding or a miner, so the open endpoint stops differentiating.
- Docker finalises the sbx licence, or another major runtime relicenses.
- Design partners or acquirers raise licence objections during diligence.
- The hosted miner proves to be the main paid value, which may argue for moving part of learning into `ee/`. That move requires local learn mode to stay open.
- Measured willingness to pay contradicts the per-developer-seat hypothesis. Evidence so far is indirect (M&A comparables and Aembit's price point).

## Invariants and components affected

- **Weakens none.** Rule 3 requires every invariant ([[I9 Hash-Chained Audit Outside the Sandbox]] included) to be enforced and tested in the open tree.
- Components: [[Repository Layout]] (workspace licence and `ee/` location), [[Control Plane and Policy Bundles]] (commercial), [[Audit Recorder and Event Schema]] (exporter stays open), [[Policy Learning Loop]] (local learn mode open; hosted miner in `ee/`), [[L1 Conformance Suite]] (public corpus).

## How it connects

- motivated-by:: [[Gap Analysis]] (licensing opening)
- motivated-by:: [[Cloud Sandbox Runtimes]] (Daytona relicensing)
- motivated-by:: [[Docker Sandboxes]] (licence "not final")
- example-of:: [[Local Credential Proxies]] (Agent Vault MIT plus `ee/` precedent)
- contrasts-with:: [[Docker Sandboxes]]
- competes-with:: [[NVIDIA OpenShell]]
- depends-on:: [[Repository Layout]]
- depends-on:: [[Control Plane and Policy Bundles]]
- part-of:: [[Product Thesis]]
- part-of:: [[MOC Decisions]]

## Implications for the build

- Create `code/LICENSE` (Apache-2.0) and `code/ee/LICENSE` (commercial placeholder) in M0, with SPDX headers enforced by CI.
- Add the "no open crate depends on `ee/`" check and the "invariants pass without `ee/`" job to CI from the first commit.
- Publish the bypass corpus from `tests/bypass-corpus/` under Apache-2.0 at M4, alongside the bug bounty.
- Set up DCO or CLA tooling before accepting the first outside contribution.

## Open questions

- Should `ee/` be source-available or proprietary? The record leaves both open.
- Which licence for the evaluation harness (`eval/`)? Not specified; defaulting to Apache-2.0 would help credibility.
- No confirmed pricing exists for Docker Sandboxes enterprise, Keycard or OpenShell commercial support ([[Agent Identity Brokers]]), so the price hypothesis has weak anchors.

## Sources

- [bex.co: Daytona goes closed source](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk)
- [INNOQ: trust but sandbox](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)
- [Docker docs: Sandboxes](https://docs.docker.com/ai/sandboxes/)
- [Infisical/agent-vault](https://github.com/Infisical/agent-vault)
- [NVIDIA/OpenShell](https://github.com/NVIDIA/openshell)
- [strongdm/leash](https://github.com/strongdm/leash)
- [anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- [MarkTechPost: best agent sandboxes 2026](https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/)
- [Aembit: IAM for Agentic AI GA](https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/)
- [WorkOS: Arcade vs WorkOS](https://workos.com/blog/arcade-vs-workos-agent-authentication-enterprise-auth)
- [Dark Reading: AI security spending](https://www.darkreading.com/cybersecurity-operations/ai-security-spending-jumps-fear-outpaces-proof-value)
- [Bytecode Alliance: Wasmtime security advisories](https://bytecodealliance.org/articles/wasmtime-security-advisories)
- Report: decisions row "Licence" and the licensing paragraph in "The gap to own"; research note 05 sections 2, 5.4 and 5.5; scoreboard sandboxing section (Demand and small-team paragraphs).
