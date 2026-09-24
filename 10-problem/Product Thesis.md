---
title: "Product Thesis"
aliases: ["Own the Broker Borrow the Sandbox", "Market Context", "Thesis"]
type: concept
section: problem
tags: [sandbox/problem, concept, topic/market, topic/credentials, topic/policy, topic/learning, topic/git, topic/audit, evidence/secondary]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Own the broker, borrow the sandbox: a vendor-neutral Apache-2.0 Rust broker that owns one policy and audit stream, per-task credential minting, developer-protocol semantics and verified policy learning, while reusing OS sandboxes; includes market context from the scoreboard."
related: [AUTO]
sources: [AUTO]
---

# Product Thesis

**Own the broker, borrow the sandbox.** Isolation primitives are mature and already shipped by every agent vendor, and proxy-side secret injection became table stakes in 2026; what nobody offers neutrally is one policy and audit stream across agents, credential *minting* bound to user, agent, repo and task, semantic rules for developer protocols, and least-privilege policy that is learned and then proved to be a narrowing. A small team should build that layer as a vendor-neutral, Apache-2.0 Rust binary, and plan for a tuck-in acquisition rather than a standalone giant.

## The three findings the thesis rests on

1. **In-band defenses fail.** Every model-based prompt-injection defense tested adaptively was broken at 71–100% ([arXiv 2510.09023](https://arxiv.org/html/2510.09023)). See [[Problem Statement]] and [[The Attacker Moves Second]].
2. **Incidents share one shape.** Nearly every documented 2025–2026 agent incident combined untrusted input with a broad standing credential and an open or "allowed" outbound channel ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability); [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)). Removing the standing credential and the open channel removes most of the blast radius.
3. **Isolation is a commodity.** Claude Code, Docker, Vercel, Cloudflare, E2B and NVIDIA OpenShell all ship proxy-side secret injection in 2026 ([Claude Code docs](https://code.claude.com/docs/en/sandboxing); [Docker docs](https://docs.docker.com/ai/sandboxes/security/defaults/); [NVIDIA OpenShell](https://github.com/NVIDIA/openshell)). By September 2026 eight products put a host-side proxy with a per-sandbox CA in front of the agent: Claude Code (v2.1.199+), Docker, Vercel, Cloudflare, E2B, Runloop, OpenShell and Infisical Agent Vault. A new entrant cannot win on "we inject credentials at the proxy".

## What to own, and what to borrow

**Proposal.** Borrow the sandbox: Seatbelt on macOS, bubblewrap with no network interface plus seccomp and Landlock on Linux, the same stack Anthropic's sandbox-runtime and OpenAI's Codex use ([srt](https://github.com/anthropic-experimental/sandbox-runtime); [codex linux-sandbox](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)), with a VM as the opt-in hard tier ([[Two-Tier Isolation Design]]). Own four things:

| Owned capability | Why it is unowned | Vault note |
|---|---|---|
| One policy and one audit stream across all agents | Each vendor ships its own settings surface (Claude Code managed settings, Codex `requirements.toml`, Cursor admin dashboard, Docker org policy) and they are incompatible ([Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/); [Cursor 2.5](https://cursor.com/changelog/2-5)) | [[Audit Recorder and Event Schema]], [[Native Config Exporters]] |
| Credential **minting** bound to user, agent, repo and task | Most products substitute a static long-lived secret for a sentinel; Keycard is closest but is closed and has no OS sandbox ([Keycard](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/)) | [[Just-in-Time Credential Minting]] |
| Semantic rules for developer protocols (git push per repo and branch, GitHub API verbs, read-only registries) | No reviewed neutral product parses git smart-HTTP; Anthropic's web sandbox does it only for its own product ([Anthropic](https://www.anthropic.com/engineering/claude-code-sandboxing)) | [[Git Smart-HTTP Adapter]], [[GitHub API Adapter]] |
| Record-then-restrict policy learning with a verified narrowing proof | No product ships an agent egress record-to-enforce miner; AgentCore does NL→Cedar in the cloud, OpenShell has an audit mode with no miner ([AWS](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/); [OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)) | [[Policy Learning Loop]] |

The full six-item gap list (adding local MCP containment without a container runtime and an OTel/OCSF audit schema attributed to Okta or Entra identities) is in [[Gap Analysis]]. The decision to put the value in the broker rather than a new isolation primitive is [[ADR-001 Value Lives in the Broker]].

The deeper claim, from the report's conclusion: the durable work is **the semantics of authority**. Knowing that a POST to `/repos/acme/web/pulls` is `pr.create` rather than `pr.merge`, that a pkt-line updates `refs/heads/main` with force, and that this session has already read a private repo and a public issue. Whoever encodes those semantics once and enforces them across Claude Code, Codex, Cursor, CI runners and stdio MCP servers holds the layer the vendors cannot provide neutrally. A corollary is that the broker sees every system of record, so it is the natural source of information-flow labels ([[Trifecta Session Labels]], [[Credential Broker as Label Authority]]).

## What the product will not claim

It will not stop an injected agent from misusing authority it legitimately holds. It shrinks that authority to the task and makes its use auditable ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)); see [[Threat Model Non-Goals]].

## Market context (from the scoreboard)

The problem "capability-based sandboxing for autonomous agents" ranked first of 11 on the scoreboard at **72.5/100**: Payout 7, Ease 6, Importance 8, Demand 8, composite = sum × 2.5 (scores are the scoreboard report's judgement; the evidence behind each is cited below).

- **Importance 8**: the model makers concede injection is not fixable (OpenAI "unlikely to ever be fully 'solved'" ([OpenAI](https://openai.com/index/hardening-atlas-against-prompt-injection/)); NCSC "will never be properly mitigated" ([NCSC](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection))), so deterministic containment is what lets agents hold real authority. It stops short of 10 because agents keep shipping with human approval prompts as a fallback.
- **Ease 6** on the full framing; the tractable wedge, a vendor-neutral egress and credential broker, scores about **7**. Isolation is solved (Firecracker boots in under 125 ms with under 5 MiB overhead ([Firecracker](https://firecracker-microvm.github.io/)); Anthropic's sandbox cut permission prompts by 84% ([Anthropic](https://www.anthropic.com/engineering/claude-code-sandboxing))); what remains is least-privilege policy that does not break tasks, IdP integration, compliance and in-customer deployment.
- **Demand 8**: at least 15 AI and agent-security startups were acquired between April 2025 and mid-2026. F5 bought CalypsoAI for $180M ([SecurityWeek](https://www.securityweek.com/f5-to-acquire-calypsoai-for-180-million/)); Check Point bought Lakera for about $300M ([SecurityWeek](https://www.securityweek.com/cybersecurity-ma-roundup-40-deals-announced-in-september-2025/)); CrowdStrike bought SGNL for roughly $740–750M ([Wikipedia: CrowdStrike](https://en.wikipedia.org/wiki/CrowdStrike)); Palo Alto Networks closed its $25B CyberArk deal ([Wikipedia: Palo Alto Networks](https://en.wikipedia.org/wiki/Palo_Alto_Networks)) and agreed to buy Portkey ([Palo Alto Networks](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-to-acquire-portkey-to-secure-the-rise-of-ai-agents)). E2B raised $21M while reporting use at 88% of the Fortune 100 ([VentureBeat](https://venturebeat.com/ai/how-e2b-became-essential-to-88-of-fortune-100-companies-and-raised-21-million/)); Keycard launched with $38M for per-task agent access control ([SiliconANGLE](https://siliconangle.com/2025/10/21/ai-agent-security-startup-keycard-reels-38m/)). Budgets hold it below 9: only 24% of CISOs have a separate AI-security budget line ([Dark Reading](https://www.darkreading.com/cybersecurity-operations/ai-security-spending-jumps-fear-outpaces-proof-value)) and only 23% of organisations monitor or log their AI agents ([BCG](https://www.bcg.com/publications/2026/cybersecurity-spending-ai-threat-trends)).
- **Payout 7**: pure-play agent-security exits cluster at $180M–$750M; $1B+ outcomes exist only in the adjacent identity layer. Market-size estimates range from $1.65B for 2026 ([MarketsandMarkets](https://www.marketsandmarkets.com/PressReleases/agentic-ai-security.asp)) to an implausible $18.7B for 2025 ([SNS Insider](https://www.snsinsider.com/reports/ai-agent-security-market-10649)).

Later comparables: SailPoint acquired Entro for a reported ~$200M on 15 Jun 2026 ([SiliconANGLE](https://siliconangle.com/2026/06/15/sailpoint-acquires-ai-agent-security-startup-entro-reported-200m/)), and Okta agreed to buy Permiso for ~$200M on 30 Jul 2026 ([TechCrunch](https://techcrunch.com/2026/07/30/okta-buys-ai-security-startup-permiso-source-says-for-about-200m/)).

> [!question] Unverified
> Market sizing and several deal figures rest on single industry sources; the scoreboard excluded some claims entirely. Treat them as context, not as planning inputs. Tracked in [[Open Questions and Unverified Claims]].

### Why this wedge fits a small team

The scoreboard gives four reasons ([Leash](https://github.com/strongdm/leash); [Docker](https://docs.docker.com/ai/sandboxes/); [MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)):

1. It can be built in months from open components (bubblewrap, Seatbelt, Firecracker, Wasm components, Cedar).
2. It fills a gap the model vendors leave open: each protects its own agent, nobody offers a neutral control plane, and MCP tells local servers to take credentials from the environment.
3. Buyers already pay for this layer: Docker gives the sandbox CLI away but sells central management of sandbox network, filesystem and MCP policies.
4. The exit market is active, because platform vendors keep buying control points on the agent's path.

The durable moat is how policies get written: learning least-privilege rules from observed runs and enforcing them without breaking tasks. Plan for a **$100M–$750M acquisition**, not a $10B standalone company.

### Buyers

Survey data compiled by CSA: 92% lack full visibility into their AI identities, 86% do not enforce access policies for them, and only 38% monitor AI traffic end to end; the recommended action is "time-bound, just-in-time credentials scoped to the specific resources their task requires" plus SIEM capture of tool-call sequences ([CSA Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/)). **Proposal.** Two ideal customer profiles: platform and devex teams want a zero-friction `broker run` and CI action (served by the Apache-2.0 CLI); CISOs want inventory, central policy, SIEM export and SOC 2 evidence (served by the commercial control plane).

### Licence and competitors

Daytona went closed-source in June 2026 ([bex.co](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk)) and Docker sbx's licence is "not final" ([INNOQ](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)), which favours a credibly Apache-2.0 data plane ([[ADR-014 Apache-2.0 Endpoint with Commercial ee]]). The two sharpest threats are vendor bundling (Claude Code ships `mask` with SigV4 re-signing) and NVIDIA OpenShell (Apache-2.0, per-binary L7 rules, ~8.7k stars). **Proposal.** Differentiate on container-free laptop mode, minting, identity and learning; interoperate with OpenShell rather than fight it on the sandbox. Risks and mitigations live in [[Risk Register]].

## Credibility is evidence

**Proposal.** Architecture can be copied; evidence cannot. Ship a public bypass corpus, SymCC-gated policy changes and paired utility-and-containment numbers on AgentDyn and SWE-bench, which nobody in the field publishes today ([[Evaluation Harness]], [[SymCC CI Gates]]). The 10-week MVP for 2–3 engineers is in [[MVP Plan]].

## How it connects

- motivated-by:: [[Problem Statement]]
- motivated-by:: [[Gap Analysis]]
- decided-by:: [[ADR-001 Value Lives in the Broker]]
- decided-by:: [[ADR-014 Apache-2.0 Endpoint with Commercial ee]]
- depends-on:: [[Two-Tier Isolation Design]]
- depends-on:: [[Just-in-Time Credential Minting]]
- depends-on:: [[Policy Learning Loop]]
- depends-on:: [[Git Smart-HTTP Adapter]]
- depends-on:: [[Audit Recorder and Event Schema]]
- delivered-by:: [[MVP Plan]]
- evaluated-by:: [[Risk Register]]

## Implications for the build

- Do not spend effort on a new isolation primitive; wrap the vendors' own OS sandboxes and invest in the broker (policy, minting, adapters, audit, learning).
- Every differentiator in the "owned" table needs a demonstrable acceptance test in the milestones: minting in [[M1 Secrets Outside]], learning and audit in [[M2 Policy Audit and Learn]], identity and MCP in [[M3 CI Identity and MCP]].
- Keep everything that runs on the endpoint Apache-2.0; the `ee/` directory is the only commercial code.
- Publish the conformance corpus and evaluation numbers with each release; treat them as product features.
- Never market the product as stopping prompt injection.

## Open questions

- No primary buyer survey specific to coding agents on laptops; willingness to pay separately from vendor-bundled controls is indirect (M&A comps, Aembit's $20/agent price) ([[Open Questions and Unverified Claims]]).
- Whether agent vendors will expose stable egress or hook APIs is unknown; the design wraps the process instead.
- The claim that no neutral product parses git smart-HTTP was not exhaustively verified.

## Sources

- [arXiv 2510.09023](https://arxiv.org/html/2510.09023)
- [Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability); [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)
- [Claude Code sandboxing docs](https://code.claude.com/docs/en/sandboxing); [Docker Sandboxes defaults](https://docs.docker.com/ai/sandboxes/security/defaults/); [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/); [NVIDIA OpenShell](https://github.com/NVIDIA/openshell); [OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)
- [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime); [codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)
- [Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/); [Cursor 2.5](https://cursor.com/changelog/2-5); [Keycard](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/); [Anthropic, Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing); [AWS AgentCore Policy](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)
- [Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)
- [OpenAI](https://openai.com/index/hardening-atlas-against-prompt-injection/); [NCSC](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection); [Firecracker](https://firecracker-microvm.github.io/)
- [SecurityWeek, CalypsoAI](https://www.securityweek.com/f5-to-acquire-calypsoai-for-180-million/); [SecurityWeek, Sept 2025 M&A](https://www.securityweek.com/cybersecurity-ma-roundup-40-deals-announced-in-september-2025/); [Wikipedia: CrowdStrike](https://en.wikipedia.org/wiki/CrowdStrike); [Wikipedia: Palo Alto Networks](https://en.wikipedia.org/wiki/Palo_Alto_Networks); [Palo Alto Networks, Portkey](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-to-acquire-portkey-to-secure-the-rise-of-ai-agents)
- [VentureBeat, E2B](https://venturebeat.com/ai/how-e2b-became-essential-to-88-of-fortune-100-companies-and-raised-21-million/); [SiliconANGLE, Keycard](https://siliconangle.com/2025/10/21/ai-agent-security-startup-keycard-reels-38m/); [Dark Reading](https://www.darkreading.com/cybersecurity-operations/ai-security-spending-jumps-fear-outpaces-proof-value); [BCG](https://www.bcg.com/publications/2026/cybersecurity-spending-ai-threat-trends)
- [MarketsandMarkets](https://www.marketsandmarkets.com/PressReleases/agentic-ai-security.asp); [SNS Insider](https://www.snsinsider.com/reports/ai-agent-security-market-10649)
- [SiliconANGLE, SailPoint–Entro](https://siliconangle.com/2026/06/15/sailpoint-acquires-ai-agent-security-startup-entro-reported-200m/); [TechCrunch, Okta–Permiso](https://techcrunch.com/2026/07/30/okta-buys-ai-security-startup-permiso-source-says-for-about-200m/)
- [CSA Labs](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-governance-framework-gap-20260403/); [bex.co](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk); [INNOQ](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/); [Leash](https://github.com/strongdm/leash); [MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)
