---
title: "Bibliography"
aliases: ["Sources", "References"]
type: source-index
section: meta
tags: [sandbox/meta, source-index]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Every source URL cited in the report (plus the scoreboard sandboxing section), grouped by topic, each pointing to the notes that use it."
related: ["[[MOC Problem]]", "[[MOC Threat Model]]", "[[MOC Research]]", "[[MOC Primitives]]", "[[MOC Identity]]", "[[MOC Architecture]]", "[[MOC Policy]]", "[[MOC Landscape]]", "[[MOC Build]]", "[[MOC Decisions]]", "[[MOC Open Problems]]"]
sources: []
---

# Bibliography

All 154 distinct URLs cited in the synthesized report *Agent sandboxing solution foundation* (September 2026), grouped by topic, plus the URLs from the scoreboard's sandboxing section. Each entry points to the note(s) that should cite it. The research-note files (`01`-`05`) cite further sources; writers may add those to a note's `sources:` and should append them here under the matching heading.

Source-quality flags to carry into notes: secondary sources (emirb, Penligent, The Hacker News for DuneSlide, Adversa for OpenClaw, SC Media/PointGuard for the Amazon Q payload) and single-source claims (the NUL-byte bypass, the July 2026 Artifactory incident) must be tagged `evidence/secondary` or `evidence/single-source` and listed in [[Open Questions and Unverified Claims]].

## Adaptive attacks and in-band defenses

- [Adaptive evaluation of out-of-band defenses (arXiv 2606.26479)](https://arxiv.org/abs/2606.26479) → [[The Attacker Moves Second]], [[Progent]], [[Adaptive Evaluation of Deterministic Monitors]], [[Red-Team Plan]]
- [NIST CAISI: red-teaming competition](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition) → [[Problem Statement]], [[The Attacker Moves Second]]
- [The Attacker Moves Second (arXiv 2510.09023)](https://arxiv.org/html/2510.09023) → [[The Attacker Moves Second]], [[Problem Statement]], [[I3 Probabilistic Components Only Narrow]]

## Agent defense systems (capabilities, IFC, privilege control)

- [ACE (arXiv 2504.20984)](https://arxiv.org/abs/2504.20984) → [[ACE and IsolateGPT]]
- [Agent privilege separation in OpenClaw (arXiv 2603.13424)](https://arxiv.org/abs/2603.13424) → [[Information Flow Control]]
- [AgentArmor (arXiv 2508.01249)](https://arxiv.org/abs/2508.01249) → [[Information Flow Control]]
- [AgentSentinel (arXiv 2509.07764)](https://arxiv.org/html/2509.07764v1) → [[AgentSentinel]]
- [AgentSpec (arXiv 2503.18666)](https://arxiv.org/abs/2503.18666) → [[AgentSpec]], [[ADR-011 Verified Policy Learning Loop]]
- [CaMeL abstract (arXiv 2503.18813)](https://arxiv.org/abs/2503.18813) → [[CaMeL]], [[Evaluation Harness]], [[Product Thesis]]
- [CaMeL full text (arXiv 2503.18813)](https://arxiv.org/html/2503.18813) → [[CaMeL]], [[Object Capabilities]], [[Threat Model Non-Goals]]
- [CaMeLs Can Use Computers Too (arXiv 2601.09923)](https://arxiv.org/html/2601.09923v1) → [[CaMeL]], [[Branch-Steering Resistance]]
- [Conseca (arXiv 2501.17070)](https://arxiv.org/html/2501.17070v3) → [[Conseca]]
- [DRIFT (arXiv 2506.12104)](https://arxiv.org/html/2506.12104v2) → [[DRIFT]], [[CaMeL]]
- [FIDES (arXiv 2505.23643)](https://arxiv.org/html/2505.23643) → [[FIDES]], [[Object Capabilities]]
- [FlowSeal (arXiv 2609.14003)](https://arxiv.org/html/2609.14003) → [[Information Flow Control]], [[Credential Broker as Label Authority]]
- [IsolateGPT (arXiv 2403.04960)](https://arxiv.org/abs/2403.04960) → [[ACE and IsolateGPT]]
- [MiniScope (arXiv 2512.11147)](https://arxiv.org/abs/2512.11147) → [[MiniScope]]
- [Progent (arXiv 2504.11703)](https://arxiv.org/html/2504.11703) → [[Progent]]
- [Progent v3 (arXiv 2504.11703v3)](https://arxiv.org/html/2504.11703v3) → [[Progent]], [[SymCC CI Gates]], [[Evaluation Harness]]
- [RTBAS (arXiv 2502.08966)](https://arxiv.org/abs/2502.08966) → [[Information Flow Control]]
- [SkillGuard (arXiv 2608.30041)](https://arxiv.org/abs/2608.30041) → [[Information Flow Control]]

## Foundations: capabilities, tokens, design patterns

- [Biscuit introduction](https://doc.biscuitsec.org/getting-started/introduction.html) → [[Macaroons and Biscuit]], [[Internal Grant JWT]]
- [Design Patterns for Securing LLM Agents (arXiv 2506.08837)](https://arxiv.org/html/2506.08837) → [[Design Patterns for Securing LLM Agents]]
- [Meta AI: Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/) → [[Agents Rule of Two]], [[Trifecta Session Labels]]
- [Miller, Robust Composition (thesis)](http://www.erights.org/talks/thesis/) → [[Object Capabilities]], [[Revocable Sub-Agent Delegation]]
- [Simon Willison: new prompt-injection papers (Rule of Two critique)](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/) → [[Agents Rule of Two]], [[Trifecta Session Labels]]
- [Simon Willison: the lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) → [[Lethal Trifecta]]

## Benchmarks and evaluation methodology

- [AgentDojo (arXiv 2406.13352)](https://arxiv.org/abs/2406.13352) → [[AgentDyn]], [[L2 Injection Benchmarks]]
- [AgentDyn (arXiv 2602.03117)](https://arxiv.org/html/2602.03117v1) → [[AgentDyn]], [[L2 Injection Benchmarks]], [[Dynamic Tasks Without Control-Flow Hijack]]
- [Anthropic: Claude Code auto mode](https://anthropic.com/engineering/claude-code-auto-mode) → [[Evaluation Harness]], [[L4 Product Metrics]], [[Fatigue-Resistant Approval Interfaces]], [[Claude Code and sandbox-runtime]]
- [HTTP Garden (arXiv 2405.17737)](https://arxiv.org/abs/2405.17737) → [[L1 Conformance Suite]]
- [SandboxEscapeBench (arXiv 2603.02277)](https://arxiv.org/html/2603.02277v1) → [[SandboxEscapeBench]]
- [SWE-bench harness](https://www.swebench.com/SWE-bench/reference/harness/) → [[L3 Real-Work Utility]]
- [Terminal-Bench 2.0 announcement](https://www.tbench.ai/news/announcement-2-0) → [[L3 Real-Work Utility]]
- [UK AISI: can AI agents escape their sandboxes](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities) → [[SandboxEscapeBench]], [[Adversary Classes]]
- [Vercel: $1M hacker challenge](https://vercel.com/blog/one-million-dollar-hacker-challenge-for-vercel-sandbox) → [[Red-Team Plan]], [[Vercel Sandbox]]
- [WASP (arXiv 2504.18575)](https://arxiv.org/abs/2504.18575v2) → [[L2 Injection Benchmarks]], [[Red-Team Plan]]

## Incidents, advisories and post-mortems

- [Adversa: OpenClaw security 101 (citing Censys)](https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/) → [[OpenClaw Exposure and Token Theft]], [[Adversary Classes]]
- [AI Incident Database #1152 (Replit)](https://incidentdatabase.ai/cite/1152/) → [[Replit Production Database Deletion]]
- [Anthropic: GTG-1002 report](https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf) → [[GTG-1002 AI-Orchestrated Espionage]], [[Adversary Classes]]
- [Anthropic: how we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude) → [[Claude Cowork Allowed-Domain Abuse]], [[I7 Reject Foreign Credentials]], [[Risk Register]], [[Red-Team Plan]], [[Threat Model Overview]]
- [Aonan Guan: NUL-byte allowlist bypass](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/) → [[sandbox-runtime SOCKS NUL-Byte Bypass]], [[Hostname Canonicaliser]]
- [AWS-2025-015 (Amazon Q)](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/) → [[Amazon Q Extension Compromise]]
- [axeploit: the Hugging Face sandbox escape (unverified)](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53) → [[July 2026 Artifactory Egress Incident]], [[Broker DNS Resolver]]
- [Claude Mythos Preview system card (LessWrong repost)](https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card) → [[Mythos Preview Evaluation Escape]], [[I9 Hash-Chained Audit Outside the Sandbox]]
- [Cymulate: CVE-2025-54794/54795](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/) → [[Claude Code Path and Command Injection CVEs]]
- [EchoLeak paper (arXiv 2509.10540)](https://arxiv.org/html/2509.10540v1) → [[EchoLeak M365 Copilot Exfiltration]]
- [Embrace The Red: Claude Code DNS exfiltration](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/) → [[Claude Code DNS Exfiltration CVE-2025-55284]], [[Broker DNS Resolver]]
- [Embrace The Red: Copilot RCE via prompt injection](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) → [[Copilot Auto-Approve Settings Write]]
- [Fortune: Replit wiped database](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/) → [[Replit Production Database Deletion]]
- [General Analysis: Supabase MCP](https://generalanalysis.com/blog/supabase-mcp-blog) → [[Supabase MCP Token Leak]]
- [GHSA-9gqj-5w7c-vx47 (sandbox-runtime empty allowlist)](https://github.com/advisories/GHSA-9gqj-5w7c-vx47) → [[sandbox-runtime Empty Allowlist Bypass]]
- [GHSA-xrxf-jgv3-qmrm (Codex CLI)](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm) → [[Codex CLI Project Config Autoload]]
- [Invariant Labs: GitHub MCP vulnerability](https://invariantlabs.ai/blog/mcp-github-vulnerability) → [[GitHub MCP Toxic Flow]]
- [NVD: CVE-2026-21852](https://nvd.nist.gov/vuln/detail/CVE-2026-21852) → [[Claude Code Pre-Trust Config Execution]], [[Registry and LLM API Adapters]]
- [Nx: s1ngularity postmortem](https://nx.dev/blog/s1ngularity-postmortem) → [[Nx s1ngularity Supply-Chain Attack]]
- [Penligent: Claude Code sandbox bypass](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/) → [[sandbox-runtime SOCKS NUL-Byte Bypass]], [[Risk Register]]
- [Tenable: CurXecute and MCPoison FAQ](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison) → [[Cursor CurXecute and MCPoison]]
- [The Hacker News: 341 malicious ClawHub skills](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html) → [[ClawHavoc Malicious Skills]]
- [The Hacker News: Cursor DuneSlide](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html) → [[Cursor DuneSlide Sandbox Escape]]
- [The Hacker News: first malicious MCP server](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html) → [[postmark-mcp Rug Pull]]
- [The Hacker News: GitLost](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html) → [[GitLost GitHub Agentic Workflows Leak]]
- [The Next Web: Mythos escape (conflicting account)](https://thenextweb.com/news/anthropics-most-capable-ai-escaped-its-sandbox-and-emailed-a-researcher-so-the-company-wont-release-it) → [[Mythos Preview Evaluation Escape]]
- [Tracebit: Gemini CLI hijack](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack) → [[Gemini CLI Prefix Allowlist Bypass]]
- [Wiz: s1ngularity supply-chain attack](https://www.wiz.io/blog/s1ngularity-supply-chain-attack) → [[Nx s1ngularity Supply-Chain Attack]], [[Threat Model Overview]]

## Frameworks and model-behaviour research

- [METR: frontier risk report](https://metr.org/blog/2026-05-19-frontier-risk-report/) → [[Adversary Classes]], [[I8 No Flag Disables Isolation]], [[Fatigue-Resistant Approval Interfaces]]
- [METR: recent reward hacking](https://metr.org/blog/2025-06-05-recent-reward-hacking/) → [[Adversary Classes]]
- [OWASP: Agentic AI threats and mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/) → [[Threat Model Overview]], [[Fatigue-Resistant Approval Interfaces]]

## Isolation primitives

- [apple/containerization #737 (sandbox-exec deprecation)](https://github.com/apple/containerization/issues/737) → [[Seatbelt]], [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]], [[Apple Virtualization Framework]]
- [AWS bulletin 2026-003 (Firecracker jailer)](https://aws.amazon.com/security/security-bulletins/rss/2026-003-aws/) → [[Firecracker]]
- [Bytecode Alliance: WASI 0.3](https://bytecodealliance.org/articles/WASI-0.3) → [[Wasmtime and WASI]]
- [Bytecode Alliance: Wasmtime security advisories](https://bytecodealliance.org/articles/wasmtime-security-advisories) → [[Wasmtime and WASI]], [[Risk Register]]
- [CNCF: runc breakout vulnerabilities (Nov 2025)](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/) → [[Container Runtimes and Escape History]]
- [Codex linux-sandbox README (raw)](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md) → [[bubblewrap]], [[OpenAI Codex CLI]], [[seccomp-bpf]]
- [Codex linux-sandbox README (repo)](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md) → [[OpenAI Codex CLI]], [[Tech Stack]]
- [cvefeed: CVE-2026-5747 (Firecracker virtio-PCI)](https://cvefeed.io/vuln/detail/CVE-2026-5747) → [[Firecracker]]
- [emirb: microVMs in 2026 (secondary)](https://emirb.github.io/blog/microvm-2026/) → [[Cloud Hypervisor]], [[gVisor]], [[Firecracker]]
- [Firecracker SPECIFICATION.md](https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md) → [[Firecracker]]
- [GitHub: apple/containerization](https://github.com/apple/containerization) → [[Apple Virtualization Framework]]
- [gVisor platforms](https://gvisor.dev/docs/architecture_guide/platforms/) → [[gVisor]]
- [kernel.org: Landlock](https://docs.kernel.org/userspace-api/landlock.html) → [[Landlock]]
- [lib.rs: hakoniwa](https://lib.rs/crates/hakoniwa) → [[Tech Stack]], [[bubblewrap]]
- [LSM list: Landlock UDP series (Jun 2026)](https://ratatoskr.run/linux-security-module/2026/06/17121634/t) → [[Landlock]]
- [openai/codex #215 (sandbox-exec deprecated)](https://github.com/openai/codex/issues/215) → [[Seatbelt]]
- [rust-landlock ABI enum](https://landlock.io/rust-landlock/landlock/enum.ABI.html) → [[Landlock]]

## Egress, proxy and TLS mechanics

- [dev.to: kernel-level egress control, 14 ms overhead](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o) → [[Topology-Forced Egress]], [[TLS Termination and Per-Session CA]], [[L4 Product Metrics]]
- [GitHub: hudsucker](https://github.com/omjadas/hudsucker) → [[Tech Stack]], [[ADR-015 Rust for the Endpoint and Custom Proxy]]
- [SafeYolo #620 (Rust rewrite)](https://github.com/craigbalding/safeyolo/issues/620) → [[Tech Stack]], [[ADR-015 Rust for the Endpoint and Custom Proxy]]
- [Vercel docs: sandbox firewall](https://vercel.com/docs/sandbox/concepts/firewall) → [[Vercel Sandbox]], [[TLS Termination and Per-Session CA]], [[Broker DNS Resolver]], [[ADR-006 Deny Unmatched L7 Requests]]

## Identity and token standards

- [AWS STS AssumeRole API](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) → [[AWS STS Session Policies]]
- [GCP: downscoping short-lived credentials](https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials) → [[GCP Credential Access Boundaries]]
- [GitHub REST: create an installation access token](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app) → [[GitHub App Installation Tokens]]
- [GitHub: personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) → [[GitHub App Installation Tokens]]
- [IETF: AAuth protocol draft](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol) → [[Transaction Tokens and Agent Auth Drafts]]
- [IETF: draft-klrc-aiagent-auth](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) → [[Transaction Tokens and Agent Auth Drafts]]
- [IETF: Transaction Tokens draft-08](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08) → [[Transaction Tokens and Agent Auth Drafts]], [[Internal Grant JWT]]
- [Microsoft Learn: Entra agent OBO flow](https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow) → [[Entra Agent ID]]
- [Okta: XAA OIDC resource](https://developer.okta.com/blog/2026/08/24/xaa-oidc-resource) → [[Okta Cross App Access]]
- [RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) → [[RFC 8693 Token Exchange]]
- [RFC 8707 Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html) → [[MCP Authorization Spec]]
- [RFC 9396 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396) → [[RFC 9396 Rich Authorization Requests]]
- [RFC 9449 DPoP](https://www.rfc-editor.org/rfc/rfc9449) → [[DPoP and mTLS-Bound Tokens]]
- [Start With Identity: agent identity gets a protocol](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/) → [[Okta Cross App Access]], [[Gap Analysis]]
- [WorkOS: ID-JAG Cross App Access](https://workos.com/blog/id-jag-cross-app-access) → [[Okta Cross App Access]]

## Model Context Protocol

- [Invariant Labs: MCP tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) → [[MCP Guard]], [[postmark-mcp Rug Pull]]
- [MCP Authorization (latest)](https://modelcontextprotocol.io/specification/latest/basic/authorization) → [[MCP Authorization Spec]], [[MCP Guard]]
- [MCP Security Best Practices (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) → [[MCP Authorization Spec]], [[Object Capabilities]]
- [WorkOS: MCP 2026 spec and agent authentication](https://workos.com/blog/mcp-2026-spec-agent-authentication) → [[MCP Authorization Spec]]

## Policy language, analysis and learning

- [AWS: Cedar Analysis open-source tools](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies/) → [[SymCC CI Gates]], [[Cedar]]
- [AWS: IAM Access Analyzer policy generation](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/) → [[Policy Learning Loop]]
- [AWS: why AgentCore Policy chose Cedar](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/) → [[AWS AgentCore]], [[Cedar]], [[Policy Learning Loop]]
- [Cedar paper (arXiv 2403.04651)](https://arxiv.org/html/2403.04651) → [[Cedar]]
- [cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md) → [[Cedar]]
- [CNCF: Security Profiles Operator v1.0](https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/) → [[Policy Learning Loop]]
- [docs.rs: cedar-policy-symcc](https://docs.rs/cedar-policy-symcc) → [[SymCC CI Gates]]
- [GitHub: Invariant guardrails](https://github.com/invariantlabs-ai/invariant) → [[Trifecta Session Labels]]
- [Teleport: benchmarking policy languages](https://goteleport.com/blog/benchmarking-policy-languages/) → [[Cedar]], [[ADR-007 Cedar with a TOML Front-End]]

## Products and landscape

- [Aembit: IAM for Agentic AI GA](https://aembit.io/blog/aembit-iam-for-agentic-ai-is-now-generally-available/) → [[Agent Identity Brokers]], [[ADR-014 Apache-2.0 Endpoint with Commercial ee]]
- [Andrew Lock: AI agents in a Docker Sandbox microVM](https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/) → [[Docker Sandboxes]], [[Git Smart-HTTP Adapter]]
- [Anthropic: Claude Code sandboxing](https://anthropic.com/engineering/claude-code-sandboxing) → [[Claude Code and sandbox-runtime]], [[Evaluation Harness]], [[Git Smart-HTTP Adapter]]
- [Anthropic: Claude Code sandboxing (www)](https://www.anthropic.com/engineering/claude-code-sandboxing) → [[Claude Code and sandbox-runtime]], [[Git Smart-HTTP Adapter]], [[Product Thesis]]
- [Arcade: authorized tool calling](https://docs.arcade.dev/en/home/auth/auth-tool-calling) → [[Agent Identity Brokers]]
- [AWS AgentCore Runtime](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-how-it-works.html) → [[AWS AgentCore]]
- [AWS AgentCore: workload access token](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html) → [[AWS AgentCore]]
- [bex.co: Daytona goes closed source](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk) → [[Cloud Sandbox Runtimes]], [[ADR-014 Apache-2.0 Endpoint with Commercial ee]], [[Gap Analysis]]
- [Claude Code docs: sandboxing](https://code.claude.com/docs/en/sandboxing) → [[Claude Code and sandbox-runtime]], [[Sentinel Swap Pattern]], [[I2 Fail-Closed Launch]]
- [Cloudflare: sandbox auth and outbound workers](https://blog.cloudflare.com/sandbox-auth/) → [[Cloud Sandbox Runtimes]], [[TLS Termination and Per-Session CA]]
- [Codex docs: sandboxing](https://learn.chatgpt.com/codex/sandboxing) → [[OpenAI Codex CLI]]
- [Codex KB: network security and requirements.toml](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/) → [[OpenAI Codex CLI]], [[Native Config Exporters]]
- [Cursor 2.5 changelog](https://cursor.com/changelog/2-5) → [[Cursor and Gemini CLI]]
- [Docker blog: Docker Sandboxes launch](https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/) → [[Docker Sandboxes]]
- [Docker Sandboxes architecture](https://docs.docker.com/ai/sandboxes/architecture/) → [[Docker Sandboxes]], [[Filesystem Control and Rollback]]
- [Docker Sandboxes default security posture](https://docs.docker.com/ai/sandboxes/security/defaults/) → [[Docker Sandboxes]], [[Sentinel Swap Pattern]]
- [docker/desktop-feedback #130](https://github.com/docker/desktop-feedback/issues/130) → [[Docker Sandboxes]]
- [E2B: internet access](https://docs.e2b.dev/network/internet-access.md) → [[Cloud Sandbox Runtimes]], [[TLS Termination and Per-Session CA]]
- [Gemini CLI: sandbox](https://geminicli.com/docs/cli/sandbox/) → [[Cursor and Gemini CLI]]
- [GitHub: anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) → [[Claude Code and sandbox-runtime]], [[bubblewrap]], [[Seatbelt]], [[Topology-Forced Egress]]
- [GitHub: docker/mcp-gateway](https://github.com/docker/mcp-gateway) → [[MCP Gateways]]
- [GitHub: Infisical Agent Vault](https://github.com/Infisical/agent-vault) → [[Local Credential Proxies]]
- [GitHub: kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) → [[Cloud Sandbox Runtimes]], [[Architecture Overview]]
- [GitHub: microsoft/wassette](https://github.com/microsoft/wassette) → [[MCP Gateways]], [[Wasmtime and WASI]]
- [GitHub: NVIDIA OpenShell](https://github.com/NVIDIA/openshell) → [[NVIDIA OpenShell]], [[Gap Analysis]]
- [GitHub: StrongDM Leash](https://github.com/strongdm/leash) → [[Local Credential Proxies]], [[Cedar]]
- [INNOQ: trust but sandbox](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/) → [[Docker Sandboxes]]
- [Keycard for coding agents](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/) → [[Agent Identity Brokers]], [[Gap Analysis]]
- [LangChain: LangSmith auth proxy](https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes) → [[Cloud Sandbox Runtimes]], [[Topology-Forced Egress]]
- [openai/codex #22387 (DNS in sandbox)](https://github.com/openai/codex/issues/22387) → [[OpenAI Codex CLI]], [[Broker DNS Resolver]]
- [OpenShell docs: first network policy](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html) → [[NVIDIA OpenShell]], [[Policy Learning Loop]]
- [Runloop: agent gateways](https://docs.runloop.ai/docs/devboxes/agent-gateways) → [[Cloud Sandbox Runtimes]], [[DPoP and mTLS-Bound Tokens]], [[Internal Grant JWT]]
- [Stacklok ToolHive: network isolation](https://docs.stacklok.com/toolhive/guides-cli/network-isolation) → [[MCP Gateways]], [[Topology-Forced Egress]]
- [Vercel: a sandbox without a network boundary](https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox) → [[Vercel Sandbox]], [[Topology-Forced Egress]]
- [Wassette concepts](https://microsoft.github.io/wassette/latest/concepts.html) → [[MCP Gateways]]
- [Zujkowski: the secret-proxying gap](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/) → [[Threat Model Non-Goals]], [[Sentinel Swap Pattern]], [[Gap Analysis]]

## Market context (scoreboard, sandboxing section)

Cited in the scoreboard's 'Agent sandboxing, problem 9' section and its small-team recommendation. URLs that also appear above are repeated here only where the scoreboard uses them for a different claim.

- [OpenAI: hardening Atlas against prompt injection](https://openai.com/index/hardening-atlas-against-prompt-injection/) → [[Problem Statement]], [[The Attacker Moves Second]]
- [NCSC: prompt injection is not SQL injection](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection) → [[Problem Statement]]
- [The Attacker Moves Second (abstract)](https://arxiv.org/abs/2510.09023) → [[The Attacker Moves Second]]
- [Firecracker home page](https://firecracker-microvm.github.io/) → [[Firecracker]]
- [Vercel Sandbox GA](https://vercel.com/blog/vercel-sandbox-is-now-generally-available) → [[Vercel Sandbox]]
- [SecurityWeek: F5 to acquire CalypsoAI](https://www.securityweek.com/f5-to-acquire-calypsoai-for-180-million/) → [[Product Thesis]]
- [SecurityWeek: M&A roundup Sep 2025 (Lakera)](https://www.securityweek.com/cybersecurity-ma-roundup-40-deals-announced-in-september-2025/) → [[Product Thesis]]
- [Wikipedia: CrowdStrike (SGNL)](https://en.wikipedia.org/wiki/CrowdStrike) → [[Product Thesis]]
- [Wikipedia: Palo Alto Networks (CyberArk)](https://en.wikipedia.org/wiki/Palo_Alto_Networks) → [[Product Thesis]]
- [Palo Alto Networks: Portkey acquisition](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-to-acquire-portkey-to-secure-the-rise-of-ai-agents) → [[Product Thesis]]
- [VentureBeat: E2B $21M, 88% of Fortune 100](https://venturebeat.com/ai/how-e2b-became-essential-to-88-of-fortune-100-companies-and-raised-21-million/) → [[Product Thesis]], [[Cloud Sandbox Runtimes]]
- [SiliconANGLE: Keycard $38M](https://siliconangle.com/2025/10/21/ai-agent-security-startup-keycard-reels-38m/) → [[Product Thesis]], [[Agent Identity Brokers]]
- [Dark Reading: AI security spending (24% budget line)](https://www.darkreading.com/cybersecurity-operations/ai-security-spending-jumps-fear-outpaces-proof-value) → [[Product Thesis]], [[Risk Register]]
- [BCG: 23% monitor AI agents](https://www.bcg.com/publications/2026/cybersecurity-spending-ai-threat-trends) → [[Product Thesis]]
- [Gartner: security spending forecast](https://www.gartner.com/en/newsroom/press-releases/2025-07-29-gartner-forecasts-worldwide-end-user-spending-on-information-security-to-total-213-billion-us-dollars-in-2025) → [[Product Thesis]]
- [MarketsandMarkets: agentic AI security market](https://www.marketsandmarkets.com/PressReleases/agentic-ai-security.asp) → [[Product Thesis]]
- [SNS Insider: AI agent security market (implausible)](https://www.snsinsider.com/reports/ai-agent-security-market-10649) → [[Product Thesis]]
- [Fly.io Sprites](https://fly.io/sprites/) → [[Cloud Sandbox Runtimes]]
- [Microsoft: introducing Wassette](https://opensource.microsoft.com/blog/2025/08/06/introducing-wassette-webassembly-based-tools-for-ai-agents/) → [[MCP Gateways]]
- [Docker Sandboxes docs (subscription)](https://docs.docker.com/ai/sandboxes/) → [[Docker Sandboxes]], [[Product Thesis]]
- [GitHub: StrongDM Leash](https://github.com/strongdm/leash) → [[Local Credential Proxies]]
- [MCP Authorization (stdio sentence)](https://modelcontextprotocol.io/specification/latest/basic/authorization) → [[MCP Authorization Spec]]
- [Anthropic: Claude Code sandboxing (84%)](https://www.anthropic.com/engineering/claude-code-sandboxing) → [[Claude Code and sandbox-runtime]]
- [CaMeL (77% vs 84%)](https://arxiv.org/abs/2503.18813) → [[CaMeL]]
- [Invariant Labs: GitHub MCP](https://invariantlabs.ai/blog/mcp-github-vulnerability) → [[GitHub MCP Toxic Flow]]
- [Fortune: Replit](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/) → [[Replit Production Database Deletion]]
- [Wiz: s1ngularity](https://www.wiz.io/blog/s1ngularity-supply-chain-attack) → [[Nx s1ngularity Supply-Chain Attack]]
