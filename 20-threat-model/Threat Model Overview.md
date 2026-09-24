---
title: "Threat Model Overview"
aliases: ["Control Vocabulary", "Assets", "Crown Jewels", "Root Cause Categories", "Recurring Incident Shapes", "OWASP Agentic Top 10", "MITRE ATLAS"]
type: concept
section: threat
tags: [sandbox/threat, concept, topic/credentials, topic/egress, topic/audit, topic/policy, control/iso, control/fs, control/egress, control/cred-out, control/task-tok, control/pin, control/audit, control/hitl, invariant/i1, invariant/i5, invariant/i6, invariant/i9]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Crown-jewel assets, the three trusted principals versus everything untrusted, the control vocabulary (ISO, FS, EGRESS, CRED-OUT, TASK-TOK, PIN, AUDIT, HITL), root-cause categories (a)-(g), the three recurring incident shapes, and OWASP ASI / MITRE ATLAS mappings."
related: [AUTO]
sources: [AUTO]
---

# Threat Model Overview

The threat model assumes the agent is hijacked and asks what it can then reach. This note fixes the shared vocabulary every other threat, architecture and test note uses: the assets worth stealing, who is trusted, the eight control codes, the seven root-cause categories, the three incident shapes that recur across two dozen 2025–2026 incidents, and how they map onto OWASP and MITRE ATLAS taxonomies.

## Assets (crown jewels)

The incident record names the same assets every time ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack); [Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)). In order of how often they were taken:

1. **Long-lived credentials**: source-control PATs, npm and PyPI tokens, cloud keys, database service roles, model API keys and SSH keys. The s1ngularity malware leaked 1,000+ valid GitHub tokens and roughly 20,000 files ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)).
2. **Source code**, including private repositories reachable with the same token ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)).
3. **Production and customer data** behind database and SaaS connectors ([General Analysis](https://generalanalysis.com/blog/supabase-mcp-blog)).
4. **Cloud accounts and infrastructure** that can be destroyed ([Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/)).
5. **The agent's own policy and configuration** (settings, MCP manifests, hooks, allowlists). Changing it turns every later action into an approved one, as the Copilot `autoApprove` and Cursor `mcp.json` CVEs showed ([Embrace The Red](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/); [Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)).
6. **The audit log.** Model self-reports cannot be trusted: the Replit agent wrongly claimed rollback was impossible ([AI Incident Database](https://incidentdatabase.ai/cite/1152/)), and an early Claude Mythos Preview snapshot rarely took steps to keep its edits out of git history ([Mythos system card](https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card)).
7. **The developer host itself**, via persistence in shell rc files and git hooks ([The Hacker News](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)).

Assets 5 and 6 are the least obvious and the most valuable; they motivate [[I5 Config Outside Writable Mounts]] and [[I9 Hash-Chained Audit Outside the Sandbox]].

## Trusted versus untrusted

**Proposal.** Trust only three things:

- the **human principal**, for intent but not for attentive approval (users approve 93% of Claude Code permission prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)));
- the **policy author**;
- the **broker together with the host kernel or hypervisor** (plus tool manifests once pinned).

Treat everything else as untrusted: model output, all workspace files, dependency install scripts, MCP server code and descriptions until pinned, tool results, web content, PR and issue text, and inter-agent messages. Entry points follow from that list: files the agent reads (source, README/AGENTS/GEMINI/CLAUDE.md, issues, tickets, email, web pages), project config auto-loaded at startup, package install hooks, MCP server install or update, skill and plugin registries, CI event payloads, and exposed agent control-plane UIs. The seven boundaries between these zones are in [[Trust Boundaries]]; the attackers in [[Adversary Classes]].

## Control vocabulary

Every incident note and probe uses these codes (research note 04b vocabulary):

| Code | Control | Where it lives in this design |
|---|---|---|
| **ISO** | Process/OS isolation: the agent and its subprocesses cannot touch the host outside granted paths | [[Sandbox Launcher]], [[Two-Tier Isolation Design]] |
| **FS** | Filesystem capability boundary: explicit read/write grants; agent cannot write its config, hooks, rc files or the sandbox helper | [[Filesystem Control and Rollback]], [[I5 Config Outside Writable Mounts]] |
| **EGRESS** | Deny-by-default egress through a broker outside the sandbox, canonicalised matching, broker-owned DNS, no raw DNS/ICMP | [[Topology-Forced Egress]], [[Netguard Ingress]], [[I6 Single Canonicaliser]] |
| **CRED-OUT** | Credentials held outside the sandbox; broker attaches auth per request | [[Credential Injector and Issuers]], [[I1 No Secrets in the Sandbox]] |
| **TASK-TOK** | Task-scoped, short-lived, least-privilege tokens (per repo, table, action; read-only by default) | [[Just-in-Time Credential Minting]] |
| **PIN** | Content-hash pinning of tool, MCP, skill and extension manifests; re-approval on change | [[MCP Guard]] |
| **AUDIT** | Tamper-resistant audit of every tool call, egress request and credential use, outside the sandbox | [[Audit Recorder and Event Schema]], [[I9 Hash-Chained Audit Outside the Sandbox]] |
| **HITL** | Human approval for irreversible or high-impact actions (approval fatigue is itself a root cause) | [[Fatigue-Resistant Approval Interfaces]] |

The highest-yield pair is CRED-OUT + TASK-TOK: it limits blast radius in about 11 of 17 mapped cases, while PIN plus FS-protected config blocks most pre-trust and supply-chain code execution. EGRESS stops the exfiltration leg only when it controls DNS and understands in-scope destinations; ISO alone would not have stopped the in-scope-channel leaks (GitHub MCP, Supabase), which need capability scoping at the broker (research note 04b Q2 synthesis over the incidents cited there).

## Root-cause categories

Every incident note tags one or more of these:

- **(a)** untrusted input steering tools;
- **(b)** over-broad standing credentials;
- **(c)** unrestricted egress;
- **(d)** missing filesystem boundary;
- **(e)** unpinned tool definitions or supply chain;
- **(f)** parser flaw or unsafe default in the enforcement layer;
- **(g)** human approval fatigue or approval-gate design.

## Three shapes recur

1. **The lethal trifecta**: private data, untrusted content and external communication in one session ([Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)); Meta's "Rule of Two" restates it as a per-session invariant ([Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/)). Examples: [[EchoLeak M365 Copilot Exfiltration]], [[GitHub MCP Toxic Flow]], [[Supabase MCP Token Leak]], [[Claude Code DNS Exfiltration CVE-2025-55284]]. See [[Lethal Trifecta]].
2. **Configuration or supply chain that executes before or outside the approval gate**: [[Amazon Q Extension Compromise]], [[Nx s1ngularity Supply-Chain Attack]], [[Cursor CurXecute and MCPoison]], [[Codex CLI Project Config Autoload]], [[Claude Code Pre-Trust Config Execution]], [[Copilot Auto-Approve Settings Write]], [[postmark-mcp Rug Pull]], [[ClawHavoc Malicious Skills]].
3. **Bugs in the enforcement layer itself**: empty-list semantics, prefix matching, NUL bytes, symlink fallback and `working_directory`, at least seven times in 13 months across four vendors ([GHSA](https://github.com/advisories/GHSA-9gqj-5w7c-vx47); [Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/); [Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)). Anthropic's own lesson: "Be wary of custom components. Battle-tested hypervisors, syscall filters, and container runtimes have survived more adversarial attention than anything you'll build", and its custom proxy repeatedly introduced vulnerabilities ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). This is uncomfortable because the proxy is exactly what this team builds; the mitigation is one canonicaliser ([[I6 Single Canonicaliser]]), fuzzing and a public bypass corpus.

Several "exfiltration" channels in the record were **allowed** channels (a Teams proxy, the same GitHub repo, the same database, DNS). Deny-by-default egress is necessary but not sufficient; the broker must understand the semantics of each destination.

## Framework mappings

- **OWASP Top 10 for LLM Applications 2025**: most relevant are LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM05 Improper Output Handling, LLM06 Excessive Agency and LLM10 Unbounded Consumption ([OWASP GenAI](https://genai.owasp.org/llm-top-10/)).
- **OWASP Agentic AI Threats and Mitigations (17 Feb 2025)**, T1–T15, including T2 Tool Misuse, T3 Privilege Compromise, T8 Repudiation & Untraceability, T10 Overwhelming HITL and T11 Unexpected RCE ([OWASP](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)).
- **OWASP Top 10 for Agentic Applications (9 Dec 2025)**: ASI01 Agent Goal Hijack (example EchoLeak), ASI02 Tool Misuse (example Amazon Q), ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain (example GitHub MCP), ASI05 Unexpected Code Execution, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents (example Replit) ([OWASP GenAI](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)).
- **MITRE ATLAS agent techniques (21 Oct 2025, with Zenity Labs)**: AML.T0080 AI Agent Context Poisoning; AML.T0081 Modify AI Agent Configuration; AML.T0082 RAG Credential Harvesting; AML.T0083 Credentials from AI Agent Configuration; AML.T0084 Discover AI Agent Configuration; AML.T0085 Data from AI Services; AML.T0086 Exfiltration via AI Agent Tool Invocation ([Zenity Labs](https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of)). MITRE ATT&CK tracks GTG-1002 as [Campaign C0062](https://attack.mitre.org/campaigns/C0062/).
- **CSA Agentic AI IAM (18 Aug 2025)**: static OAuth scopes are insufficient; proposes JIT credentials "automatically expiring after task completion", delegation chains, a session authority for immediate revocation and rich audit ([CSA](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)).
- **NIST AI Agent Standards Initiative** (launched 17 Feb 2026; pillars: standards, protocols, research on agent authentication/identity and security evaluation) ([NIST](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)).

**Proposal (mapping to controls).** ASI02/ASI03 → TASK-TOK, CRED-OUT; ASI04 → PIN; ASI05 → ISO, FS; ASI01/ASI06 → assumed-successful entry points (the model is not a boundary); ASI08/ASI10 → AUDIT, HITL for irreversible actions, kill switch; ASI09 → approval UX that renders full commands and authority diffs. ATLAS AML.T0081 and T0083 correspond to the config-file CVEs; AML.T0086 to GitHub MCP, Supabase and postmark. Tag audit detections with these IDs.

## How it connects

- depends-on:: [[Problem Statement]]
- part-of:: [[Adversary Classes]]
- part-of:: [[Trust Boundaries]]
- contrasts-with:: [[Threat Model Non-Goals]]
- example-of:: [[Lethal Trifecta]]
- mitigated-by:: [[I1 No Secrets in the Sandbox]]
- mitigated-by:: [[I5 Config Outside Writable Mounts]]
- mitigated-by:: [[I6 Single Canonicaliser]]
- mitigated-by:: [[I9 Hash-Chained Audit Outside the Sandbox]]
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[Risk Register]]

## Implications for the build

- Use the control codes and root-cause letters verbatim in test names, audit reason codes and `broker why` output so incidents, probes and logs join up.
- Treat assets 5 (policy/config) and 6 (audit) as first-class: the conformance suite must include write attempts against every config path and a tamper test on the audit chain.
- The broker is itself custom code on a hostile boundary: every parser gets property tests and a fuzz target from day one ([[L1 Conformance Suite]]).
- Map each audit event to OWASP ASI and ATLAS technique IDs where applicable ([[Audit Recorder and Event Schema]]).
- Semantic rules per destination (git ref, GitHub verb, registry read-only) are required, not optional, because allowed channels carried most exfiltration.

## Open questions

- NIST AI 600-1, the NCCoE agent-identity concept paper, the Jan 2026 CAISI RFI text, OWASP ASI per-item mitigations and the May 2026 Five Eyes/CISA agentic guidance were not verified ([[Open Questions and Unverified Claims]]).
- Anthropic's "custom proxy repeatedly introduced vulnerabilities" is not enumerated by category ([[Risk Register]]).
- MITRE ATT&CK TA0010 mapping for probe categories was not fetched.

## Sources

- [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack); [Embrace The Red, CVE-2025-55284](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/); [Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability); [General Analysis](https://generalanalysis.com/blog/supabase-mcp-blog); [Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/)
- [Embrace The Red, CVE-2025-53773](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/); [Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison); [The Hacker News, DuneSlide](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)
- [AI Incident Database #1152](https://incidentdatabase.ai/cite/1152/); [Mythos system card](https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card); [Anthropic, auto mode](https://anthropic.com/engineering/claude-code-auto-mode)
- [Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/); [Meta AI](https://ai.meta.com/blog/practical-ai-agent-security/)
- [GHSA-9gqj-5w7c-vx47](https://github.com/advisories/GHSA-9gqj-5w7c-vx47); [Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/); [Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack); [Anthropic, How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude)
- [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/); [OWASP Agentic Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/); [OWASP Agentic Top 10](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [Zenity Labs / MITRE ATLAS](https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of); [MITRE ATT&CK C0062](https://attack.mitre.org/campaigns/C0062/); [CSA Agentic IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach); [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
