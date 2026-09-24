---
title: "Threat Model Non-Goals"
aliases: ["Non-Goals", "Out of Scope"]
type: concept
section: threat
tags: [sandbox/threat, concept, topic/policy, topic/approval, topic/ifc, adversary/a1, adversary/a4]
status: proposal
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Four stated non-goals (misuse inside granted scope, text-only manipulation, host-kernel zero-days in the standard tier, operator abuse only partly addressed) and the residual 'prevents theft, not misuse' risk the design narrows but cannot remove."
related: [AUTO]
sources: [AUTO]
---

# Threat Model Non-Goals

The broker prevents credential theft and unauthorised egress; it does not make a hijacked agent behave well with the authority it legitimately holds. **Proposal:** the shipped threat-model document states four non-goals verbatim so that buyers are not misled, and the design narrows (but cannot remove) the residual risk by making granted authority small, verb-specific and audited.

## The four non-goals

1. **Misuse inside granted scope.** An agent holding a legitimate `contents:write` grant can still push bad code. A proxy "prevents theft but not misuse": an agent with a legitimate `repo:write` token can still act maliciously through the proxy ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)).
2. **Text-only manipulation with no side effect**, such as misrepresenting the content of an email to the user. CaMeL lists this as out of scope too: text-to-text attacks with no data-flow consequence, phishing links shown to users, and fully autonomous operation with no human in the loop ([arXiv 2503.18813](https://arxiv.org/html/2503.18813)). See [[CaMeL]].
3. **Host-kernel zero-days in the standard (process-sandbox) tier.** Seatbelt and bubblewrap share the host kernel; those threats need the VM hard tier ([[Two-Tier Isolation Design]]). SandboxEscapeBench found every successful breakout used previously disclosed vulnerabilities and none at difficulty 4–5 ([arXiv 2603.02277](https://arxiv.org/html/2603.02277v1)), but that is capability evidence at one point in time, not a guarantee.
4. **Operator abuse** is only partly addressed, through hosted-mode egress limits and audit. In [[GTG-1002 AI-Orchestrated Espionage]] the agent platform was the attacker's tool, not the victim ([Anthropic](https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf)). A local broker run by the attacker on the attacker's own machine constrains nothing.

## Why these are real limits, not gaps to be closed later

Deterministic systems share the same residual surface. Progent's authors state that it cannot stop attacks that stay inside least privilege (for example preference manipulation), offers no protection for text-only outputs, and depends on users not making approval errors ([arXiv 2504.11703](https://arxiv.org/html/2504.11703)); see [[Progent]]. The design-patterns paper says most patterns stop control-flow hijack but still allow manipulation of data parameters, and "we believe it is unlikely that general-purpose agents can provide meaningful and reliable safety guarantees" ([arXiv 2506.08837](https://arxiv.org/html/2506.08837)). "Branch steering" makes a valid, pre-approved branch fire via spoofed observations ([arXiv 2601.09923](https://arxiv.org/html/2601.09923v1)); see [[Branch-Steering Resistance]].

Two further residuals follow from the design itself:

- **Allowed domains remain exfiltration channels.** A gist or issue on an allowed github.com, a package registry acting as a proxy, and timing or request-count encoding all remain (research note 01 inference; the registry case is the unverified [[July 2026 Artifactory Egress Incident]] reported by [axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53)). The conformance suite measures covert-channel bandwidth and reports it; it does not claim zero (probe category 11 in [[Conformance Probe Matrix]]).
- **The broker is itself custom code.** Anthropic's custom proxy "repeatedly introduced vulnerabilities" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). The broker's own bugs are in scope as a risk ([[Risk Register]]), not excluded.

## How the design narrows the residual

**Proposal.** None of these removes misuse; each shrinks what misuse can reach.

- **Narrow verbs.** `pr.create` is not `pr.merge`; `contents.write` on one repo under `refs/heads/agent/*`, never force ([[GitHub API Adapter]], [[Git Smart-HTTP Adapter]]). Allowing a PR to be opened while forbidding its merge is a one-line rule.
- **Session labels.** Once a session has read untrusted input and sensitive data, writes and pushes need out-of-band approval ([[Trifecta Session Labels]]). This blocks the public-write step of the GitHub MCP and GitLost flows but not a bad commit to the task's own branch.
- **Approvals only for irreversible verbs,** rendered as authority diffs. Users approve 93% of Claude Code prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)) and OWASP lists "Overwhelming HITL" as T10 ([OWASP](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)), so a prompt is a weak control and must be rare to be meaningful.
- **Small tasks.** A fresh session per task keeps both the grant set and the taint small.
- **Audit.** Misuse that cannot be prevented is attributed to user, agent, task and session outside the sandbox ([[I9 Hash-Chained Audit Outside the Sandbox]]).

## Claims the product must never make

Following the report and research note 05's risk row ("Don't claim to stop injection"):

- never "prevents prompt injection" or "makes agents safe";
- never "zero exfiltration" (covert channels on allowed hosts are measured, not eliminated);
- never "escape-proof" for the standard tier.

Say instead: "limits what a hijacked agent can reach to the task's grants, keeps secrets out of the agent, and records every decision".

## How it connects

- part-of:: [[Threat Model Overview]]
- motivated-by:: [[CaMeL]]
- motivated-by:: [[Progent]]
- example-of:: [[GTG-1002 AI-Orchestrated Espionage]]
- depends-on:: [[Two-Tier Isolation Design]]
- mitigated-by:: [[GitHub API Adapter]]
- mitigated-by:: [[Trifecta Session Labels]]
- evaluated-by:: [[Risk Register]]

## Implications for the build

- `code/docs/threat-model.md` must list the four non-goals verbatim; `broker --help` and the README link it.
- Reviewers reject any code comment, CLI string or doc claiming the broker stops injection or misuse.
- Because misuse inside scope is out of scope, the default grants must be as small as possible: repo-scoped, branch-prefixed, no merge, no publish, no production DDL.
- Report "model complied, broker blocked" separately from end-to-end attack success in every evaluation ([[Red-Team Plan]]), and report covert-channel bandwidth rather than claiming zero.
- Offer the VM hard tier wherever host-kernel zero-days are in the customer's threat model.

## Open questions

- No user study of approval fatigue for agent capability prompts exists; the 93% figure and METR's ~40% survey are the only data ([[Open Questions and Unverified Claims]]; [[Fatigue-Resistant Approval Interfaces]]).
- No white-box adaptive attack against any deterministic monitor has been published ([[Adaptive Evaluation of Deterministic Monitors]]).

## Sources

- [Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)
- [arXiv 2503.18813, CaMeL](https://arxiv.org/html/2503.18813); [arXiv 2504.11703, Progent](https://arxiv.org/html/2504.11703); [arXiv 2506.08837, Design Patterns](https://arxiv.org/html/2506.08837); [arXiv 2601.09923](https://arxiv.org/html/2601.09923v1)
- [arXiv 2603.02277, SandboxEscapeBench](https://arxiv.org/html/2603.02277v1)
- [Anthropic, GTG-1002](https://www-cdn.anthropic.com/d7dd50dd1185f59be051b307150d877f2b82bd2c.pdf); [Anthropic, How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude); [Anthropic, auto mode](https://anthropic.com/engineering/claude-code-auto-mode)
- [axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53); [OWASP Agentic Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
