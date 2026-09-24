---
title: "ACE and IsolateGPT"
aliases: ["ACE", "IsolateGPT", "Abstract-Concrete-Execute"]
type: paper
section: research
tags: [sandbox/research, paper, topic/ifc, topic/mcp, topic/isolation, milestone/m3, milestone/phase3]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "ACE (NDSS 2026): abstract plan from trusted input, concrete plan, static IFC analysis of the plan, execution with barriers; IsolateGPT (NDSS 2025): hub-and-spoke per-app isolation, which ACE breaks; basis for per-MCP-server principals and phase-3 plan analysis."
related: ["[[MCP Guard]]", "[[Information Flow Control]]", "[[Design Patterns for Securing LLM Agents]]", "[[MVP Plan]]", "[[Provenance-Aware Cedar]]", "[[Dynamic Tasks Without Control-Flow Hijack]]", "[[ADR-012 MCP Servers as Pinned Sandboxed Principals]]", "[[postmark-mcp Rug Pull]]", "[[AgentDyn]]", "[[Broker Cedar Schema]]", "[[CaMeL]]", "[[The Attacker Moves Second]]"]
sources: ["https://arxiv.org/abs/2504.20984", "https://github.com/escottrose01/ace-llm", "https://arxiv.org/abs/2403.04960", "https://arxiv.org/abs/2409.19091", "https://github.com/fzwark/Secure_LLM_System", "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks", "https://arxiv.org/html/2602.03117v1"]
---

# ACE and IsolateGPT

Two NDSS systems that isolate LLM apps from one another. **IsolateGPT** (NDSS 2025) runs each third-party app in its own "spoke" with its own LLM, mediated by a hub. **ACE** (NDSS 2026) shows that hub-and-spoke can still be attacked through planning, and instead fixes an abstract plan from trusted input, statically checks the concrete plan against information-flow constraints, then executes with barriers between apps. The broker takes IsolateGPT's separation (each MCP server its own sandboxed principal) now and ACE's pre-execution plan analysis in phase 3.

## Citations

- **IsolateGPT.** Wu, Roesner, Kohno, Zhang, Iqbal. "IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems". NDSS 2025; arXiv 2403.04960 ([arXiv](https://arxiv.org/abs/2403.04960)). Also known as SecGPT.
- **ACE.** Li, Mallick, Rose, Robertson, Oprea, Nita-Rotaru. "ACE" (Abstract-Concrete-Execute). arXiv 2504.20984, Apr 2025, rev. Sep 2025; NDSS 2026 ([arXiv](https://arxiv.org/abs/2504.20984)). Code: [escottrose01/ace-llm](https://github.com/escottrose01/ace-llm).
- **Background:** Wu, Cecchetti, Xiao, "System-Level Defense against Indirect Prompt Injection Attacks: An IFC Perspective" (f-secure LLM system), arXiv 2409.19091, Sep 2024 ([arXiv](https://arxiv.org/abs/2409.19091)); code [fzwark/Secure_LLM_System](https://github.com/fzwark/Secure_LLM_System).

## IsolateGPT: mechanism and evidence

**Mechanism.** Hub-and-spoke. Each third-party app runs in its own isolated spoke with its own LLM; the hub mediates inter-app communication, with user consent ([arXiv](https://arxiv.org/abs/2403.04960)).

```text
            ┌── spoke: app A (own LLM, own context)
user ─ hub ─┼── spoke: app B (own LLM, own context)
            └── spoke: app C
hub routes requests; cross-spoke data flow needs user consent
```

**Evidence.** Overhead under 30% for three-quarters of tested queries, with functionality preserved ([arXiv](https://arxiv.org/abs/2403.04960)).

**Weakness.** ACE demonstrates new attacks on IsolateGPT affecting planning integrity and execution integrity and availability ([arXiv 2504.20984](https://arxiv.org/abs/2504.20984)). The hub LLM is still a confusable planner: isolating app *contexts* does not stop the hub from being steered into a harmful sequence of legitimate cross-app calls.

## ACE: mechanism and evidence

**Mechanism** ([arXiv](https://arxiv.org/abs/2504.20984)):

1. **Abstract plan** generated from trusted information only (the user request).
2. **Concrete plan** mapping abstract steps onto the apps actually installed.
3. **Static analysis** of the structured concrete plan against user-specified information-flow constraints, *before* anything runs.
4. **Execution** with data and capability barriers between apps.

```text
abstract = Planner(trusted_request)              # no untrusted data seen
concrete = map(abstract, installed_apps)
assert check_flows(concrete, user_ifc_constraints)   # e.g. tenant-A data ↛ external domain
execute(concrete) with barriers(app_i ↮ app_j except declared flows)
```

**Evidence.** ACE defends against InjecAgent and ASB attacks plus new variants, and breaks IsolateGPT. Utility was evaluated on the LangChain Tool Usage suite; the research record did not extract a single headline number ([arXiv](https://arxiv.org/abs/2504.20984)).

**Weaknesses.** Utility is measured on a LangChain tool suite, not on hard dynamic tasks; [[AgentDyn]] does not evaluate ACE ([arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)). The abstract planner is an LLM. As with every static-plan design, data-dependent tasks are the utility risk that zeroed [[CaMeL]] on open-ended tasks. f-secure, the IFC predecessor, has no benchmark numbers.

## Threat model, assumptions and adaptive results

- **IsolateGPT:** third-party apps (and their content) are untrusted and may attack each other or the user; the hub and the user's consent are trusted ([arXiv](https://arxiv.org/abs/2403.04960)). Code availability is not in the record.
- **ACE:** the user request and user-specified information-flow constraints are trusted; the abstract plan is produced before untrusted data is seen; installed apps and their outputs may be malicious ([arXiv](https://arxiv.org/abs/2504.20984)). Code is public ([escottrose01/ace-llm](https://github.com/escottrose01/ace-llm)).
- **Adaptive results:** ACE's authors built new attacks that broke IsolateGPT, which is the main adaptive result in the record for either system. No third party has adaptively attacked ACE in the record; neither system was in [[The Attacker Moves Second]] or the June 2026 out-of-band study.
- **Assumption to watch:** ACE assumes users (or administrators) can write the information-flow constraints. For coding agents, the broker must supply defaults, because developers will not write IFC rules per task.

## Where the probabilistic part lives

IsolateGPT: the hub LLM. ACE: the abstract planner (from trusted input only); static analysis and barriers are deterministic.

## The MCP connection

MCP servers are the agent-era equivalent of IsolateGPT's apps, and tool descriptions are part of the planner's input. Invariant Labs showed **shadowing**: one server's tool description overrides another trusted server's tool behaviour, for example redirecting email recipients even when the user specified one ([Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)). Shadowing breaks per-server isolation assumptions unless descriptions from server A are never trusted when planning calls to server B: descriptions need integrity labels too (research note 02, Q3 inference). The [[postmark-mcp Rug Pull]] shows a single server turning malicious after approval.

## Adopt / Improve / Add

- **Adopt (IsolateGPT, now):** **Proposal:** each MCP server runs as a separate sandbox principal with separate credentials and its own egress policy. It is cheap and orthogonal to IFC. This is [[MCP Guard]] and [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]: the agent names a pinned server; `brokerd` launches the pinned command in its own sandbox as an `McpServer` principal with sentinel env vars.
- **Adopt (ACE, phase 3):** **Proposal:** pre-execution static analysis of plans against information-flow constraints, which is where a policy engine can give answers like "this plan would send tenant-A data to an external domain" before execution. The [[MVP Plan]] lists ACE-style static plan analysis in phase 3.
- **Improve:** **Proposal:** express ACE's flow constraints in Cedar with label attributes, so plan checks and per-request checks share one analyzable policy ([[Provenance-Aware Cedar]]).
- **Add:** **Proposal:** manifest pinning as the integrity label for tool descriptions: the guard hashes `tools/list` (names, schemas, descriptions) and any change revokes the server's grants until re-approved, which addresses rug pulls and shadowing ([[MCP Guard]]).

## How it connects

- contrasts-with:: [[CaMeL]]
- example-of:: [[Information Flow Control]]
- example-of:: [[Design Patterns for Securing LLM Agents]]
- delivered-by:: [[MVP Plan]]

Design notes grounded here: [[MCP Guard]], [[ADR-012 MCP Servers as Pinned Sandboxed Principals]], [[Provenance-Aware Cedar]]. ACE's static-plan approach faces the same utility wall as other plan-first systems, which [[Dynamic Tasks Without Control-Flow Hijack]] addresses. The per-server principal is modelled as the `McpServer` entity in the [[Broker Cedar Schema]].

## Implications for the build

- M3: every wrapped MCP server is its own sandbox and its own Cedar principal/resource; never share a credential or egress policy between two servers.
- Tool descriptions are integrity-critical input: pinned by hash, loaded only from user or org config, never from the repo.
- Phase 3: design the plan-analysis API so a plan can be expressed as a set of Cedar requests and checked with SymCC before execution.

## Open questions

- ACE's utility on open-ended tasks is unmeasured.
- How to label description integrity across servers from the same publisher: not in the record.

## Sources

- [ACE, arXiv 2504.20984](https://arxiv.org/abs/2504.20984); [code](https://github.com/escottrose01/ace-llm)
- [IsolateGPT, arXiv 2403.04960](https://arxiv.org/abs/2403.04960)
- [f-secure, arXiv 2409.19091](https://arxiv.org/abs/2409.19091); [code](https://github.com/fzwark/Secure_LLM_System)
- [Invariant Labs, tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks); [AgentDyn](https://arxiv.org/html/2602.03117v1)
