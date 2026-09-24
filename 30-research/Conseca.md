---
title: "Conseca"
aliases: ["Contextual Agent Security"]
type: paper
section: research
tags: [sandbox/research, paper, topic/policy, topic/learning, topic/audit, invariant/i3]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "HotOS 2025 per-task policy generated from trusted context only with human-readable rationale and a deterministic enforcer: 12/20 tasks vs 14/20 unrestricted and 0/20 static-restrictive."
related: ["[[AgentSpec]]", "[[Progent]]", "[[Policy Learning Loop]]", "[[Broker CLI and Daemon]]", "[[I3 Probabilistic Components Only Narrow]]", "[[MiniScope]]", "[[Audit Recorder and Event Schema]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[Cedar]]", "[[SymCC CI Gates]]", "[[AgentDyn]]", "[[The Attacker Moves Second]]"]
sources: ["https://arxiv.org/html/2501.17070v3", "https://dl.acm.org/doi/10.1145/3713082.3730378"]
---

# Conseca

Conseca argues that no single static policy fits an agent: a policy that is safe for "summarise my inbox" is wrong for "pay this invoice". It has an LLM write a **task-specific policy** for each request, using only **trusted context** (for example timestamps and metadata, not email bodies), with a human-readable rationale for each rule; a deterministic enforcer then checks every action without calling the LLM again. On 20 synthetic tasks it completed 12, against 14 for an unrestricted agent and 0 for a restrictive static policy. The broker adopts two ideas: every grant carries a rationale, and task policy is generated before untrusted data is seen.

## Citation

- Tsai (Google), Bagdasarian. "Contextual Agent Security: A Policy for Every Purpose". arXiv 2501.17070; HotOS 2025 ([arXiv HTML v3](https://arxiv.org/html/2501.17070v3); [ACM DL](https://dl.acm.org/doi/10.1145/3713082.3730378)).
- Code: not in the record.

## Mechanism

From the paper ([arXiv HTML v3](https://arxiv.org/html/2501.17070v3)):

1. The user's request arrives together with **trusted context** only. The trusted-context boundary is specified by hand (for example, timestamps are trusted, email bodies are not).
2. An LLM **generates a task-specific policy** from that input, with a **human-readable rationale** for each constraint.
3. A **deterministic enforcer** (regex constraints in the prototype) checks each proposed agent action against the policy, without re-invoking the LLM.

```text
policy, rationale = PolicyLLM(user_request, trusted_context)   # before untrusted data is seen
for action in agent_run:
    allow = enforcer.match(policy, action)                     # deterministic, no LLM
    log(action, allow, rationale_for(matched_rule))
```

(Illustrative.)

## Threat model and assumptions

- **Attacker:** injects instructions into untrusted data the agent processes (email bodies, file contents) ([arXiv HTML v3](https://arxiv.org/html/2501.17070v3)).
- **Trusted:** the user's request and a hand-specified set of trusted context. The policy generator sees only these, so the attacker cannot steer the policy unless they can write to trusted context.
- **Assumed:** the policy LLM understands the user's intent well enough to write a policy that neither blocks the task nor admits harmful actions; the authors list this dependency as a limitation.
- **Out of scope:** attacks that choose among actions the generated policy allows, and data-dependent actions the trusted context could not anticipate.
- **Adaptive attacks:** none in the record. Conseca was not in [[The Attacker Moves Second]] or the June 2026 out-of-band study.

## Evidence

Twenty synthetic filesystem and email tasks ([arXiv HTML v3](https://arxiv.org/html/2501.17070v3)):

| Configuration | Tasks completed (of 20) |
|---|---|
| Unrestricted | 14.0 |
| **Conseca** | **12.0** |
| Static permissive | 12.2 |
| Static restrictive | 0 |

Conseca denied contextually inappropriate actions that the static permissive policy allowed, at similar utility.

## Counter-evidence and weaknesses

Stated by the authors ([arXiv HTML v3](https://arxiv.org/html/2501.17070v3)):

- Policy quality depends on the LLM's understanding of intent.
- Limited trusted context cannot anticipate data-dependent actions.
- Regex-only constraints in the prototype.
- Synthetic evaluation; per-task LLM latency.

From the research audit: 20 synthetic tasks is a small sample; there is no AgentDojo or [[AgentDyn]] result and no adaptive attack; and a subtly over-broad generated policy is accepted silently, the same weakness as [[Progent]]'s initial policy and [[AgentSpec]]'s 71% recall.

## Where the probabilistic part lives

Policy generation (LLM). Enforcement is deterministic. Because the generator sees only trusted context, an injection in untrusted data cannot influence the policy; an attacker would have to reach the trusted context itself.

## Mapping onto the broker's session start

**Proposal.** Conseca's "policy before untrusted data" maps cleanly onto the broker's lifecycle: grants are fixed at `session.start {argv, cwd, profile, repo_remote}`, before the agent has read anything.

```text
session.start
  inputs (trusted): user identity, agent binary hash, repo remote, profile, org bundle, repo policy (narrow-only)
  optional: LLM drafts a task-specific narrowing + rationale from the user's typed request only
  gate:     check_implies(P_task, P_org)  → else discard the draft, use the learned default
  output:   Task entity + grant entities, each with a rationale string
```

Everything the agent later reads (issues, READMEs, web pages) can only cause a `grant.request` step-up, which is a widening and goes to a human with the authority diff.

## Adopt / Improve / Add

- **Adopt:** **Proposal:** a human-readable rationale on every grant, carried into the audit record ([[Audit Recorder and Event Schema]]) and shown in `broker why`. The report's control API already carries one: `grant.request {session_id, action, resource, rationale}` for step-up ([[Broker CLI and Daemon]]).
- **Adopt:** generate or select the task's policy **before untrusted data is seen**: the session's grants are computed at `session.start` from the bundle, repo policy and task, not mid-session from content.
- **Improve:** **Proposal:** target a real policy language instead of regex: task grants are Cedar entities checked by the verified engine ([[Cedar]]), and any generated task policy must pass `check_implies(P_task, P_ceiling)` before use ([[SymCC CI Gates]]). Evaluate on AgentDojo and AgentDyn rather than synthetic tasks.
- **Add:** **Proposal:** a deterministic fallback when generation is unavailable or distrusted: learned per-repo defaults from [[Policy Learning Loop]], or tool-graph-derived grants in the style of [[MiniScope]]. The LLM may narrow the default for this task, never widen it ([[I3 Probabilistic Components Only Narrow]]).

## How it connects

- contrasts-with:: [[AgentSpec]]
- contrasts-with:: [[Progent]]
- contrasts-with:: [[MiniScope]]

Conseca's generator is the kind of probabilistic component that [[I3 Probabilistic Components Only Narrow]] confines to narrowing. Rationales feed the approval UX in [[Fatigue-Resistant Approval Interfaces]]: a prompt should say why a grant exists and what it adds.

## Implications for the build

- The grant data model gets a `rationale` field from day one, stored with the grant and emitted in audit events.
- `broker why <request>` shows the deciding policy IDs and the rationale of the grant that allowed or would have allowed the request.
- Any LLM-drafted task policy is an input to the narrowing check, never an output that bypasses it.

## Open questions

- Which parts of a coding task's context are "trusted" (the user's typed request, the repo remote, the branch) and which are not (issue text, README)? Needs a written rule per agent profile.
- No evaluation of per-task generated policy on realistic coding workloads exists in the record.

## Sources

- [Conseca, arXiv 2501.17070 v3](https://arxiv.org/html/2501.17070v3); [ACM DL (HotOS 2025)](https://dl.acm.org/doi/10.1145/3713082.3730378)
