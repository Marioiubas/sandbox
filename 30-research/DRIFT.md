---
title: "DRIFT"
aliases: ["Dynamic Rule-Based Defense"]
type: paper
section: research
tags: [sandbox/research, paper, topic/policy, invariant/i3, evidence/single-source]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "NeurIPS 2025 defense with a secure planner, an LLM dynamic validator using read/write/execute privilege classes and an injection isolator: AgentDojo 30.7% -> 1.3% at 58.48% utility, but large utility loss on AgentDyn."
related: ["[[Progent]]", "[[CaMeL]]", "[[AgentDyn]]", "[[I3 Probabilistic Components Only Narrow]]", "[[The Attacker Moves Second]]", "[[Broker Cedar Schema]]", "[[Dynamic Tasks Without Control-Flow Hijack]]", "[[SymCC CI Gates]]", "[[Example Cedar Policies]]", "[[L2 Injection Benchmarks]]"]
sources: ["https://arxiv.org/html/2506.12104v2", "https://neurips.cc/virtual/2025/poster/116028", "https://github.com/SaFo-Lab/DRIFT", "https://arxiv.org/html/2602.03117v1"]
---

# DRIFT

DRIFT adds a dynamic element to plan-then-execute defenses. A secure planner fixes a minimal tool trajectory and parameter constraints up front; when the agent later wants to deviate, an **LLM validator** judges the deviation by whether it reads, writes or executes; and an **injection isolator** masks conflicting instructions in memory. On AgentDojo it cut attack success from 30.7% to 1.3% while keeping far more utility than CaMeL, but its guarantee depends on two LLMs, and on the same group's harder AgentDyn benchmark it lost most of its utility. The broker takes its read/write/execute axis and replaces the LLM judge with a deterministic gate.

## Citation

- Li, Liu, Chiu, Li, Zhang, Xiao. "DRIFT: Dynamic Rule-Based Defense with Injection Isolation" (short title as recorded). arXiv 2506.12104; NeurIPS 2025 poster ([arXiv HTML](https://arxiv.org/html/2506.12104v2); [NeurIPS](https://neurips.cc/virtual/2025/poster/116028)).
- Code: [SaFo-Lab/DRIFT](https://github.com/SaFo-Lab/DRIFT).

## Mechanism

Three components ([arXiv HTML](https://arxiv.org/html/2506.12104v2)):

1. **Secure Planner.** Before any environment interaction, emits a minimal function trajectory plus JSON parameter constraints for each call.
2. **Dynamic Validator (LLM).** When execution deviates from the planned trajectory, judges the deviation by the privilege class of the new call: **Read**, **Write** or **Execute**.
3. **Injection Isolator.** Detects instructions in memory that conflict with the user task and masks them.

```text
plan = Planner(user_task)                  # [(tool, param_constraints)], before seeing data
for step in agent_run:
    if step ∈ plan and step.args ⊨ constraints: execute
    else:  cls = privilege(step.tool)       # Read | Write | Execute
           if Validator_LLM(step, cls, context) approves: plan += step; execute
           else: block
    memory = Isolator_LLM(memory)           # mask conflicting instructions
```

(Illustrative control loop based on the description above.)

## Threat model and assumptions

- **Attacker:** controls content that enters the agent's context through tool results and memory (indirect prompt injection); the user task is trusted ([arXiv HTML](https://arxiv.org/html/2506.12104v2)).
- **Assumed trusted:** the Secure Planner's output, because it is produced before any environment interaction, and the user query it is produced from.
- **Assumed good enough (the weak point):** the Validator and Isolator LLMs. They read the same context the attacker writes to, so the defense assumes the injection cannot also persuade the judge. The research audit notes this makes parts of the guarantee probabilistic.
- **Out of scope, by construction:** misuse of calls that are already in the planned trajectory with parameters that satisfy the JSON constraints; the constraints bound the parameters but do not track where the values came from.
- **Code:** public ([SaFo-Lab/DRIFT](https://github.com/SaFo-Lab/DRIFT)), which makes it a practical baseline to re-run.

## Evidence

AgentDojo, GPT-4o-mini ([arXiv HTML](https://arxiv.org/html/2506.12104v2)):

| Metric | DRIFT | Comparison in the same paper |
|---|---|---|
| ASR | 30.7% → **1.3%** | — |
| Benign utility | **58.48%** | CaMeL 37.71% |
| Utility under attack | 47.91% | CaMeL 32.25% |
| ASB ASR | 4.8% | Progent 15.8% (DRIFT's setup) |
| Combined adaptive attack on isolator + validator | 2.10% ASR at 47.87% utility | — |

## Counter-evidence

- **AgentDyn (Feb 2026, same lab group):** DRIFT "shows significant utility loss in dynamic scenarios", keeping only about 30% utility on GPT-4o ([arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)). The utility gains over CaMeL on AgentDojo did not hold on harder, open-ended tasks.
- **Adaptive evaluation is by the authors only.** DRIFT was not in [[The Attacker Moves Second]] or in the June 2026 out-of-band study.
- **Comparison numbers conflict with other papers.** DRIFT's CaMeL figure (37.71%) conflicts with CaMeL's own 77%, and its Progent-on-ASB figure (15.8%) conflicts with Progent's 3.9%. All are model- and setup-specific (see [[CaMeL]], [[Progent]]).

## Where the probabilistic part lives

The Validator and the Isolator are LLMs, so DRIFT is hybrid leaning probabilistic: the decision to **widen** the plan is made by a model reading context that may contain the injection. In this product's terms, DRIFT lets a probabilistic component widen authority, which [[I3 Probabilistic Components Only Narrow]] forbids.

## DRIFT versus Progent, in one table

| Question | DRIFT | [[Progent]] |
|---|---|---|
| Who fixes the initial authority? | Secure Planner (LLM, before seeing data) | Policy LLM (from the trusted task) |
| Who decides a widening? | Validator LLM, by read/write/execute class | SMT classifies; the user approves widenings |
| Can a model widen authority alone? | Yes | No |
| AgentDojo ASR | 30.7% → 1.3% (GPT-4o-mini) | 39.9% → 1.0% (gpt-4o) |
| Open-ended (AgentDyn) | ~30% utility on GPT-4o | Struggles with larger tool sets |

Numbers from each paper and AgentDyn ([DRIFT](https://arxiv.org/html/2506.12104v2); [AgentDyn](https://arxiv.org/html/2602.03117v1)); models differ, so compare shapes, not digits. The broker keeps Progent's answer to the third row and DRIFT's privilege classes.

## Adopt / Improve / Add

- **Adopt:** explicit Read / Write / Execute privilege classes per action as the axis for "does this deviation need approval". The [[Broker Cedar Schema]] already groups HTTP methods into `http.read` (GET, HEAD, OPTIONS) and `http.write` (POST, PUT, PATCH, DELETE); protocol adapters extend the same split to `git.fetch`/`git.push`, registry read versus publish, and MCP tools.
- **Improve:** **Proposal:** keep DRIFT-style dynamic re-planning, but gate every *widening* through a deterministic check (Progent-style `check_implies` via [[SymCC CI Gates]] at build time, and a Cedar decision at runtime) instead of an LLM validator. An LLM may propose or explain a widening; only policy or a human grants it.
- **Add:** **Proposal:** default the approval requirement by class: Read deviations inside the task's repo and hosts may be auto-granted if they narrow the ceiling; Write and Execute deviations always need the authority-diff prompt; irreversible verbs are never auto-granted ([[Example Cedar Policies]]).

## How it connects

- contrasts-with:: [[Progent]]
- contrasts-with:: [[CaMeL]]
- evaluated-by:: [[AgentDyn]]
- evaluated-by:: [[L2 Injection Benchmarks]]

DRIFT is the clearest counter-example for [[I3 Probabilistic Components Only Narrow]]; [[The Attacker Moves Second]] explains why an LLM validator is not a boundary. Its dynamic re-planning is the utility idea behind [[Dynamic Tasks Without Control-Flow Hijack]].

## Implications for the build

- Every Cedar action should belong to exactly one of read, write or execute groups so policies, prompts and learning can reason by class.
- No component that reads agent context (including injected text) may be on the path that grants a widening.
- On AgentDyn, report DRIFT alongside CaMeL and Progent as comparison baselines.

## Open questions

- Whether read-class widenings can be auto-granted safely when `untrusted_input` is live (reads can still feed exfiltration later); decide with the trifecta rules.

## Sources

- [arXiv 2506.12104v2](https://arxiv.org/html/2506.12104v2); [NeurIPS 2025 poster](https://neurips.cc/virtual/2025/poster/116028); [code](https://github.com/SaFo-Lab/DRIFT)
- [AgentDyn, arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)
