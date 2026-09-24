---
title: "The Attacker Moves Second"
aliases: ["Attacker Moves Second", "In-Band vs Out-of-Band Defenses", "Adaptive Attacks"]
type: paper
section: research
tags: [sandbox/research, paper, topic/evaluation, topic/policy, invariant/i3, adversary/a1, evidence/single-source]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Adaptive attacks broke 12 in-band defenses (most above 90%) and humans won 100% of scenarios; the in-band versus out-of-band split, the small June 2026 out-of-band study, and the deterministic/probabilistic classification of every audited system."
related: ["[[I3 Probabilistic Components Only Narrow]]", "[[Progent]]", "[[Problem Statement]]", "[[Adaptive Evaluation of Deterministic Monitors]]", "[[AgentDyn]]", "[[Red-Team Plan]]", "[[CaMeL]]", "[[AgentSentinel]]", "[[FIDES]]", "[[DRIFT]]", "[[Conseca]]", "[[ACE and IsolateGPT]]", "[[MiniScope]]", "[[AgentSpec]]", "[[Information Flow Control]]", "[[L2 Injection Benchmarks]]", "[[Claude Code DNS Exfiltration CVE-2025-55284]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://arxiv.org/abs/2510.09023", "https://arxiv.org/html/2510.09023", "https://arxiv.org/abs/2606.26479", "https://agentdojo.spylab.ai/results/", "https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations", "https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition", "https://openai.com/index/hardening-atlas-against-prompt-injection/", "https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://arxiv.org/html/2602.03117v1", "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/"]
---

# The Attacker Moves Second

This October 2025 paper showed that adaptive attackers break the published prompt-injection defenses that sit inside the model's input/output loop. Most of the 12 defenses fell at more than 90% attack success, and human red-teamers won every evaluated scenario. It is the single most decision-relevant result for this product: it sorts defenses into **in-band** (model-based, broken) and **out-of-band** (deterministic, so far holding, but tested only at small scale). That split justifies [[I3 Probabilistic Components Only Narrow]].

## Citation

- Nasr, Carlini, Sitawarin, Schulhoff, Hayes, Ilie, Pluto, Song, Chaudhari, Shumailov, Thakurta, Xiao, Terzis, Tramèr. "The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses against LLM Jailbreaks and Prompt Injections". arXiv 2510.09023, 10 Oct 2025 ([arXiv](https://arxiv.org/abs/2510.09023)).
- Companion data point: Narisetty, Kore, Kattamanchi, Kumarapu, adaptive evaluation of out-of-band defenses, arXiv 2606.26479, 25 Jun 2026 ([arXiv](https://arxiv.org/abs/2606.26479)).

## Mechanism: how the attacks work

Four adaptive attack families were run against each defense: gradient descent, reinforcement learning, random search, and human-guided attacks ([arXiv](https://arxiv.org/abs/2510.09023)). "Adaptive" means the attacker knows the defense and optimises against it, rather than replaying a fixed attack set as the defenses' own papers did. Every defense evaluated had originally reported near-zero attack success.

## Threat model and assumptions

- **Attacker knowledge:** the attacker knows which defense is deployed and adapts to it. This is the standard adversarial-ML evaluation stance, and the paper's core critique is that defenses were published against *static* attack sets ([arXiv](https://arxiv.org/abs/2510.09023)).
- **Attacker capability:** varies by family, from gradient access (white-box) to query-only search and RL, to humans iterating by hand.
- **Scope:** in-band defenses to jailbreaks and prompt injection (prompting, training, filtering, secret-knowledge). System-level, out-of-band designs were not in scope.
- **Implication:** a defense's number is only meaningful with the attacker's budget attached, which is why this vault reports ASR@k rather than single-shot ASR.
- **Code:** not in the record.

## Evidence: the per-defense record

Adaptive attack success rate (ASR), from the paper ([arXiv HTML](https://arxiv.org/html/2510.09023)):

| Defense (in-band) | Family | Adaptive ASR |
|---|---|---|
| Spotlighting | Prompting | >95% |
| Prompt Sandwiching | Prompting | >95% |
| RPO | Prompting/optimisation | 96–98% |
| Circuit Breakers | Training | 100% |
| StruQ | Training | 100% |
| MetaSecAlign | Training | 96% (from 2%) |
| Protect AI detector | Filtering | >90% |
| PromptGuard | Filtering | >90% |
| PIGuard | Filtering | 71% |
| Model Armor | Filtering | >90% |
| Data Sentinel | Filtering | 80%+ |
| MELON | Re-execution | 76–95% |

Human red-teaming succeeded in 100% of evaluated scenarios. **CaMeL and other system-level defenses were not evaluated.** The authors' conclusion: "Simply adding more filters or stacking additional detectors does not resolve the underlying robustness problem" ([arXiv HTML](https://arxiv.org/html/2510.09023)).

Corroborating evidence from outside the paper:

- NIST CAISI (Jan 2025), using AgentDojo on Claude 3.5 Sonnet: baseline attacks succeeded 11% of the time versus 81% for novel red-team attacks; retrying 25 times raised average success from 57% to 80% ([NIST](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)).
- NIST CAISI competition (23 Mar 2026): 400+ participants, 250,000+ attacks on 13 frontier models; "all models were successfully compromised", and universal attacks transferred across models ([NIST CAISI](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)).
- Gray Swan figures cited by Anthropic: about 0.1% single-attempt success rose to 5–6% after 100 adaptive attempts ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).
- Model makers concede the point: OpenAI says prompt injection is "unlikely to ever be fully 'solved'" ([OpenAI](https://openai.com/index/hardening-atlas-against-prompt-injection/)); the UK NCSC says it "will never be properly mitigated" the way SQL injection was ([NCSC](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection)).
- Willison: "in web application security 95% is very much a failing grade" ([simonwillison.net](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)).

A telling baseline: on AgentDojo (gpt-4o-2024-05-13), the simple `tool_filter` defense had 72.16% utility and 6.84% targeted ASR, beating the ML detector (`transformers_pi_detector`, 41.24% / 7.95%) and spotlighting (72.16% / 41.65%); the undefended baseline was 69.07% / 47.69% ([AgentDojo results](https://agentdojo.spylab.ai/results/); the page notes it is "not a leaderboard"). Reducing reachable authority beat detecting malicious text.

## Counter-evidence: the out-of-band side is thin

The June 2026 study evaluated CaMeL, FIDES, Progent, RTBAS and FORGE, calling deterministic external mediation "a fundamentally different defense paradigm". Progent cut mean ASR from 25.8% to 4.2%, and a hand-crafted black-box adaptive attack reached only 2.6%. The authors call this "one small-scale data point" and leave white-box GCG attacks for future work ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)). No white-box or optimisation-based adaptive attack against CaMeL, FIDES or any deterministic monitor is in the record ([[Adaptive Evaluation of Deterministic Monitors]]).

The utility side cuts the other way. On [[AgentDyn]], the best-utility defense was Meta SecAlign at 53.4%, from the family broken at 96% adaptively, while CaMeL scored zero on open-ended tasks ([arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)). **No current design is both robust and useful on dynamic tasks.**

## Where the probabilistic part lives: classification of audited systems

D = deterministic decision outside the model; P = probabilistic; H = hybrid (research note 02, Q5, inference):

| System | Class | Probabilistic part |
|---|---|---|
| [[CaMeL]] | D enforcement, H overall | P-LLM writes the program (trusted input only); schema-bounded Q-LLM output |
| [[FIDES]] | D enforcement | Label annotation; bounded quarantined answers |
| [[Progent]] | H | LLM writes and updates policy; SMT and monitor deterministic |
| [[Conseca]] | H | LLM writes policy |
| [[DRIFT]] | H leaning P | LLM validator and isolator |
| [[ACE and IsolateGPT]] (ACE) | D | Abstract planner |
| [[MiniScope]] | D | None in loop |
| RTBAS / AgentArmor | H | Dependency judgement / trace-graph construction |
| SkillGuard | D | None |
| FlowSeal | H | Declassification oracle |
| [[AgentSpec]] | D checks | Rules may be LLM-generated (71% recall) |
| [[AgentSentinel]] | H | LLM auditor |
| AgentCore Policy | D (Cedar) | NL→Cedar authoring, verified before use |
| Invariant guardrails | H | ML detectors in rules |
| MELON, spotlighting, detectors, StruQ, SecAlign | P | Entirely model-based |

The inference that follows: a deterministic monitor gives a *conditional* guarantee ("if the policy and labels are right"). The attacker's move shifts to (a) getting a bad policy authored, (b) poisoning label sources, (c) choosing among allowed actions, (d) channels the monitor does not see, such as DNS ([[Claude Code DNS Exfiltration CVE-2025-55284]]). The product should close (b) and (d) deterministically and make (a) and (c) auditable and human-gated.

## Adopt / Improve / Add

- **Adopt:** Principle 1, "enforce outside the model, and allow probabilistic components only to narrow authority", as invariant [[I3 Probabilistic Components Only Narrow]]. Treat every in-band defense as noise reduction and telemetry, never a boundary.
- **Improve:** **Proposal:** evaluate the broker the way this paper evaluated in-band defenses: ASR@k for k=10–100 with adaptive LLM attackers per probe category ([[Red-Team Plan]], [[L2 Injection Benchmarks]]).
- **Add:** **Proposal:** a white-box ring targeting the Cedar entity builder and label sources, the area the June 2026 study leaves open ([[Adaptive Evaluation of Deterministic Monitors]]). Report "model complied, broker blocked" separately.

## How it connects

- contrasts-with:: [[AgentDyn]]
- contrasts-with:: [[Progent]]
- contrasts-with:: [[CaMeL]]

The [[Problem Statement]] is motivated by this paper's result. Design notes grounded in this paper: [[I3 Probabilistic Components Only Narrow]], [[Red-Team Plan]], [[Adaptive Evaluation of Deterministic Monitors]]. [[Information Flow Control]] and [[AgentSentinel]] are classified by it.

## Implications for the build

- No detector, classifier or LLM judge may sit on a path that can grant or widen authority. They may deny, flag or explain.
- The product's claims must be stated as conditional ("if policy and labels are right") and backed by published adaptive results, not benchmark-only numbers.
- Every evaluation report pairs utility with ASR and includes adaptive attempts.

## Open questions

- Unread defenses flagged in the record: ActGov (arXiv 2609.24446, rate-limited), "Operationalizing CaMeL", IPIGuard, Task Shield, ShieldAgent, LlamaFirewall/AlignmentCheck, Azure Prompt Shields, the original Spotlighting paper; FORGE's source paper is unidentified; MELON, StruQ and SecAlign original headline numbers not extracted ([[Open Questions and Unverified Claims]]).
- No white-box attack on any deterministic monitor exists yet.

## Sources

- [arXiv 2510.09023](https://arxiv.org/abs/2510.09023); [HTML](https://arxiv.org/html/2510.09023)
- [arXiv 2606.26479](https://arxiv.org/abs/2606.26479)
- [AgentDojo results](https://agentdojo.spylab.ai/results/); [AgentDyn](https://arxiv.org/html/2602.03117v1)
- [NIST CAISI Jan 2025](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations); [NIST CAISI Mar 2026](https://www.nist.gov/blogs/caisi-research-blog/insights-ai-agent-security-large-scale-red-teaming-competition)
- [OpenAI](https://openai.com/index/hardening-atlas-against-prompt-injection/); [NCSC](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection); [Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude); [Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
