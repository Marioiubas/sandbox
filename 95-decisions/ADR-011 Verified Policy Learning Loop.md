---
title: "ADR-011 Verified Policy Learning Loop"
aliases: ["ADR-011"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/learning, topic/policy, topic/approval, invariant/i3, invariant/i4, milestone/m2]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Learn policy via record, mine, SymCC, human PR, shadow, enforce; reject auto-applied LLM-synthesized policy and no learning."
related: ["[[Policy Learning Loop]]", "[[Policy Miner Safeguards]]", "[[SymCC CI Gates]]", "[[AgentSpec]]", "[[I3 Probabilistic Components Only Narrow]]", "[[Trace-Mined Least Privilege]]", "[[Progent]]", "[[Cedar]]", "[[AWS AgentCore]]", "[[NVIDIA OpenShell]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[I4 Repo Policy Only Narrows]]", "[[I8 No Flag Disables Isolation]]", "[[L4 Product Metrics]]", "[[M2 Policy Audit and Learn]]", "[[Risk Register]]", "[[Open Questions and Unverified Claims]]", "[[ADR-014 Apache-2.0 Endpoint with Commercial ee]]", "[[Audit Recorder and Event Schema]]", "[[Control Plane and Policy Bundles]]", "[[Gap Analysis]]", "[[MOC Decisions]]"]
sources: ["https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/", "https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/", "https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/", "https://arxiv.org/abs/2503.18666", "https://arxiv.org/html/2504.11703v3", "https://arxiv.org/abs/2509.23994", "https://docs.rs/cedar-policy-symcc", "https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://anthropic.com/engineering/claude-code-auto-mode", "https://arxiv.org/html/2510.09023"]
superseded_by:
---

# ADR-011 Verified Policy Learning Loop

> Learn policy via record, mine, SymCC, human PR, shadow, enforce; reject auto-applied LLM-synthesized policy and no learning.

## Status

Proposed (2026-09-24). Delivered by [[M2 Policy Audit and Learn]]: learn mode over 3 repos × 3 agents must yield a policy under which the same tasks pass with 0 denies, a seeded injection must be blocked and logged, and every learned change must pass the narrowing or ceiling gates or show counterexamples.

## Context

Hand-written least-privilege egress policy is the product's hardest usability problem. Over-broad policy is the default failure, and prompts do not rescue it: users approve 93% of Claude Code permission prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)).

**Prior art is mature outside agents.** Security Profiles Operator v1.0 (June 2026) records seccomp, SELinux and AppArmor profiles through log or eBPF recorders and merges them across replicas ([CNCF](https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/)). IAM Access Analyzer generates policies from CloudTrail activity ([AWS](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/)); the research treated its details as background, not fetched. NVIDIA OpenShell has an `enforcement: audit` mode but no miner ([OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)). AgentCore Policy turns natural language into Cedar and checks the result with Cedar Analysis ([AWS](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)). **No product in the record ships an agent egress "record → enforce" miner.**

**Generated policy misses hazards.** [[AgentSpec]]'s LLM-generated rules reached 95.56% precision but **70.96% recall**, so roughly 29% of hazards were missed ([arXiv 2503.18666](https://arxiv.org/abs/2503.18666)). Policy-as-Prompt compiles design documents into prompt-based classifiers, so its enforcement stays probabilistic ([arXiv 2509.23994](https://arxiv.org/abs/2509.23994)). Model-based defenses were broken adaptively at 71–100% ([arXiv 2510.09023](https://arxiv.org/html/2510.09023)).

**Narrowing can be proved.** [[Progent]] uses an SMT solver to classify each policy update as a narrowing (applied automatically) or a widening (needs approval); only 6% of updates on AgentDojo needed approval ([arXiv 2504.11703](https://arxiv.org/html/2504.11703v3)). Cedar's symbolic compilation is proved sound and complete in Lean ([cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)). `cedar-policy-symcc` exposes `check_implies`, `check_equivalent`, `check_disjoint` and related queries, each with a counterexample variant ([docs.rs](https://docs.rs/cedar-policy-symcc)).

**Learning can bake in an attack.** In the Cowork incident, an attacker-planted API key used the allowlisted `api.anthropic.com` to exfiltrate ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). A learned "allow `api.anthropic.com`" rule would not have stopped it ([[Claude Cowork Allowed-Domain Abuse]]).

## Decision

**Proposal.** Least-privilege policy is learned by a deterministic pipeline whose every output is proved or shown, and merged only by a human ([[Policy Learning Loop]]):

1. **Record.** `broker learn` runs sessions in `record` mode with L7 visibility on credentialed hosts, collecting `(task class, repo, binary, host, method, path template, verb)` tuples. The org ceiling, credential brokering and the sandbox stay on in every mode ([[I8 No Flag Disables Isolation]]).
2. **Mine and generalise conservatively.** Prefer operation-level entries to wildcards; require minimum support before collapsing a path prefix; collapse to a domain suffix only after k distinct subdomains; never widen methods beyond those observed; never auto-grant high-risk verbs (write, auth-bearing, publish, delete). Derive the GitHub `permissions` object and STS session policy from observed operations. Apply the poisoning defences in [[Policy Miner Safeguards]]: learn only from trusted-input runs or the intersection of N runs, exclude any request that carried a foreign credential or tripped the sentinel check, and never learn past the org deny ceiling.
3. **Emit a Cedar diff** with evidence counts and replay statistics ("would have blocked N requests").
4. **Gate in CI** with [[SymCC CI Gates]]: `check_implies(P_new, P_old)` labels a change a proved narrowing; otherwise the counterexample requests are shown as the "expansion delta". `check_implies(P_new, P_ceiling)` failing **blocks merge outright**, and no approval overrides it.
5. **Open a pull request** on the customer's policy repo. A human merges it. An LLM may *explain* a diff but never merge it.
6. **Shadow, then enforce.** After merge, the candidate runs in `shadow` mode logging would-deny decisions; it is enforced only after review of those results.

**Testable as:** the M2 acceptance criteria; the L4 thresholds "learned policy covers ≥95% of legitimate held-out requests within 3 sessions" and "0 learned rules broader than a registrable domain without approval" ([[L4 Product Metrics]]); and a test that a poisoned trace set produces no widening.

## Alternatives considered

| Alternative | Pros | Cons | Why rejected |
|---|---|---|---|
| **LLM-synthesized policy, auto-applied** | Fast; handles novel tasks; AgentCore shows NL→Cedar in production | 70.96% recall in AgentSpec; the author model can be steered by untrusted input; nothing bounds a subtly over-broad rule | Violates [[I3 Probabilistic Components Only Narrow]]. An LLM may *draft* a candidate, but only through the same gates |
| **No learning (hand-written policy only)** | Simplest; no poisoning risk | Policy authoring does not scale across repos and agents; pushes users towards broad wildcards or prompt fatigue | Abandons one of the six unowned capabilities in the [[Gap Analysis]] |
| **Miner with human review, no proof** | Cheap | Reviewers cannot see what a diff really widens; approval fatigue applies to reviewers too | The proof turns review into checking a counterexample list |
| **Auto-apply proved narrowings (Progent's rule)** | Fewer PRs | Policy changes bypass the customer's change control | Kept as a later option for narrowing-only diffs; MVP routes everything through a PR |

## Consequences

- **Easier:** policy starts from observed behaviour, and every change carries evidence and a machine-checked classification. This is the "learning plus verified review" capability no product in the record offers.
- **Harder:** the miner needs L7 visibility (TLS termination on the hosts that will need credentials) and a reliable path templatizer. Mining quality depends on the diversity of recorded runs.
- **Riskier:** a poisoned or narrow training set yields either an over-grant or a brittle policy. The ceiling, trusted-input learning and shadow mode bound this, but the risk is not zero ([[Risk Register]], row "Learned policy over-grants or is poisoned").
- **Guarantee boundaries:** SymCC proves facts about policy semantics relative to the schema, not about how the proxy parses traffic into entities, so the conformance suite remains necessary.

## Revisit triggers

- Measured over- or under-privilege rates from L4 fall short of the thresholds after the conservative rules are tuned.
- A study of learning from compromised runs appears (none is in the record) or a poisoned rule reaches production.
- SymCC hits scaling or unsupported-feature limits on real policy sets; the record found no official list of those limits.
- Customers ask for auto-apply of proved narrowings.

## Invariants and components affected

- **Upholds [[I3 Probabilistic Components Only Narrow]]:** probabilistic helpers may explain or draft, and every widening requires a SymCC-proved diff plus human approval.
- **Upholds [[I4 Repo Policy Only Narrows]]:** the same `check_implies` machinery gates repo-supplied policy.
- **Upholds [[I8 No Flag Disables Isolation]]:** `record` mode relaxes task permits only, never isolation, egress or brokering.
- **Upholds I9:** traces and decisions come from the hash-chained audit log.
- Components: `crates/learn` (aggregation, generaliser, risk classifier, Cedar diff), [[SymCC CI Gates]], [[Policy Miner Safeguards]], [[Audit Recorder and Event Schema]] (trace source), and the phase 2 review UI in [[Control Plane and Policy Bundles]].

## How it connects

- depends-on:: [[Policy Learning Loop]]
- depends-on:: [[Policy Miner Safeguards]]
- depends-on:: [[SymCC CI Gates]]
- depends-on:: [[Cedar]]
- motivated-by:: [[AgentSpec]]
- motivated-by:: [[Progent]]
- motivated-by:: [[Claude Cowork Allowed-Domain Abuse]]
- implements:: [[I3 Probabilistic Components Only Narrow]]
- contrasts-with:: [[AWS AgentCore]] (NL authoring, cloud-bound)
- contrasts-with:: [[NVIDIA OpenShell]] (audit mode without a miner)
- example-of:: [[Trace-Mined Least Privilege]]
- evaluated-by:: [[L4 Product Metrics]]
- delivered-by:: [[M2 Policy Audit and Learn]]
- part-of:: [[MOC Decisions]]

## Implications for the build

- Build the gates before the miner. A miner whose output cannot yet be checked must not produce PRs.
- Encode each generalisation and poisoning rule as a unit-tested function in `code/crates/learn/`, with a test that a sparse or poisoned trace set does not widen.
- Keep `broker suggest` output identical to the PR body, so the CLI and CI show the same evidence.
- Log mining inputs by audit-row hash, so a merged rule can be traced back to the sessions that justified it.

## Open questions

- What are the values of N (runs to intersect), k (subdomains before suffix collapse) and minimum support? Not in the record; tune on M2 data.
- How long should shadow mode run before enforcement: a fixed number of sessions or a zero-would-deny window?
- Should phase 2 ship a hosted miner in `ee/` while local learn mode stays Apache-2.0 ([[ADR-014 Apache-2.0 Endpoint with Commercial ee]])?
- IAM Access Analyzer, AppArmor `aa-logprof` and Tetragon were background knowledge in the research ([[Open Questions and Unverified Claims]]).

## Sources

- [CNCF: Security Profiles Operator v1](https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/)
- [AWS: IAM Access Analyzer policy generation](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/)
- [NVIDIA OpenShell docs: first network policy](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)
- [AWS Security Blog: AgentCore Policy and Cedar](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)
- [AgentSpec, arXiv 2503.18666](https://arxiv.org/abs/2503.18666)
- [Progent, arXiv 2504.11703](https://arxiv.org/html/2504.11703v3)
- [Policy-as-Prompt, arXiv 2509.23994](https://arxiv.org/abs/2509.23994)
- [docs.rs: cedar-policy-symcc](https://docs.rs/cedar-policy-symcc)
- [cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)
- [Anthropic: how we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude)
- [Anthropic: Claude Code auto mode](https://anthropic.com/engineering/claude-code-auto-mode)
- [The Attacker Moves Second, arXiv 2510.09023](https://arxiv.org/html/2510.09023)
- Report: decisions row "Policy learning", "Least-privilege learning" and "Formal gates in CI"; research notes 02 Q4, 03 Q6 and 04a Q5.
