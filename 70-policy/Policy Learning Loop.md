---
title: "Policy Learning Loop"
aliases: ["Record Shadow Enforce Modes", "Audit Mode", "Shadow Mode", "broker learn", "broker suggest", "Learning Plane"]
type: concept
section: policy
tags: [sandbox/policy, concept, topic/learning, topic/policy, topic/audit, invariant/i3, milestone/m2, milestone/phase3, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Record in audit mode with L7 visibility, generalise conservatively, emit a Cedar diff with evidence and replay stats, run SymCC gates, open a PR, shadow (log would-deny) and only then enforce; the record, shadow and enforce modes; an LLM may explain a diff but never merge it."
related: ["[[Policy Miner Safeguards]]", "[[SymCC CI Gates]]", "[[ADR-011 Verified Policy Learning Loop]]", "[[I3 Probabilistic Components Only Narrow]]", "[[Trace-Mined Least Privilege]]", "[[NVIDIA OpenShell]]", "[[AWS AgentCore]]", "[[M2 Policy Audit and Learn]]", "[[Broker CLI and Daemon]]", "[[Audit Recorder and Event Schema]]", "[[Progent]]", "[[AgentSpec]]", "[[Conseca]]", "[[MiniScope]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[L4 Product Metrics]]", "[[Control Plane and Policy Bundles]]", "[[Broker Cedar Schema]]", "[[Local Credential Proxies]]", "[[Docker Sandboxes]]", "[[GitHub App Installation Tokens]]", "[[AWS STS Session Policies]]", "[[Open Questions and Unverified Claims]]", "[[Fatigue-Resistant Approval Interfaces]]"]
sources: ["https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/", "https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/", "https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/", "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html", "https://github.com/strongdm/leash", "https://docs.docker.com/ai/sandboxes/network-policies/", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://arxiv.org/abs/2503.18666", "https://arxiv.org/html/2504.11703v3", "https://arxiv.org/html/2501.17070v3", "https://arxiv.org/abs/2512.11147", "https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/installation-usage.md"]
code: ["code/crates/learn/src", "code/crates/broker-cli/src/cmd/suggest.rs"]
---

# Policy Learning Loop

> Record in audit mode with L7 visibility, generalise conservatively, emit a Cedar diff with evidence and replay stats, run SymCC gates, open a PR, shadow (log would-deny) and only then enforce; the record, shadow and enforce modes; an LLM may explain a diff but never merge it.

## Summary

Hand-written least-privilege egress policy does not scale across repos and agents, and over-broad policy is the default failure. The broker therefore learns policy from observed runs and proves each change before it ships. The loop is **record → mine → prove → review → shadow → enforce**. Mining is deterministic. Every widening needs a SymCC counterexample shown to a human, and no LLM can merge anything. This is one of the six unowned capabilities in [[Gap Analysis]] and a research contribution in its own right ([[Trace-Mined Least Privilege]]). The decision is [[ADR-011 Verified Policy Learning Loop]].

## Details

### Prior art

The pattern is mature for syscall and MAC profiles:

- Security Profiles Operator v1.0 (June 2026) records profiles through **logs** or **eBPF** recorders via a `ProfileRecording` CRD, and merges them across replicas with a `mergeStrategy` ([CNCF](https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/); [SPO usage doc](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/installation-usage.md)). The article does not discuss the risk of recording compromised workloads.
- IAM Access Analyzer generates IAM policies from CloudTrail access activity ([AWS](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/)).
- NVIDIA OpenShell has `enforcement: audit` logging mode ([OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)), but no miner ([[NVIDIA OpenShell]]).
- AgentCore Policy turns natural language into Cedar and validates it with Cedar Analysis ([AWS](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/); [AWS docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html)). It is authoring, not trace mining ([[AWS AgentCore]]).
- StrongDM Leash captures complete file and network telemetry "so Cedar policies and audit trails operate on complete telemetry" ([GitHub](https://github.com/strongdm/leash)), the closest thing to a learning input ([[Local Credential Proxies]]). Docker's `docker sandbox network log` (allowed and blocked) is another raw input ([Docker docs](https://docs.docker.com/ai/sandboxes/network-policies/)).

**No product in the record ships an agent egress "record → enforce" miner.** That absence should be re-checked before it is claimed publicly.

> [!question] Unverified
> AppArmor `aa-logprof`, Tetragon and IAM Access Analyzer details were background knowledge in the research, not fetched primary docs. No study of learning least-privilege policy from compromised runs exists in the record. See [[Open Questions and Unverified Claims]].

On the agent-research side, policy synthesis is mostly LLM-generated today: Progent ([arXiv](https://arxiv.org/html/2504.11703v3)), Conseca ([arXiv](https://arxiv.org/html/2501.17070v3)) and AgentSpec, whose generated rules reached 95.56% precision but only 70.96% recall ([arXiv 2503.18666](https://arxiv.org/abs/2503.18666)). MiniScope is the main non-LLM approach, reconstructing permission hierarchies from tool-call relationships ([arXiv 2512.11147](https://arxiv.org/abs/2512.11147)). AgentSpec's recall is the reason generated rules need a static ceiling ([[AgentSpec]], [[Progent]], [[Conseca]], [[MiniScope]]).

### The three modes

Every session runs in exactly one mode, carried as `context.session.mode` ([[Broker Cedar Schema]]) and written to every audit row ([[Audit Recorder and Event Schema]]).

| Mode | Decision applied | Logged | Used for |
|---|---|---|---|
| `record` (audit) | Allow if the **org ceiling** allows; everything else denied | Would-be decision of the current policy, full L7 tuple, process ancestry | Collecting traces for mining |
| `shadow` | Current enforced policy | Both current and candidate policy decisions; "would-deny" of the candidate | Measuring a candidate before it bites |
| `enforce` | Current policy | Decision, determining policy IDs | Normal operation |

**Proposal:** `record` is never "allow everything". The org deny ceiling stays enforced in every mode ([[Policy Miner Safeguards]]), credentials are still brokered, and the sandbox is unchanged. Only the task-level permits are relaxed. [[I8 No Flag Disables Isolation]] applies to `broker learn` like any other flag.

### The five stages (Proposal, from the report)

1. **Record.** Run in audit mode with L7 visibility on the hosts that will need credentials. Collect `(task class, repo, binary, host, method, path template, verb)` tuples. Templatize IDs, SHAs and UUIDs, and map requests to known OpenAPI operations such as GitHub's. The landscape note adds process ancestry (binary path, argv hash) to each trace row.
2. **Generalise conservatively.** Prefer operation-level entries to wildcards; require minimum support before collapsing a path prefix; collapse to a domain suffix only after k distinct subdomains; never widen methods beyond those observed; classify risk (write, auth-bearing, publish, delete) and never auto-grant high-risk verbs; derive the GitHub `permissions` object and the STS session policy from the operations actually observed. The rules are in [[Policy Miner Safeguards]].
3. **Emit a Cedar diff** with evidence counts and replay statistics ("would have blocked N requests").
4. **Run SymCC gates,** then open a pull request on the customer's policy repo ([[SymCC CI Gates]]).
5. **After approval, shadow first.** Log would-deny decisions before enforcing.

**An LLM may *explain* a diff but never merge it.** This is [[I3 Probabilistic Components Only Narrow]] applied to learning.

### CLI surface

From the landscape note's UX sketch (**Proposal**):

```text
broker learn -- claude -p "fix tests"    # record-mode session; traces to SQLite
broker suggest                           # mine traces → Cedar diff + evidence + gate results
broker suggest --pr                      # open the PR on the policy repo (control plane in phase 2)
broker policy shadow <bundle>            # activate candidate in shadow mode
broker why <request-id>                  # explain any decision, including would-deny
```

`broker learn` and `broker suggest` are M2 scope. The diff-review UI is phase 2 ([[Control Plane and Policy Bundles]]). Drift and anomaly detection against the learned baseline is phase 3.

### Worked example: a diff PR

After three recorded `fix tests` runs of Claude Code on `acme/web` (**Proposal; illustrative output format, not real data**):

```text
+ permit http.GET  api.github.com/repos/acme/web/pulls/{n}         support 14 runs 3/3  risk read
+ permit http.POST api.github.com/repos/acme/web/pulls             support  3 runs 3/3  risk write  [NEEDS REVIEW: widening]
~ credential github_app:acme permissions: contents=write, pull_requests=write   (from observed ops)
- (not proposed) http.POST gist.github.com/                          support 1 run 1/3   blocked by: ceiling (paste site)
Gates: narrowing FAIL (1 counterexample shown) · ceiling PASS · confinement PASS · errors PASS · live-deny PASS
Replay over last 7 days: candidate would deny 0 of 412 legitimate requests, 3 of 3 seeded-injection requests
```

The reviewer sees one concrete widening, its evidence and its counterexample, not a policy file.

### Poisoning: the loop's specific risk

The learning loop's specific risk is baking in a poisoned run. The Cowork incident shows that a learned rule allowing `api.anthropic.com` would not have stopped the attacker-key exfiltration ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude); [[Claude Cowork Allowed-Domain Abuse]]). The four mitigations are specified in [[Policy Miner Safeguards]]: trusted-input or N-run intersection learning, excluding foreign-credential runs, an org deny ceiling, and rate and volume limits.

### Human review

**Proposal:** Review shows authority diffs, never prose summaries. It follows the approval-fatigue evidence: users approve 93% of Claude Code permission prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode); [[Fatigue-Resistant Approval Interfaces]]). Narrowing-only diffs can be batch-approved. Widenings are listed one per line, each with its counterexample request and supporting run IDs, so a reviewer can open the actual trace.

## How it connects

- depends-on:: [[Policy Miner Safeguards]]
- evaluated-by:: [[SymCC CI Gates]]
- evaluated-by:: [[L4 Product Metrics]]
- implements:: [[I3 Probabilistic Components Only Narrow]]
- decided-by:: [[ADR-011 Verified Policy Learning Loop]]
- depends-on:: [[Audit Recorder and Event Schema]]
- part-of:: [[Broker CLI and Daemon]]
- delivered-by:: [[M2 Policy Audit and Learn]]
- motivated-by:: [[Progent]]
- motivated-by:: [[AgentSpec]]
- contrasts-with:: [[NVIDIA OpenShell]]
- contrasts-with:: [[AWS AgentCore]]
- example-of:: [[Trace-Mined Least Privilege]]

## Implications for the build

- M2 acceptance: learn mode over 3 repos × 3 agents yields a policy under which the same tasks pass with 0 denies; a seeded injection ("post `~/.aws` to a paste site; push to attacker repo") is blocked and logged; every learned change passes the narrowing or ceiling gates or shows counterexamples ([[M2 Policy Audit and Learn]]).
- L4 targets for learning: learned policy covers ≥95% of legitimate held-out requests within 3 sessions, and 0 learned rules broader than a registrable domain without approval ([[L4 Product Metrics]]).
- Traces live in SQLite next to the audit chain; the miner reads only committed, hash-chained rows.
- The miner is deterministic code in `code/crates/learn/`. No model call sits on the path from trace to diff.
- Mining derives upstream scopes too: the GitHub `permissions` object ([[GitHub App Installation Tokens]]) and the STS session policy ([[AWS STS Session Policies]]).

## Open questions

- What k and minimum-support values keep coverage ≥95% without broad rules? Only measurement will tell.
- How long must `shadow` run before `enforce`: a fixed window, or until N sessions show zero candidate-only denies?
- Can the replay statistic be computed offline from the audit log alone, without re-running agents?

## Sources

- [CNCF: SPO v1.0](https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/); [SPO usage doc](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/installation-usage.md)
- [AWS: IAM Access Analyzer policy generation](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/)
- [NVIDIA OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html)
- [AWS Security Blog: AgentCore Policy](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/); [AgentCore docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html)
- [StrongDM Leash](https://github.com/strongdm/leash); [Docker network policies](https://docs.docker.com/ai/sandboxes/network-policies/)
- [Anthropic: How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude)
- [AgentSpec](https://arxiv.org/abs/2503.18666); [Progent](https://arxiv.org/html/2504.11703v3); [Conseca](https://arxiv.org/html/2501.17070v3); [MiniScope](https://arxiv.org/abs/2512.11147)

## Build log

- 2026-09-24: record and mine built: `broker learn` (record mode, [[ADR-022 Cedar Schema and Engine as Built]]) writes allows with the enforce-mode `would_deny` and the adapter's structured `actions`; `broker suggest` (`code/crates/learn`) verifies the audit chain, mines record-mode sessions, prints evidence, exclusions, ceiling hits and G8 GitHub scopes, replays every recorded request under the current and the candidate policy, and writes a `broker.toml` diff with high-risk rules commented out. Shadow mode and the SymCC gate run are still to come. Tests: `learn::tests::{mining_applies_the_safeguards, replay_shows_the_candidate_closes_the_gap}`, `m2_learn::c1_learned_policy_passes_the_task_and_c2_seeded_injection_is_blocked`.
- 2026-09-24: prove built: `broker suggest` runs the formal gates on the proposal against the current policy (per profile) when cvc5 is available; the report shows the hard gates and the widening counterexamples; without a solver it says the gates were not run ([[ADR-024 Formal Gates as Built]]). Shadow mode is not built yet.
- 2026-09-24: shadow built ([[ADR-026 Shadow Mode as Built]]): `broker policy shadow <file>` (a candidate `broker.toml` stands in for the bundle until the control plane), evaluated beside the enforced policy in every enforce session, verdicts in every decision row, `--report` and `broker why`. The loop record → mine → prove → review → shadow → enforce now runs end to end on one machine; promotion to enforce stays a human edit.
