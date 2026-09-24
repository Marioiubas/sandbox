---
title: "Policy Miner Safeguards"
aliases: ["Conservative Generalisation", "Org Deny Ceiling", "Learning Poisoning Mitigations"]
type: concept
section: policy
tags: [sandbox/policy, concept, topic/learning, topic/policy, invariant/i3, invariant/i7, milestone/m2, evidence/unverified]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Generalisation rules (operation-level entries over wildcards, minimum support before prefix collapse, domain suffix only after k subdomains, never widen methods, risk classes never auto-granted, derive GitHub permissions and STS policy from observed operations) and poisoning defenses (trusted-input or N-run intersection, exclude foreign-credential runs, org deny ceiling, rate and volume limits)."
related: ["[[Policy Learning Loop]]", "[[SymCC CI Gates]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[AgentSpec]]", "[[Risk Register]]", "[[I7 Reject Foreign Credentials]]", "[[GitHub App Installation Tokens]]", "[[AWS STS Session Policies]]", "[[Trace-Mined Least Privilege]]", "[[L4 Product Metrics]]", "[[Trifecta Session Labels]]", "[[Hostname Canonicaliser]]", "[[GitHub API Adapter]]", "[[July 2026 Artifactory Egress Incident]]", "[[Open Questions and Unverified Claims]]", "[[I3 Probabilistic Components Only Narrow]]", "[[Example Cedar Policies]]"]
sources: ["https://www.anthropic.com/engineering/how-we-contain-claude", "https://arxiv.org/abs/2503.18666", "https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app", "https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html", "https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/", "https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53", "https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/"]
code: ["code/crates/learn/src/generalise.rs"]
---

# Policy Miner Safeguards

> Generalisation rules (operation-level entries over wildcards, minimum support before prefix collapse, domain suffix only after k subdomains, never widen methods, risk classes never auto-granted, derive GitHub permissions and STS policy from observed operations) and poisoning defenses (trusted-input or N-run intersection, exclude foreign-credential runs, org deny ceiling, rate and volume limits).

## Summary

The miner in the [[Policy Learning Loop]] faces two failure modes. It can **over-generalise**, turning a handful of observed requests into a wildcard that grants far more than any task used. And it can **learn from a poisoned run**, encoding an attacker's exfiltration path as "normal". This note specifies the deterministic rules that bound both. [[SymCC CI Gates]] then prove each emitted diff against a ceiling, and a human reviews every widening. The risk row is "Learned policy over-grants or is poisoned" in [[Risk Register]].

## Details

### Generalisation rules (Proposal)

These come from the report's stage-2 rules and the landscape note's miner design. All thresholds are tunable. None is a measured value.

| # | Rule | Rationale |
|---|---|---|
| G1 | **Operation-level entries over wildcards.** Map `POST /repos/acme/web/pulls` to the GitHub OpenAPI operation `pulls/create` and emit that, not `POST /repos/**` | Semantic verbs are what reviewers can reason about ([[GitHub API Adapter]]) |
| G2 | **Templatise before counting.** Collapse IDs, SHAs and UUIDs to `{id}`; template GitHub paths as `/repos/{owner}/{repo}/pulls` | Otherwise every PR number is a separate "rule" |
| G3 | **Minimum support before collapsing a path prefix.** Collapse `/a/b/x`, `/a/b/y` to `/a/b/*` only after n distinct children across m runs | One odd request must not widen a subtree |
| G4 | **Domain suffix only after k distinct subdomains.** `*.example.com` is proposed only after k different canonical subdomains | Suffix rules are the cheapest widening |
| G5 | **Never widen methods** beyond those observed for that path. No GET-to-`http.read` or POST-to-`http.write` promotion | Method is the capability |
| G6 | **Never widen write methods to unobserved hosts.** | From the identity note's learning inference |
| G7 | **Classify risk** (write, auth-bearing, publish, delete) and **never auto-grant** high-risk verbs; they are emitted as "needs review" with evidence | High-risk verbs are where misuse costs most |
| G8 | **Derive upstream scope from observed operations.** Compute the GitHub `permissions` object and the STS session policy from what was used | Keeps minted credentials minimal; IAM Access Analyzer does this from CloudTrail ([AWS](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/)) |
| G9 | **No rule broader than a registrable domain** without explicit approval | This is an L4 release threshold: 0 such learned rules ([[L4 Product Metrics]]) |
| G10 | **Canonical inputs only.** The miner consumes the canonical host from [[Hostname Canonicaliser]], never raw SNI or `Host` strings | Proofs and rules must be about canonical names |

G8 in practice: a GitHub installation token takes a `repositories` selection (up to 500) and a per-category `permissions` object; omitting them inherits the whole installation ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)). An STS session policy (inline plus up to 10 ARNs, 2,048 characters combined) is intersected with the role ([AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)). The miner should emit both explicitly, never omit them ([[GitHub App Installation Tokens]], [[AWS STS Session Policies]]).

### Why a static ceiling is non-negotiable

AgentSpec's LLM-generated safety rules reached 95.56% precision but only **70.96% recall** ([arXiv 2503.18666](https://arxiv.org/abs/2503.18666)). Generated rules miss hazards. The same holds for a trace miner: it can only learn what it saw, and it cannot know that something it saw was malicious. So the result must be bounded by a ceiling written independently of any generation ([[AgentSpec]], [[I3 Probabilistic Components Only Narrow]]).

### Poisoning defenses (Proposal, from the report)

The learning loop's specific risk is baking in a poisoned run. In the Cowork incident, a file carried instructions plus an attacker API key, and "the egress proxy checked the destination, saw api.anthropic.com, and let it through" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). A learned rule allowing `api.anthropic.com` would not have stopped it ([[Claude Cowork Allowed-Domain Abuse]]). Four mitigations:

**P1. Learn only from trusted inputs, or from the intersection of N independent runs.**
- *Trusted-input runs:* sessions whose `untrusted_input` label stayed false ([[Trifecta Session Labels]]). No public issue, web page or ticket body entered the context.
- *N-run intersection:* a tuple is proposed only if it appears in at least N independent runs (different sessions, ideally different days or users). A one-off injection rarely repeats identically across runs.

**P2. Exclude any request that carried a foreign credential or tripped the sentinel check.** Such a request is already rejected at the proxy ([[I7 Reject Foreign Credentials]]). The miner must also drop it, and **every other request from that session**, from the training set, and flag the session for review.

**P3. Keep an org-level deny ceiling** that no learned or edited policy can exceed:
- paste sites;
- raw IPs;
- tunnels such as `*.ngrok.*`;
- newly registered domains;
- arbitrary object storage.

Sketch (**Proposal; not compiled**; `dest_class` values are illustrative):

```cedar
@id("ceiling-no-raw-ip")
forbid (principal, action in [Broker::Action::"http.read", Broker::Action::"http.write"], resource)
when { context.dest_class == "ip_literal" || context.dest_class == "metadata" || context.dest_class == "link_local" };

@id("ceiling-no-paste-or-tunnel")
forbid (principal, action in [Broker::Action::"http.read", Broker::Action::"http.write"], resource)
when { resource in Broker::Host::"category:paste" || resource in Broker::Host::"category:tunnel" };
```

The category entities would be maintained in org entity data. The schema sketch declares `Host` without a parent, so a category hierarchy (`Host in [HostCategory]`) must be added first ([[Broker Cedar Schema]]). The ceiling is enforced at runtime *and* used as `P_ceiling` in the `check_implies(P_new, P_ceiling)` gate ([[SymCC CI Gates]]).

**P4. Keep rate and volume limits on allowed domains,** because allowed domains remain exfiltration channels. The July 2026 incident's only verified path went through the *sanctioned* Artifactory egress point, not DNS, and its details remain unconfirmed ([axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53); [[July 2026 Artifactory Egress Incident]]). **Proposal:** the miner also learns per-host request and byte baselines, and enforcement caps them at a multiple of the baseline. Cedar sees `body_bytes` in `HttpCtx`; per-session counters are exposed as context the same way sequence state is.

### Human review as the last safeguard

**Proposal:** Every diff states which safeguards applied (runs used, N, excluded sessions and why, ceiling hits). Rules that hit the ceiling are listed as "observed but blocked", so a reviewer sees attempted exfiltration rather than having it silently dropped.

> [!question] Unverified
> No study of learning least-privilege policy from compromised runs exists in the record; SPO's own article does not discuss recording compromised workloads ([CNCF](https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/)). The effectiveness of P1-P4 is a hypothesis to measure ([[Trace-Mined Least Privilege]], [[Open Questions and Unverified Claims]]).

## How it connects

- part-of:: [[Policy Learning Loop]]
- evaluated-by:: [[SymCC CI Gates]]
- evaluated-by:: [[L4 Product Metrics]]
- mitigates:: [[Risk Register]] (row "Learned policy over-grants or is poisoned")
- motivated-by:: [[Claude Cowork Allowed-Domain Abuse]]
- motivated-by:: [[AgentSpec]]
- motivated-by:: [[July 2026 Artifactory Egress Incident]]
- depends-on:: [[I7 Reject Foreign Credentials]]
- depends-on:: [[Trifecta Session Labels]]
- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[GitHub App Installation Tokens]]
- depends-on:: [[AWS STS Session Policies]]
- example-of:: [[Trace-Mined Least Privilege]]

## Implications for the build

- Encode G1-G10 as unit-tested functions in `code/crates/learn/`, each with a test that a poisoned or sparse trace set does *not* produce the widening.
- Ship the org ceiling as a template in `code/policies/` and make `broker suggest` refuse to run without one.
- Build a poisoning fixture for M2: three benign runs plus one run with a seeded "post `~/.aws` to a paste site" injection. The mined policy must not contain the paste-site rule, and the diff must list it as "observed but blocked".
- Record k, n, m and N defaults in the policy reference docs, and report them in every diff.

## Open questions

- Which newly-registered-domain feed is acceptable for an Apache-2.0 endpoint, and how fresh must it be?
- What N gives a useful intersection without starving small repos of evidence?
- Should the miner learn body-size baselines per verb or per host?

## Sources

- [Anthropic: How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude)
- [AgentSpec](https://arxiv.org/abs/2503.18666)
- [GitHub REST: installation tokens](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)
- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [AWS: IAM Access Analyzer policy generation](https://aws.amazon.com/blogs/security/iam-access-analyzer-makes-it-easier-to-implement-least-privilege-permissions-by-generating-iam-policies-based-on-access-activity/)
- [axeploit: July 2026 incident](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53)
- [CNCF: SPO v1.0](https://www.cncf.io/blog/2026/06/26/security-profiles-operator-v1-stable-apis-security-hardened-and-shaping-upstream-kubernetes/)

## Build log

- 2026-09-24: G2 (identifier templating), G3 (prefix collapse after n=3 children in m=2 sessions), G4 (`*.name` after k=3 subdomains), G5 (one rule per observed method), G7 (high-risk proposals commented out: DELETE and non-standard methods, force pushes, pushes outside `refs/heads/agent/`), G8 (GitHub `contents` scope from observed fetch/push), G9 (never above the registrable domain or over a public suffix), P1 (minimum support, default 2 sessions), P2 (sessions with a foreign credential, wrong-host sentinel or reflected secret excluded entirely), P3 (ceiling hits listed as observed but blocked; the ceiling is in every policy). P4 (rate and volume limits) is not built. Defaults are in `learn::generalise::Options`.
- 2026-09-24: status `built` for G2-G10 and P1-P3 (G6 holds by construction: only observed methods on observed hosts are proposed; G10: the miner reads canonical hosts from audit rows). G1, P4 and the newly-registered-domain and object-storage ceiling categories are deferred ([[ADR-028 M2 Plan Items Built Differently or Deferred]]).
