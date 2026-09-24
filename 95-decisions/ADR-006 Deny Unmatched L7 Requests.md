---
title: "ADR-006 Deny Unmatched L7 Requests"
aliases: ["ADR-006"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/egress, topic/policy, topic/tls, control/egress, boundary/tb4, invariant/i4, invariant/i6, invariant/i7, invariant/i9, milestone/m1, milestone/m2]
status: built
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Within an allowed domain, method and path rules are authorization: unmatched L7 requests are denied, rejecting Vercel's pass-without-credential semantics."
related: ["[[Vercel Sandbox]]", "[[TLS Termination and Per-Session CA]]", "[[Cedar]]", "[[Example Cedar Policies]]", "[[broker.toml Human Policy Layer]]", "[[ADR-004 Selective TLS Termination with Per-Session CA]]", "[[Local Credential Proxies]]", "[[NVIDIA OpenShell]]", "[[OpenAI Codex CLI]]", "[[GitHub MCP Toxic Flow]]", "[[GitLost GitHub Agentic Workflows Leak]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[sandbox-runtime Empty Allowlist Bypass]]", "[[July 2026 Artifactory Egress Incident]]", "[[Policy Engine and Entity Builder]]", "[[GitHub API Adapter]]", "[[Git Smart-HTTP Adapter]]", "[[Policy Learning Loop]]", "[[SymCC CI Gates]]", "[[Conformance Probe Matrix]]", "[[L3 Real-Work Utility]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[I4 Repo Policy Only Narrows]]", "[[I6 Single Canonicaliser]]", "[[I7 Reject Foreign Credentials]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[ADR-007 Cedar with a TOML Front-End]]", "[[ADR-011 Verified Policy Learning Loop]]", "[[M1 Secrets Outside]]", "[[Risk Register]]"]
sources: ["https://vercel.com/docs/sandbox/concepts/firewall", "https://invariantlabs.ai/blog/mcp-github-vulnerability", "https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53", "https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md", "https://github.com/Infisical/agent-vault", "https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html", "https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/", "https://github.com/advisories/GHSA-9gqj-5w7c-vx47", "https://anthropic.com/engineering/claude-code-auto-mode"]
code: ["code/crates/policy/src/l7.rs"]
---

# ADR-006 Deny Unmatched L7 Requests

> Within an allowed domain, method and path rules are authorization: unmatched L7 requests are denied, rejecting Vercel's pass-without-credential semantics.

## Status

**Proposed** (2026-09-24). Method and path rules arrive in [[M1 Secrets Outside]], and the Cedar-backed enforce mode in M2. Not superseded.

## Context

Once the broker terminates TLS for a host ([[ADR-004 Selective TLS Termination with Per-Session CA]]), it sees each request's method and path. The question is what happens to a request to an allowed host that matches no L7 rule.

**Vercel's answer is "pass through".** "Matchers never block": a request that does not match a rule passes through unchanged, just without the credential. Restricting paths requires routing non-matching traffic to your own proxy with `forwardURL` ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall); [[Vercel Sandbox]]). Research note 03 lists this as the first anti-pattern to avoid.

**Allowed domains are the exfiltration channel in the incident record.**

- GitHub MCP toxic flow: a public issue drove the agent to leak private repositories through a public PR on github.com ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability); [[GitHub MCP Toxic Flow]]).
- GitLost: an org-read agent posted a private README to a public issue ([The Hacker News](https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html); [[GitLost GitHub Agentic Workflows Leak]]).
- Cowork: an attacker-planted key was used against the allowlisted api.anthropic.com ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude); [[Claude Cowork Allowed-Domain Abuse]]).
- July 2026: the only verified path ran through the sanctioned Artifactory egress point. Its details remain unconfirmed ([axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53); [[July 2026 Artifactory Egress Incident]]).
- Conformance category 1 is built from these cases: a gist, issue comment or package publish on an allowed forge, or a push to an attacker repo on github.com ([[Conformance Probe Matrix]]).

**Pass-through defeats the other controls.** An unmatched request forwarded "unchanged" carries whatever the sandbox wrote: an attacker-supplied credential, an anonymous write to a public endpoint, or data encoded in the path or body. Stripping foreign credentials ([[I7 Reject Foreign Credentials]]) narrows this, but the request still reaches the upstream. The rule then decorates traffic rather than authorizing it.

**Default deny is the verified semantics of the policy engine.** Cedar's Lean proofs include "A request is allowed only if it is explicitly permitted" and "If some forbid policy is satisfied, then the request is denied" ([cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md); [[Cedar]]).

**Precedent for L7 denial.**

- OpenShell's L7 proxy allows or denies at method and path level, with `enforce` and `audit` modes ([OpenShell docs](https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html); [[NVIDIA OpenShell]]).
- Codex's managed proxy restricts read-only mode to GET/HEAD/OPTIONS ([Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/); [[OpenAI Codex CLI]]).
- Agent Vault has `unmatched_host_policy=deny`, but only at host level ([Agent Vault](https://github.com/Infisical/agent-vault); [[Local Credential Proxies]]).

**Empty-list semantics have already failed once.** In srt, empty `allowedDomains` meant allow-all ([GHSA](https://github.com/advisories/GHSA-9gqj-5w7c-vx47); [[sandbox-runtime Empty Allowlist Bypass]]).

## Decision

**Proposal.** In enforce mode, for every request on the L7 path:

1. The claiming protocol adapter (git, GitHub API, registry, LLM API, MCP, or generic HTTP) classifies the request into one or more Cedar requests, for example `http.POST` on a PathPrefix plus `credential.use` ([[Policy Engine and Entity Builder]]).
2. The request is forwarded **only if every derived Cedar request is allowed**. A request that no permit matches is denied. The broker returns an error response to the sandbox and logs a reason and the determining policy IDs. It is **never** forwarded, with or without a credential.
3. An adapter error, an unparseable request, or an empty classification denies.
4. If a host has any L7 rule, all of its traffic is terminated and authorized; there is no L4 splice for that host.
5. In `broker.toml`, listing `methods` or `paths` for a host means everything else on that host is denied. An empty list denies. It never means "any" ([[broker.toml Human Policy Layer]]).
6. Every redirect hop is re-evaluated as a new request.

Record and shadow modes log would-deny decisions under [[Policy Learning Loop]] rules ([[ADR-011 Verified Policy Learning Loop]]). They never attach a credential to a request that no rule matches.

Example ([[Example Cedar Policies]], **Proposal; not compiled**): the git push permit allows only `refs/heads/agent/*` on the task repo without force. Any other push has no permit and is denied, which is what `broker why` explains.

Testable form:

- Conformance category 1 probes are 100% denied.
- For random `(method, path)` pairs on an L7 host, the forward decision equals the conjunction of adapter requests (property test).
- A host with `methods = []` denies everything.
- Every deny has a logged reason.

## Alternatives considered

| Alternative | Pros | Cons (evidence) | Why rejected |
|---|---|---|---|
| **Pass without credential** (Vercel) | Fewer false denies; the credential is never misused on unlisted paths | The request still reaches the upstream with whatever the sandbox wrote; allowed-domain exfiltration (public PR, gist, issue, publish) is untouched; restricting paths needs a separate proxy ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)) | Method and path rules are authorization, not decoration |
| **Host-level allow only** | Simple; no termination for most hosts | Cannot distinguish `pr.create` from `pr.merge`, or read from publish | Keeps the domain as the unit of trust, which the incidents show is too coarse |
| **Prompt the human on every unmatched request** | Preserves utility on novel endpoints | Users approve 93% of Claude Code permission prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)); fatigue makes this a rubber stamp ([[Fatigue-Resistant Approval Interfaces]]) | Deny by default. Step-up goes through `grant.request` with an authority diff, and only for explicitly approvable verbs |
| **Audit-only for unmatched requests** | No breakage during rollout | Leaves the exfiltration path open in production | Allowed only in record and shadow modes, never as the enforce default |

## Consequences

**Positive.**

- The verb semantics that differentiate the product become enforceable: PR creation versus merge, `agent/*` pushes versus `main`, registry reads versus publish ([[GitHub API Adapter]], [[Git Smart-HTTP Adapter]]).
- Formal gates mean something: for an L7 host, SymCC's `check_implies` over the policy set describes exactly what can be forwarded ([[SymCC CI Gates]]).
- Foreign-credential rejection and deny-by-default reinforce each other.

**Negative.**

- False denies on legitimate endpoints nobody wrote a rule for. The utility thresholds cap this: ≤2% of tasks blocked by a necessary action and per-action false-deny ≤0.5% ([[L3 Real-Work Utility]]).
- Rules must come from somewhere. That makes the learning loop and good default profiles mandatory rather than optional.
- Every deny needs a clear `broker why` explanation, or users will disable the product. That behaviour is itself adversary A5.

**Follow-up work.**

- Default L7 profiles for GitHub, npm, PyPI, crates and the LLM APIs.
- Deny responses that name the missing rule.
- `broker suggest` output from would-deny logs.

## Revisit triggers

- L3 false-deny or task-block rates exceed thresholds after learning has run for 3 sessions.
- A protocol (for example WebSockets after upgrade, or gRPC streams) cannot be classified per message. Document its coarser semantics in a new ADR rather than silently passing it.

## Invariants and components affected

- **Upholds** [[I7 Reject Foreign Credentials]] (unmatched requests never reach upstream) and [[I9 Hash-Chained Audit Outside the Sandbox]] (every deny is logged with a reason).
- **Upholds** [[I6 Single Canonicaliser]] (paths are canonicalised before matching) and [[I4 Repo Policy Only Narrows]] (repo policy can add L7 rules only as narrowing).
- **Weakens none.**
- Components: [[TLS Termination and Per-Session CA]], [[Policy Engine and Entity Builder]], all protocol adapters.

## How it connects

- contrasts-with:: [[Vercel Sandbox]]
- depends-on:: [[ADR-004 Selective TLS Termination with Per-Session CA]]
- depends-on:: [[Cedar]]
- depends-on:: [[ADR-007 Cedar with a TOML Front-End]]
- implements:: [[Example Cedar Policies]]
- implements:: [[broker.toml Human Policy Layer]]
- part-of:: [[TLS Termination and Per-Session CA]]
- mitigates:: [[GitHub MCP Toxic Flow]]
- mitigates:: [[GitLost GitHub Agentic Workflows Leak]]
- mitigates:: [[Claude Cowork Allowed-Domain Abuse]]
- motivated-by:: [[sandbox-runtime Empty Allowlist Bypass]]
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[L3 Real-Work Utility]]
- delivered-by:: [[M1 Secrets Outside]]

## Implications for the build

- The M1 acceptance tests are direct instances of this ADR: pushes to another repo, to `main`, or with force are denied, and `broker why` explains each.
- The TOML compiler must emit no catch-all permit for a host with L7 rules. Add a SymCC `check_always_allows` gate per high-risk action.
- Log the adapter verb (for example `git.push refs/heads/agent/x`) on every deny, so learning and explanations have material.

## Open questions

- The coarse semantics for WebSocket frames and long-lived gRPC streams are undecided (policy applies at the upgrade request only).
- Allowed domains remain covert channels through timing and request counts. Bandwidth is measured, not claimed zero ([[Risk Register]]).
- The July 2026 incident details are unverified.

## Sources

- https://vercel.com/docs/sandbox/concepts/firewall
- https://invariantlabs.ai/blog/mcp-github-vulnerability
- https://thehackernews.com/2026/07/public-github-issue-could-trick-github.html
- https://www.anthropic.com/engineering/how-we-contain-claude
- https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53
- https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md
- https://github.com/Infisical/agent-vault
- https://docs.nvidia.com/openshell/latest/tutorials/first-network-policy.html
- https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/
- https://github.com/advisories/GHSA-9gqj-5w7c-vx47
- https://anthropic.com/engineering/claude-code-auto-mode
- Report: "L4 by default, L7 only where credentials or verbs matter" ("Vercel's matchers never block semantics are the anti-pattern to avoid"), conformance probe matrix, decision table row "Unmatched L7 requests". Research note 03 Q3 anti-patterns.

## Build log

- 2026-09-24: built: `policy::l7::authorize` denies any action no grant rule matches (`l7_no_rule_matched`); tested by `methods_paths_and_default_deny` and `cat2_unmatched_paths_and_methods_deny`.
