---
title: "I4 Repo Policy Only Narrows"
aliases: ["Repo Narrows Only"]
type: concept
section: architecture
tags: [sandbox/architecture, concept, invariant/i4, topic/policy, boundary/tb5, control/pin, milestone/m2]
status: built
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Repository-supplied policy can only narrow user and org policy; widening requires user or org scope, proved by SymCC implication gates."
related: ["[[broker.toml Human Policy Layer]]", "[[SymCC CI Gates]]", "[[Claude Code Pre-Trust Config Execution]]", "[[Codex CLI Project Config Autoload]]", "[[Request and Session Lifecycle]]", "[[Claude Code and sandbox-runtime]]", "[[I3 Probabilistic Components Only Narrow]]", "[[I5 Config Outside Writable Mounts]]", "[[Policy Engine and Entity Builder]]", "[[Broker CLI and Daemon]]", "[[Cedar]]", "[[Trust Boundaries]]", "[[M2 Policy Audit and Learn]]", "[[ADR-007 Cedar with a TOML Front-End]]"]
sources: ["https://nvd.nist.gov/vuln/detail/CVE-2025-59536", "https://nvd.nist.gov/vuln/detail/CVE-2026-21852", "https://github.com/advisories/GHSA-xrxf-jgv3-qmrm", "https://code.claude.com/docs/en/sandboxing", "https://docs.rs/cedar-policy-symcc"]
milestone: M2
code: ["code/crates/brokerd/src/repo_policy.rs", "code/crates/broker-cli/src/cmd/policy.rs", "code/crates/policy/src/cedar/mod.rs"]
---

# I4 Repo Policy Only Narrows

> Repository-supplied policy can only narrow user and org policy; widening requires user or org scope, proved by SymCC implication gates.

## Statement

**Proposal.** Policy comes in three scopes: **org** (signed bundle from the control plane or an org file), **user** (the developer's own config outside any repo), and **repo** (`.broker/broker.toml` and `.broker/policy.cedar` written by `broker init` and committed to the repository). For every request `r` in the schema:

`allow_effective(r) ⇒ allow_org∧user(r)`

That is, adding, editing or deleting repository policy can never make a request allowed that the org and user layers deny. Repository policy additionally may not name credential sources, issuer configuration, MCP server commands, backend selection or anything else that confers authority rather than restricting it. Widening needs a change at user or org scope.

## Rationale

The repository is attacker-writable content (trust boundary TB5, [[Trust Boundaries]]). Three advisories show repo config acting as authority:

- Claude Code CVE-2025-59536: code could run from an untrusted project before the user accepted the trust dialog ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-59536)).
- Claude Code CVE-2026-21852: a malicious repo's project-load configuration could redirect API calls and "exfiltrate data including Anthropic API keys before users confirmed trust" ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)). Both are in [[Claude Code Pre-Trust Config Execution]].
- Codex CLI CVE-2025-61260: Codex "automatically loads project-local .env and .codex/config.toml files without requiring user confirmation" ([GHSA](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)); see [[Codex CLI Project Config Autoload]].

The precedent for the rule is Claude Code itself: repository-level settings cannot set `mask` or `tlsTerminate` ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)); see [[Claude Code and sandbox-runtime]].

## How it is enforced

**Proposal.** Two mechanisms, one structural and one proved.

1. **Conjunctive evaluation (structural).** The [[Policy Engine and Entity Builder]] holds two Cedar policy sets per session: `P_base` (org plus user) and `P_repo` (may be empty). A derived request is allowed only if `P_base` allows it **and**, when `P_repo` is present, `P_repo` allows it. Because Cedar is default-deny and forbid-wins within each set ([[Cedar]]), the conjunction can only remove allows. Entity data from the repo layer (for example a narrower `branch_prefix`) is accepted only if it is a sub-value of the base value (prefix extension, subset of hosts).
2. **Implication gate (proved).** At `session.start` and in CI on the policy repo, run `check_implies(P_repo ∧ P_org, P_org)` from `cedar-policy-symcc` ([docs.rs](https://docs.rs/cedar-policy-symcc)). Structurally this always holds, so a failure means a bug in composition, and launch is refused ([[SymCC CI Gates]]).
3. **Compiler restrictions.** The TOML-to-Cedar compiler ([[broker.toml Human Policy Layer]]) rejects in repo scope any `credential = {...}` table, `[mcp.*]` server definitions, `backend` choices, and filesystem `write` grants outside `${repo}`/`${tmp}`. Rejection is a hard error naming the key.
4. **Load after approval.** Repo policy files are read by `brokerd`, never by the agent, and only after content-hash approval ([[I5 Config Outside Writable Mounts]]). A changed hash is treated as absent until re-approved, so a malicious commit can at worst remove the repo's own narrowing.

This appears in the request lifecycle at step 1: "computes the Task entity and its grants from the active bundle plus any narrowing repo policy" ([[Request and Session Lifecycle]]).

## Minimal test

**Proposal.** `tests/policy/repo_narrows`:

- a repo layer containing `permit(principal, action == Broker::Action::"git.push", resource);` alongside an org layer that forbids pushes to `main`: a push to `main` is still denied;
- a repo `broker.toml` with a `credential` table: compile error;
- property test over generated repo policy sets: for random requests, `allow_effective ⇒ allow_base`;
- the SymCC gate `check_implies(repo ∧ org, org)` runs in CI on fixtures and fails a deliberately broken composition function.

## What would violate it

- Merging repo policies into the base set (`P_base ∪ P_repo`), which lets a repo `permit` widen.
- Letting a repo specify `credential.ref = "keychain:..."` or a GitHub App permission object.
- Loading `.broker/` files from inside the sandbox or before approval.
- An `--trust-repo-policy` flag ([[I8 No Flag Disables Isolation]] forbids the flag route as well).

## How it connects

- motivated-by:: [[Claude Code Pre-Trust Config Execution]]
- motivated-by:: [[Codex CLI Project Config Autoload]]
- example-of:: [[Claude Code and sandbox-runtime]]
- depends-on:: [[SymCC CI Gates]]
- depends-on:: [[broker.toml Human Policy Layer]]
- depends-on:: [[Policy Engine and Entity Builder]]
- part-of:: [[Request and Session Lifecycle]]
- evaluated-by:: [[SymCC CI Gates]]
- delivered-by:: [[M2 Policy Audit and Learn]]
- decided-by:: [[ADR-007 Cedar with a TOML Front-End]]

## Implications for the build

- Ship the conjunctive evaluator from the first Cedar integration; retrofitting composition later is error-prone.
- `broker why` must say which layer denied (org, user or repo) and cite the policy ID.
- Share the implication-gate code with [[I3 Probabilistic Components Only Narrow]].

## Open questions

- Whether user-scope policy should itself be bounded by org policy with the same conjunctive rule (likely yes for managed fleets; unmanaged laptops have no org layer).
- How repo policy expresses path-level narrowing for filesystem grants without a second path canonicaliser (must reuse [[I6 Single Canonicaliser]]).

## Sources

- https://nvd.nist.gov/vuln/detail/CVE-2025-59536
- https://nvd.nist.gov/vuln/detail/CVE-2026-21852
- https://github.com/advisories/GHSA-xrxf-jgv3-qmrm
- https://code.claude.com/docs/en/sandboxing
- https://docs.rs/cedar-policy-symcc
- Report: invariant I4, request-life step 1; research note 05 section 3.5 (repo policy may only narrow org policy).

## Build log

- 2026-09-24: built. Structural: the repo layer (`.broker/broker.toml` compiled + `.broker/policy.cedar` raw) is a separate Cedar policy set conjoined with the base set; repo scope rejects `credential`, `passthrough`, `addrs`, `[issuers]`, `[tls]` and `[filesystem]`; `credential.use` is decided by the base set only. Tests: `cedar::tests::{repo_layer_only_narrows, raw_repo_cedar_only_narrows, repo_layers_never_widen}` (property: `allow_effective ⇒ allow_base` over generated repo layers) and the end-to-end `invariants::i4_repo_policy_only_narrows_and_needs_approval` (unapproved: ignored and announced; approved: narrows and cannot widen; any edit revokes; authority keys cannot be approved). The SymCC `check_implies(repo ∧ org, org)` gate is still to come.
