---
title: "MOC Policy"
aliases: []
type: moc
section: policy
tags: [sandbox/policy, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Cedar decides each request while analysis gates every policy change: language, schema, example policies, trifecta labels, SymCC gates, the record-then-restrict learning loop and the human TOML layer."
related: ["[[Cedar]]", "[[Broker Cedar Schema]]", "[[Example Cedar Policies]]", "[[Trifecta Session Labels]]", "[[SymCC CI Gates]]", "[[Policy Learning Loop]]", "[[Policy Miner Safeguards]]", "[[broker.toml Human Policy Layer]]", "[[Native Config Exporters]]", "[[MOC Architecture]]", "[[MOC Research]]", "[[ADR-007 Cedar with a TOML Front-End]]", "[[ADR-011 Verified Policy Learning Loop]]"]
sources: []
---

# MOC Policy

> Cedar decides each request while analysis gates every policy change: language, schema, example policies, trifecta labels, SymCC gates, the record-then-restrict learning loop and the human TOML layer.

Cedar decides each request while formal analysis gates every policy change. Cedar's semantics are proved in Lean and its symbolic compiler lets CI prove that a learned or edited policy is a *narrowing*. The guarantees stop at the enforcement point: how raw traffic becomes Cedar entities must still be tested empirically, and proofs hold only relative to a schema with canonical host strings.

Grants are Cedar *entities*, not policy text, so expiry and revocation are data updates. Humans write a small TOML layer that compiles to Cedar; the broker computes session labels (the trifecta) that only it can see.

## Language and model

- [[Cedar]] — Cedar as the decision core: Lean-proved semantics (forbid wins, default deny, order-independence, sound typing), sound and complete SMT compilation, 4-11 µs median latency, no regex, agent-gateway precedent (AgentCore Policy, Leash), and the hard edges of its guarantees.
- [[Broker Cedar Schema]] — The Broker namespace schema sketch (Trifecta and Session types; Group, User, Agent, Task, Host, PathPrefix, Repo, Credential, McpServer, Dir, File; HttpCtx, GitCtx, CredCtx, McpCtx; http.*, git.*, credential.use, mcp.call_tool, fs.* actions), with grants as entities and time as epoch seconds.
- [[Example Cedar Policies]] — The five sketch policies (credential host ceiling, task expiry, push only to refs/heads/agent/* on the task repo without force, Rule of Two approval gate, pinned MCP servers only) plus the group-push and publish-requires-approval examples.
- [[broker.toml Human Policy Layer]] — The small human-facing TOML (profile filesystem.write and deny_read, egress array-of-tables entries with host, protocol, methods, git allow rules and credential kinds) that compiles to Cedar; empty lists and unmatched requests fail closed; a repository copy can only narrow.

## Session context

- [[Trifecta Session Labels]] — How the broker computes untrusted_input, sensitive_read and external_effect from systems of record, enforces Rule of Two as a Cedar forbid, optionally forbids public-sink writes whenever untrusted_input is set, limits label creep with one session per task, and exposes sequence rules (Invariant's '->') as automaton context.

## Verification

- [[SymCC CI Gates]] — cedar-policy-symcc's six queries (never_errors, always_allows, always_denies, implies, equivalent, disjoint, each with counterexamples, on cvc5) and the six merge-blocking gates: narrowing, org ceiling, credential confinement, no runtime errors, live deny rules, tenant disjointness. This is eval layer L5.

## Least-privilege learning

Record, mine, prove, review, shadow, enforce.

- [[Policy Learning Loop]] — Record in audit mode with L7 visibility, generalise conservatively, emit a Cedar diff with evidence and replay stats, run SymCC gates, open a PR, shadow (log would-deny) and only then enforce; the record, shadow and enforce modes; an LLM may explain a diff but never merge it.
- [[Policy Miner Safeguards]] — Generalisation rules (operation-level entries over wildcards, minimum support before prefix collapse, domain suffix only after k subdomains, never widen methods, risk classes never auto-granted, derive GitHub permissions and STS policy from observed operations) and poisoning defenses (trusted-input or N-run intersection, exclude foreign-credential runs, org deny ceiling, rate and volume limits).

## Interoperability

- [[Native Config Exporters]] — Compile the one Cedar source to Claude Code managed settings, Codex requirements.toml, Cursor sandbox.json and OpenShell YAML so each vendor's own controls become defense in depth instead of competitors.

## How this section connects

- Runtime evaluation happens in [[Policy Engine and Entity Builder]]; bundles ship through [[Control Plane and Policy Bundles]].
- The decisions are [[ADR-007 Cedar with a TOML Front-End]], [[ADR-010 Session-Level Trifecta Labels in the MVP]] and [[ADR-011 Verified Policy Learning Loop]].
- Research roots: [[Progent]] (monotonic confinement), [[AgentSpec]] (why generated rules need a ceiling), [[Lethal Trifecta]] and [[Agents Rule of Two]]; open extensions in [[Provenance-Aware Cedar]] and [[Trace-Mined Least Privilege]].
- [[SymCC CI Gates]] is eval layer L5 in the [[Evaluation Harness]]; M2 delivers most of this section ([[M2 Policy Audit and Learn]]).
