---
title: "ADR-028 M2 Plan Items Built Differently or Deferred"
aliases: ["ADR-028"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/policy, topic/learning, topic/audit, milestone/m2]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Where M2 as built differs from its task list: grants compile to policy text (not entities) so the formal gates can prove them; a differential property test replaces compile/decompile round-trips; per-file-operation would-be decisions, per-request process ancestry, OpenAPI operation mapping (G1), rate limits (P4), newly-registered-domain and object-storage ceilings, `[profile.*]` tables, `broker init` and LLM diff explanations are deferred."
related: ["[[M2 Policy Audit and Learn]]", "[[Policy Engine and Entity Builder]]", "[[broker.toml Human Policy Layer]]", "[[Policy Miner Safeguards]]", "[[Policy Learning Loop]]", "[[Audit Recorder and Event Schema]]", "[[ADR-022 Cedar Schema and Engine as Built]]", "[[ADR-024 Formal Gates as Built]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
---

# ADR-028 M2 Plan Items Built Differently or Deferred

> The M2 task list, reconciled with what was built: two items are built another way for a stated reason, and the rest are deferred to the milestone that brings their inputs.

## Status

built (2026-09-24).

## Context

[[M2 Policy Audit and Learn]] lists tasks written before any code. Building steps 1-6 (ADR-022 to ADR-027) settled most of them; this ADR records the remainder so that the milestone note's checklist is true.

## Decision

**Built differently**

1. **Grants are policy text, not entities.** [[Policy Engine and Entity Builder]] proposed grants as entities so expiry and revocation are data updates. As built, each grant compiles to `@id`-named permits. Reason: the formal gates quantify over entity data as arbitrary ([[ADR-024 Formal Gates as Built]] found confinement unprovable while it lived in entity attributes); grants in entities would make narrowing, ceiling and confinement proofs vacuous. Expiry stays data (`Task.expires_at` with the `task-expiry` forbid); revocation takes effect at the next session start, which compiles the policy anyway.
2. **No compile/decompile round-trip test.** There is no decompiler to test: TOML is the only authored form. The meaning-preservation check is the differential property test `cedar_agrees_with_the_reference` (compiled Cedar vs the M1 reference semantics) plus golden compile tests and the gates.

**Deferred**

3. **Per-file-operation would-be decisions** in record mode: file access is decided by the kernel layers (Seatbelt, Landlock, bwrap) with no per-operation callback to the broker. Kernel denials already surface as `fs.denied` where the platform reports them.
4. **Per-request process ancestry** (binary path, argv hash): sessions record the agent binary path hash; attributing each connection to a process needs `SO_PEERCRED` on the Linux Unix-socket ingress and has no cheap equivalent on the macOS loopback ingress. Deferred to [[M3 CI Identity and MCP]], where per-binary MCP principals need the same attribution.
5. **G1** (map GitHub requests to OpenAPI operations): arrives with the GitHub API adapter in M3. **P4** (rate and volume limits on learned rules) and the **newly-registered-domain** and **arbitrary object storage** ceiling categories need data sources the endpoint does not have yet (registration dates; a bucket-ownership model with the S3 adapter in M3).
6. **`[profile.<name>]` tables and `broker init`**: built-in profiles are files shipped with the binary and the user layer uses top-level `[[egress]]`/`[filesystem]`; per-repo profile tables and `broker init` move to M4 (onboarding).
7. **`check_equivalent` on recompilation** of unchanged TOML: the policy is compiled per session from the same code; the check matters once bundles are compiled centrally (control plane).
8. **LLM explanations of learned diffs** (`suggest` "may" ask an LLM to explain): not built; the report is deterministic text.
9. **C1 over 3 real repositories × 3 real agents**: the mechanics pass with a deterministic agent (`m2_learn`); the 3 × 3 run needs Codex and Gemini CLI installed and signed in on the test machine.

## Consequences

- The formal proofs are about the text the engine evaluates.
- Learned policy quality for GitHub traffic stays path-based until M3 (G1).
- The M2 note's checklist reflects this ADR; the milestone stays open until C1 runs with real agents.

## Invariants affected

None weakened.

## Relationships

- decided-by:: M2 build
- motivated-by:: [[M2 Policy Audit and Learn]]

## Build log

- 2026-09-24: created while reconciling the M2 task list.
