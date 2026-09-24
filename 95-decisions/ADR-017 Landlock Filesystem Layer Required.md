---
title: "ADR-017 Landlock Filesystem Layer Required"
aliases: ["ADR-017"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/isolation, platform/linux, control/iso, control/fs, boundary/tb2, invariant/i2, invariant/i8, milestone/m0]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "On Linux the Landlock filesystem layer (ABI 1+) is a required layer and its absence refuses launch; only Landlock TCP rules degrade below ABI 4, where the empty network namespace remains the network boundary; no flag or repo policy can change this."
related: ["[[Landlock]]", "[[I2 Fail-Closed Launch]]", "[[I8 No Flag Disables Isolation]]", "[[Sandbox Launcher]]", "[[bubblewrap]]", "[[Risk Register]]", "[[MOC Decisions]]"]
sources: ["https://docs.kernel.org/userspace-api/landlock.html"]
superseded_by:
code: ["code/crates/launcher/src/backends/linux/inner.rs"]
---

# ADR-017 Landlock Filesystem Layer Required

> The Landlock filesystem layer is required on Linux; only its TCP rules may degrade below ABI 4.

## Status

Built (2026-09-24). Settles the open question in [[I2 Fail-Closed Launch]]: "Whether any Landlock degradation should be allowed at all … An ADR must settle it before M0 closes."

## Context

[[I2 Fail-Closed Launch]] lists Landlock network rules below ABI 4 as degradable and the Landlock filesystem layer as degradable only by an org-signed bundle. Org bundles arrive with the control plane (phase 2), so in M0 nothing can mark Landlock best-effort. Landlock ABI 1 shipped in Linux 5.13 and ABI 4 (TCP port rules) in 6.7 ([kernel.org](https://docs.kernel.org/userspace-api/landlock.html)); Ubuntu 22.04's GA kernel is 5.15. Inside the sandbox the empty network namespace already removes every route except the bridge, so Landlock's TCP rule is defence in depth; the filesystem allowlist is what closes the deny-glob hole for secrets created after start ([[Filesystem Control and Rollback]]).

## Decision

1. `landlock_fs` (ABI ≥1, ruleset at least partially enforced) is a **required** layer of `linux-native`. If the probe reports ABI 0, or `restrict_self` reports `NotEnforced`, launch is refused.
2. `landlock_net` (TCP connect only to the bridge port) is applied when the kernel has ABI ≥4 and reported as an **optional** layer otherwise; `broker doctor` shows which.
3. Scopes (abstract Unix sockets, signals) are applied at ABI ≥6.
4. No CLI flag, environment variable or user or repository policy can change 1-3 ([[I8 No Flag Disables Isolation]]). An org-signed override may be designed with bundles in phase 2, by a new ADR.

**Testable as:** `i2_launch_refuses_when_any_layer_is_missing` (fault `landlock_fs`); `broker doctor` on a Linux host lists both layers with the kernel's ABI.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Landlock best-effort everywhere | A missing required layer that only warns is the fail-open pattern I2 forbids |
| Require ABI 4 | Excludes Ubuntu 22.04 GA kernels, while the netns already enforces the network boundary |
| Make Landlock optional, rely on bwrap masks | bwrap masks are literal paths at start; later-created secrets outside masked dirs would be readable |

## Consequences

Kernels without Landlock (before 5.13, or with Landlock disabled in the LSM list) are unsupported for the standard tier until a VM backend exists. On kernels with ABI ≥4, agents cannot connect to TCP servers they start inside the sandbox (only the bridge port is allowed); this utility cost is documented in `code/docs/threat-model.md`.

## Invariants affected

Upholds [[I2 Fail-Closed Launch]] and [[I8 No Flag Disables Isolation]]; narrows the degradable set in I2 until org bundles exist.

## Relationships

- motivated-by:: [[Landlock]]
- decided-by:: [[I2 Fail-Closed Launch]]

## Build log

- 2026-09-24: created and built. Measured: Landlock ABI 6 on Linux 6.12 (Docker Desktop VM); ruleset fully enforced; conformance category 10 passes with it on.
