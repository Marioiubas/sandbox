---
title: "Two-Tier Isolation Design"
aliases: ["Standard Tier", "Hard Tier", "Per-Platform Layered Design"]
type: "concept"
section: "primitives"
summary: "Standard tier (OS process sandbox, default) and hard tier (microVM, opt-in) for macOS laptops, Linux laptops, CI runners and local MCP servers, with the layering rule: pair an OS or hard boundary with an inner Landlock/seccomp layer and put the policy boundary in the broker."
tags: [sandbox/primitives, concept, topic/isolation, topic/egress, platform/macos, platform/linux, platform/ci, control/iso, control/egress, boundary/tb2, boundary/tb3, invariant/i2, milestone/m0, milestone/phase2, evidence/secondary]
status: proposal
confidence: medium
milestone: M0
created: 2026-09-24
updated: 2026-09-24
related: ["[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[Seatbelt]]", "[[bubblewrap]]", "[[Landlock]]", "[[Firecracker]]", "[[Apple Virtualization Framework]]", "[[gVisor]]", "[[Sandbox Launcher]]", "[[MCP Guard]]", "[[Wasmtime and WASI]]", "[[Threat Model Non-Goals]]", "[[Open Questions and Unverified Claims]]", "[[seccomp-bpf]]", "[[Cloud Hypervisor]]", "[[Container Runtimes and Escape History]]", "[[Topology-Forced Egress]]", "[[Just-in-Time Credential Minting]]", "[[I1 No Secrets in the Sandbox]]", "[[I8 No Flag Disables Isolation]]", "[[I2 Fail-Closed Launch]]", "[[MVP Plan]]", "[[Core Trait Contracts]]", "[[SandboxEscapeBench]]", "[[M0 Contained Run]]", "[[L4 Product Metrics]]"]
---

# Two-Tier Isolation Design

The broker ships two isolation tiers per platform behind one launcher trait: a **standard tier** (OS process sandbox, the default, ~ms start, zero install) and an opt-in **hard tier** (a microVM or user-space kernel). The layering rule is never to rely on one primitive: pair a hard or OS-level boundary with an inner Landlock or seccomp layer, and put the *policy* boundary (network plus credentials) in the broker, so an escape yields a process with no secrets and no network except the capability-checked broker. This note is the per-platform recipe for macOS laptops, Linux laptops, CI runners and local MCP servers.

## Why two tiers

- Isolation is a solved commodity; the team needs composition, not invention (report). The standard-tier stack is exactly what srt and Codex ship in production ([srt](https://github.com/anthropic-experimental/sandbox-runtime); [Codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)).
- The standard tier does not cover host-kernel zero-days; that is a stated non-goal for this tier and the reason the hard tier exists ([[Threat Model Non-Goals]]).
- VMs cost start time and density on laptops: moving from Seatbelt to a Linux VM raised start from <5 ms to ~800 ms in one project's measurement ([apple/containerization#737](https://github.com/apple/containerization/issues/737)). The decision to default to the process sandbox is [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]].

## Comparison matrix (inputs to the choice)

Figures are from the primitive notes; "~" marks secondary or approximate values ([[Open Questions and Unverified Claims]]).

| Primitive | Boundary / TCB | Start | Memory overhead | Egress control | Platforms | Tier |
|---|---|---|---|---|---|---|
| [[Seatbelt]] | macOS kernel sandbox | ~ms | ~0 | localhost-port only | macOS | standard (macOS) |
| [[bubblewrap]] + [[seccomp-bpf]] | namespaces, shared kernel | ~ms | ~0 | no NIC; UDS to broker | Linux | standard (Linux) |
| [[Landlock]] | unprivileged LSM | µs | ~0 | TCP ports (ABI 4+) | Linux ≥5.13 | inner layer everywhere on Linux |
| [[Firecracker]] | KVM + ~83k-line Rust VMM | ≤125 ms ([spec](https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md)) | ≤5 MiB VMM + guest | vsock | Linux + KVM | hard (Linux CI, bare metal) |
| [[Cloud Hypervisor]] | KVM + ~106k-line Rust VMM | ~<200 ms (secondary) | n/a | vsock / virtio-net | Linux + KVM | hard (Linux laptop, virtiofs) |
| [[Apple Virtualization Framework]] | Apple hypervisor | "sub-second" | not published | vsock | macOS (containerization: 26 + Apple silicon) | hard (macOS) |
| [[gVisor]] | Go Sentry + seccomp | ~50 ms (secondary) | low | `--network=none` + UDS | Linux | hard (CI without KVM) |
| [[Container Runtimes and Escape History]] | shared kernel | ~ms | ~0 | netns | Linux | packaging only, inside a VM or gVisor |
| [[Wasmtime and WASI]] | Wasm JIT + host imports | µs–ms | small | host-implemented `wasi:http` | all | pure-logic MCP tools |

No same-hardware 2026 benchmark of all primitives exists in the record; measure on the team's CI and reference laptops.

## Recommended layered design per platform

**Proposal** (report table "Recommended layered design per platform").

| Platform | Standard tier (default) | Hard tier (opt-in) | Only egress path | Known sharp edges |
|---|---|---|---|---|
| macOS laptop | generated SBPL: deny writes except repo and tmp; deny reads of secret dirs; network only to a per-session broker localhost port; no Apple Events; no `trustd` | one Virtualization.framework VM per session (Apple `containerization`/`vminitd` model); repo via virtiofs or clone mode | loopback port with a per-session proxy credential; vsock in the hard tier | `sandbox-exec` deprecation; Go TLS needs `trustd`, which srt calls an exfiltration vector; VM fallback ~800 ms start |
| Linux laptop | bwrap (`--ro-bind / /`, repo bind, `.git/hooks` and `.git/config` read-only, agent config dirs read-only) + `--unshare-net` + seccomp (no new `AF_UNIX` after the bridge, no ptrace, bpf, raw sockets or keyctl) + Landlock (FS plus TCP connect to the bridge port only) + `PR_SET_NO_NEW_PRIVS` | Cloud Hypervisor or Firecracker VM | UDS bridge from the empty netns | Ubuntu AppArmor userns restriction; literal paths, so deny-globs miss files created after start |
| CI runner | Linux standard tier inside the runner VM; broker outside the sandbox holding runner OIDC | Firecracker on bare metal, else gVisor Systrap | UDS, or vsock in a VM | nested virtualization costs; `pull_request_target`-style triggers put untrusted text next to credentials ([Nx](https://nx.dev/blog/s1ngularity-postmortem)) |
| Local MCP servers | each server in its own standard-tier sandbox as a separate principal, with sentinel env vars | pure-logic tools as Wasm components hosted by the broker, `wasi:http` implemented by the broker (Wassette model) | broker, under a per-server policy | Wassette is "not production ready" ([microsoft/wassette](https://github.com/microsoft/wassette)); most MCP servers are Node or Python and need a process sandbox |

Sources for the sharp edges: [srt](https://github.com/anthropic-experimental/sandbox-runtime), [apple/containerization#737](https://github.com/apple/containerization/issues/737).

## The layering rule, made testable

**Proposal.** Every session has at least three independent layers, and the launcher's `probe()` must confirm each before launch:

1. **Outer boundary:** Seatbelt, bwrap namespaces, a VM, or gVisor.
2. **Inner restriction:** Landlock and seccomp on Linux (inside the VM guest too where supported); the SBPL itself on macOS, with deny rules on secret paths even though the outer rules already cover them.
3. **Policy boundary:** the broker, reachable over exactly one channel, holding every credential ([[Topology-Forced Egress]]; [[Just-in-Time Credential Minting]]).

Consequence: an escape from layer 1 or 2 yields a process that still has no secrets in env, files or `/proc` ([[I1 No Secrets in the Sandbox]]) and no network except a broker that authorizes every request. That is why the design can accept the standard tier's shared-kernel risk as a documented non-goal rather than a hole.

## Tier selection

**Proposal.**

- Default: standard tier on every platform.
- Hard tier on request (`--tier hard`) or by org policy (for example "CI jobs triggered by untrusted events run in the hard tier").
- Tier is an isolation *strengthening* only: no flag selects "none" ([[I8 No Flag Disables Isolation]]); if the requested tier cannot start, launch fails rather than falling back to a weaker tier ([[I2 Fail-Closed Launch]]).
- The chosen backend, versions and probe results are recorded in the session's audit event.

## Windows

Out of scope for v1. srt's alpha approach (a dedicated `srt-sandbox` local user with WFP filters allowing only loopback proxy ports 60080–60089) and the Windows 11 agent workspace (separate agent account and desktop, ACLs) point to account-based isolation rather than AppContainer for CLI agents ([srt](https://github.com/anthropic-experimental/sandbox-runtime); [Windows 11 security book](https://learn.microsoft.com/en-us/windows/security/book/operating-system-agentic-security)). srt's Windows alpha notes "DNS resolution bypasses the fence". Phase 3 adds Windows via WSL2 first ([[MVP Plan]]).

## Verdict for the broker

**Proposal.**

- **Use it for:** the launcher's backend selection and `probe()` contract; the documentation of what each tier does and does not defend.
- **Don't use it for:** claiming kernel-exploit resistance in the standard tier.
- **How we integrate it.** `SandboxBackend` implementations `macos-seatbelt` and `linux-native` in M0; `container` and `vm` in phase 2, all in `crates/launcher/backends/` ([[Sandbox Launcher]]; [[Core Trait Contracts]]). MCP servers reuse the same backends through [[MCP Guard]].

## How it connects

- decided-by:: [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]
- depends-on:: [[Seatbelt]] (macOS standard)
- depends-on:: [[bubblewrap]] (Linux standard)
- depends-on:: [[Landlock]] (inner layer)
- depends-on:: [[seccomp-bpf]] (inner layer)
- depends-on:: [[Firecracker]] (hard, Linux CI)
- depends-on:: [[Cloud Hypervisor]] (hard, Linux laptop)
- depends-on:: [[Apple Virtualization Framework]] (hard, macOS)
- depends-on:: [[gVisor]] (hard, CI without KVM)
- depends-on:: [[Wasmtime and WASI]] (pure-logic MCP tools)
- delivered-by:: [[Sandbox Launcher]]
- depends-on:: [[MCP Guard]] (per-server sandboxes)
- motivated-by:: [[Threat Model Non-Goals]] (kernel zero-days need the hard tier)
- evaluated-by:: [[SandboxEscapeBench]]

## Implications for the build

- M0 delivers only the two standard-tier backends and fail-closed launch ([[M0 Contained Run]]).
- The L4 threshold "sandbox start ≤150 ms (native)" applies to the standard tier ([[L4 Product Metrics]]); the hard tier needs its own measured figure.
- Run SandboxEscapeBench scenarios at difficulty 1–3 against each backend, nested in VMs (L6).

## Open questions

- No same-hardware benchmark; VZ memory overhead, QEMU `microvm` and realistic VM density are missing ([[Open Questions and Unverified Claims]]).
- Windows AppContainer and Hyperlight were not reviewed.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
