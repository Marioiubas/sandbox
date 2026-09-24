---
title: "ADR-002 OS Process Sandbox by Default with VM Hard Tier"
aliases: ["ADR-002"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/isolation, platform/macos, platform/linux, platform/ci, control/iso, boundary/tb2, invariant/i2, invariant/i8, milestone/m0, milestone/phase2, evidence/secondary]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Default to the OS process sandbox (Seatbelt; bwrap+seccomp+Landlock) with a microVM as opt-in hard tier, rejecting microVM-by-default and containers."
related: ["[[Two-Tier Isolation Design]]", "[[Seatbelt]]", "[[bubblewrap]]", "[[Firecracker]]", "[[Apple Virtualization Framework]]", "[[Docker Sandboxes]]", "[[Sandbox Launcher]]", "[[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]", "[[Landlock]]", "[[seccomp-bpf]]", "[[Cloud Hypervisor]]", "[[gVisor]]", "[[Container Runtimes and Escape History]]", "[[SandboxEscapeBench]]", "[[Threat Model Non-Goals]]", "[[L4 Product Metrics]]", "[[I2 Fail-Closed Launch]]", "[[I5 Config Outside Writable Mounts]]", "[[I8 No Flag Disables Isolation]]", "[[ADR-001 Value Lives in the Broker]]", "[[ADR-003 Topology-Enforced Egress]]", "[[Risk Register]]", "[[M0 Contained Run]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://github.com/anthropic-experimental/sandbox-runtime", "https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md", "https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md", "https://github.com/apple/containerization", "https://github.com/apple/containerization/issues/737", "https://emirb.github.io/blog/microvm-2026/", "https://gvisor.dev/docs/architecture_guide/platforms/", "https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/", "https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities", "https://docs.docker.com/ai/sandboxes/security/defaults/", "https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/", "https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/", "https://aws.amazon.com/security/security-bulletins/rss/2026-003-aws/", "https://cvefeed.io/vuln/detail/CVE-2026-5747", "https://landlock.io/rust-landlock/landlock/enum.ABI.html"]
---

# ADR-002 OS Process Sandbox by Default with VM Hard Tier

> Default to the OS process sandbox (Seatbelt; bwrap+seccomp+Landlock) with a microVM as opt-in hard tier, rejecting microVM-by-default and containers.

## Status

**Proposed** (2026-09-24). The standard tier is delivered in [[M0 Contained Run]]; the VM and container backends are phase 2. Not superseded. The macOS specifics are refined by [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]].

## Context

Every `broker run` must wrap the agent in some boundary (trust boundary TB2). The choice is between a shared-kernel OS process sandbox, a container, and a microVM per session.

**Start time and footprint on laptops.**

- OS process sandboxes start in about a millisecond: bwrap plus netns plus seccomp and Seatbelt are "~ms", Landlock is "µs" (report primitive table).
- Firecracker: ≤125 ms to guest init and ≤5 MiB VMM overhead, KVM only ([Firecracker spec](https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md)).
- Cloud Hypervisor: under 200 ms; gVisor ~50 ms. Both figures are secondary ([emirb](https://emirb.github.io/blog/microvm-2026/)).
- Apple `containerization`: "sub-second", one VM per container, needs macOS 26 and Apple silicon ([apple/containerization](https://github.com/apple/containerization)).
- One project measured a Linux-VM fallback on macOS moving start time from <5 ms to ~800 ms ([apple/containerization#737](https://github.com/apple/containerization/issues/737)).
- The proposed release threshold is sandbox start ≤150 ms (native) ([[L4 Product Metrics]]).
- Research note 01 infers laptop density of "a handful of concurrent VMs", because each guest's working set is tens to hundreds of MiB. That is an inference from secondary data; no same-hardware benchmark exists.

**Production precedent.** srt and Codex already run the standard-tier recipe. srt uses Seatbelt on macOS and bubblewrap with the network namespace "removed entirely" on Linux ([srt](https://github.com/anthropic-experimental/sandbox-runtime)). Codex uses `--ro-bind / /`, read-only re-binds of `.git` and `.codex`, `--unshare-user --unshare-pid --unshare-net`, `PR_SET_NO_NEW_PRIVS` and seccomp ([codex README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)).

**VM-by-default precedent.** Docker Sandboxes runs each agent in a microVM with a private Docker engine ([Docker docs](https://docs.docker.com/ai/sandboxes/security/defaults/)). It reached GA on 30 January 2026 for macOS and Windows, with Linux listed as "what's next" ([Docker blog](https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/)). Reported friction includes many VMs across many projects, an IDE/VM network split, and no way to mask individual files in the project ([INNOQ](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)).

**Security record.**

- runc/crun shares the host kernel: Leaky Vessels (Jan 2024), then three procfs and masked-path escapes (Nov 2025) ([CNCF](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)).
- UK AISI found frontier models reliably exploit container misconfigurations, with escape success scaling roughly log-linearly with inference compute ([UK AISI](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities); [[SandboxEscapeBench]]).
- VMMs are attack surface too: Firecracker had a jailer symlink CVE and a virtio-PCI out-of-bounds write in 2026 ([AWS](https://aws.amazon.com/security/security-bulletins/rss/2026-003-aws/); [cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-5747)).

**What the tier must defend.** The policy boundary (network plus credentials) sits in the broker, so an escape from the process sandbox yields "a process with no secrets and no network except the capability-checked broker" ([[Two-Tier Isolation Design]]). Host-kernel zero-days in the standard tier are an explicit non-goal that the VM tier covers ([[Threat Model Non-Goals]]).

## Decision

**Proposal.**

1. **Standard tier is the default on every platform.**
   - macOS: generated SBPL through `sandbox-exec` ([[Seatbelt]]).
   - Linux: [[bubblewrap]] with `--ro-bind / /`, a repo bind, read-only `.git/hooks`, `.git/config` and agent config dirs, and `--unshare-net`; plus [[seccomp-bpf]] (no new `AF_UNIX` after the bridge; no ptrace, bpf, raw sockets or keyctl); plus [[Landlock]] (filesystem, and TCP connect to the bridge port only); plus `PR_SET_NO_NEW_PRIVS`.
2. **Hard tier is opt-in** through `--tier hard` or org policy (for example CI jobs triggered by untrusted events).
   - macOS: one [[Apple Virtualization Framework]] VM per session.
   - Linux laptops: [[Cloud Hypervisor]] or [[Firecracker]].
   - CI: Firecracker on bare metal, else [[gVisor]] Systrap.
   - Egress is vsock only.
3. **Containers are never the primary boundary.** runc or crun appears only as packaging inside a VM or gVisor.
4. **The tier can only strengthen isolation.** No flag selects "none". If the requested tier cannot start, launch fails; there is no fallback to a weaker tier.

Testable form:

- Default `broker run` selects `macos-seatbelt` or `linux-native`, and the session audit event records the backend, versions and probe results.
- Native start is ≤150 ms on the reference machines.
- `--tier hard` on a host without a usable hypervisor exits non-zero.
- No code path launches an agent under a bare container backend.

## Alternatives considered

| Alternative | Pros | Cons (evidence) | Why rejected |
|---|---|---|---|
| **MicroVM by default** (Docker sbx model) | Separate guest kernel; covers host-kernel zero-days; Docker ships it | ~100 ms to sub-second start vs ~ms; a macOS fallback measured <5 ms → ~800 ms ([#737](https://github.com/apple/containerization/issues/737)); VZ containerization needs macOS 26 and Apple silicon; Firecracker needs KVM; per-VM memory limits density; Linux sbx was not GA at launch | VMs cost start time and density on laptops; the broker, not the kernel, carries the policy boundary |
| **Containers** (runc/crun + seccomp + userns) | ~ms start; familiar packaging | Shared kernel with a recent escape record ([CNCF](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)); models exploit container misconfigurations ([UK AISI](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities)); needs a container runtime on the laptop | No stronger than the process sandbox, and adds an install dependency ([[Container Runtimes and Escape History]]) |
| **gVisor by default** | ~50 ms (secondary); works in VMs without nested virtualization ([gVisor](https://gvisor.dev/docs/architecture_guide/platforms/)) | Linux only; no macOS story | Kept as the CI hard tier where KVM is absent |
| **Single-layer OS sandbox** (no inner Landlock or seccomp) | Simpler | One bug is a full escape | Violates the layering rule: never rely on one primitive |

## Consequences

**Positive.**

- Zero-install feel: nothing to install beyond the binary (bubblewrap on Linux), with ~ms start.
- The product uses the same stack as srt and Codex, so an Apple change that breaks Seatbelt breaks incumbents too.
- An outer-plus-inner layering, with the broker as the third layer, makes an escape yield no secrets and no network.

**Negative.**

- Host-kernel zero-days are out of scope in the standard tier; this must be stated in the shipped threat model.
- Platform variance ([[Risk Register]] R6, R7):
  - `sandbox-exec` is deprecated with no removal date.
  - Ubuntu 24.04+ gates unprivileged userns via AppArmor ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).
  - Landlock ABI varies by kernel (ABI 9 on Linux 7.1) ([rust-landlock](https://landlock.io/rust-landlock/landlock/enum.ABI.html)).
  - Linux path rules are literal, so deny-globs miss files created after start.
- Go TLS on macOS needs `trustd`, which srt calls an exfiltration vector ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).

**Follow-up work.**

- `broker doctor` and an installer AppArmor profile.
- Runtime Landlock ABI probing with best-effort layering, recorded in the audit event.
- VZ and Firecracker backends in phase 2.
- Measure start time and memory on our own CI and laptops; the secondary figures are planning numbers only.

## Revisit triggers

- SandboxEscapeBench scenarios at difficulty 1–3 escape the standard tier with frontier models at default budget (the L6 threshold is 0 escapes).
- A measured VM start on reference laptops meets the ≤150 ms budget with acceptable memory, which would make VM-by-default affordable.
- Apple removes `sandbox-exec` (see [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]).
- Enterprise buyers require a separate guest kernel by default.

## Invariants and components affected

- **Upholds** [[I2 Fail-Closed Launch]]: no tier fallback, and each layer is probed. **Upholds** [[I8 No Flag Disables Isolation]]: the tier only strengthens. **Upholds** [[I5 Config Outside Writable Mounts]]: agent config and git hooks are mounted read-only.
- **Weakens none**, but accepts the shared-kernel risk as a documented non-goal.
- Components: [[Sandbox Launcher]] (`SandboxBackend` with `probe()` and `launch()`).

## How it connects

- implements:: [[Two-Tier Isolation Design]]
- depends-on:: [[Seatbelt]]
- depends-on:: [[bubblewrap]]
- depends-on:: [[Landlock]]
- depends-on:: [[seccomp-bpf]]
- depends-on:: [[Firecracker]]
- depends-on:: [[Apple Virtualization Framework]]
- contrasts-with:: [[Docker Sandboxes]]
- delivered-by:: [[Sandbox Launcher]]
- delivered-by:: [[M0 Contained Run]]
- evaluated-by:: [[SandboxEscapeBench]]
- evaluated-by:: [[L4 Product Metrics]]
- motivated-by:: [[ADR-001 Value Lives in the Broker]]

## Implications for the build

- M0 builds only the `macos-seatbelt` and `linux-native` backends; `container` and `vm` are stubs that fail closed.
- M0 acceptance requires `broker run` to refuse launch when any layer is missing, and to deny reading `~/.ssh/id_ed25519` ([[M0 Contained Run]]).
- The egress half of the tier is decided separately in [[ADR-003 Topology-Enforced Egress]].

## Open questions

- There is no same-hardware 2026 benchmark of all primitives. Cloud Hypervisor, gVisor and Apple-silicon per-VM memory figures are secondary ([[Open Questions and Unverified Claims]]).
- Coding-agent VM density per laptop is not in the record.
- The bubblewrap licence is believed LGPL-2.0+ but was not verified.

## Sources

- https://github.com/anthropic-experimental/sandbox-runtime
- https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md
- https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md
- https://github.com/apple/containerization
- https://github.com/apple/containerization/issues/737
- https://emirb.github.io/blog/microvm-2026/
- https://gvisor.dev/docs/architecture_guide/platforms/
- https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/
- https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities
- https://docs.docker.com/ai/sandboxes/security/defaults/
- https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/
- https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/
- https://aws.amazon.com/security/security-bulletins/rss/2026-003-aws/
- https://cvefeed.io/vuln/detail/CVE-2026-5747
- https://landlock.io/rust-landlock/landlock/enum.ABI.html
- Report: "Isolation is a solved commodity" (primitive table, per-platform design, fail-closed proposal), non-goals, decision table row "Default isolation", L4 and L6 thresholds. Research note 01 Q1 and Q7.
