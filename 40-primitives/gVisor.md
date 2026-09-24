---
title: "gVisor"
aliases: ["runsc", "Systrap"]
type: "primitive"
section: "primitives"
summary: "Go user-space kernel (Sentry) whose seccomp filter forbids host connect(2); Systrap works inside VMs without nested virtualization (~50 ms start); the CI and cloud tier where KVM is absent."
tags: [sandbox/primitives, primitive, topic/isolation, topic/egress, platform/linux, platform/ci, platform/cloud, control/iso, control/egress, boundary/tb2, milestone/phase2, evidence/secondary]
status: verified
confidence: medium
milestone: phase2
created: 2026-09-24
updated: 2026-09-24
related: ["[[Firecracker]]", "[[Container Runtimes and Escape History]]", "[[Two-Tier Isolation Design]]", "[[Topology-Forced Egress]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[Cursor and Gemini CLI]]", "[[Cloud Sandbox Runtimes]]", "[[Open Questions and Unverified Claims]]", "[[I6 Single Canonicaliser]]", "[[Sandbox Launcher]]", "[[M3 CI Identity and MCP]]", "[[SandboxEscapeBench]]"]
---

# gVisor

gVisor (`runsc`) interposes a Go re-implementation of the Linux kernel interface, the Sentry, between the workload and the host kernel. Its default Systrap platform works inside ordinary VMs without nested virtualization and starts in about 50 ms (secondary), and the Sentry's own seccomp filter forbids host `connect(2)`, so networking can be cut to nothing but a Unix socket to the broker. That makes it the broker's hard tier for Linux CI runners and cloud hosts where KVM is absent or nested.

## Boundary and trusted computing base

- **Sentry.** A userspace application kernel reimplementing the "system call interface, memory management, filesystems, a network stack, process management". It runs under a seccomp filter that "prohibits system calls like exec(2), connect(2)" on the host ([gVisor security intro](https://gvisor.dev/docs/architecture_guide/intro/)).
- **Gofer.** A "slightly-more-trusted companion process" that mediates file access for the Sentry ([gVisor security intro](https://gvisor.dev/docs/architecture_guide/intro/)).
- **Out of scope by design.** Side-channel (Spectre-class) attacks and bugs inside the sandboxed application ([gVisor security intro](https://gvisor.dev/docs/architecture_guide/intro/)).
- **TCB for an escape.** The Sentry (memory-safe Go) plus the narrow set of host syscalls its seccomp filter allows, plus the Gofer. The host kernel remains behind it, but the application never talks to it directly.
- **Licence and maturity.** Apache-2.0, GA; Google Cloud Run runs "billions of containers" on it (secondary) ([emirb.github.io](https://emirb.github.io/blog/microvm-2026/)).

## Platforms (how syscalls reach the Sentry)

| Platform | Mechanism | Where it fits |
|---|---|---|
| **Systrap** (default since mid-2023) | seccomp `SECCOMP_RET_TRAP`: "the kernel send[s] SIGSYS to the triggering thread, which hands over control to gVisor" | best in VMs and nested virtualization |
| **KVM** | Sentry runs as a guest using hardware virtualization | "runs best on bare-metal"; nested virtualization adds significant overhead |
| **ptrace** | legacy | "no longer supported and is expected to eventually be removed" |

Source: [gVisor platforms](https://gvisor.dev/docs/architecture_guide/platforms/).

Systrap is the reason gVisor matters here: GitHub-hosted runners and most cloud VMs lack usable nested KVM, so [[Firecracker]] is off the table there, yet Systrap still gives a user-space kernel boundary.

## Performance (dated, with conditions)

| Figure | Value | Source |
|---|---|---|
| Start | ~50 ms | secondary, Mar 2026 ([emirb.github.io](https://emirb.github.io/blog/microvm-2026/)) |
| Modal (gVisor-based) start | ~300 ms | same source |
| DigitalOcean App Platform after moving to Systrap | "2x throughput on Node.js, 7x on WordPress" | same source (vendor-reported, secondary) |
| Kubernetes benchmark, gVisor release-20260202.0 vs runc | CPU −1.7%, HTTP req/s −42%, sequential read +551% (page-cache effect), latency better than runc in that test | DigitalOcean c5-8vcpu nested VMs, 2 CPU / 4 Gi per pod ([container-runtime-benchmarks](https://github.com/bikramkgupta/container-runtime-benchmarks)) |

> [!question] Unverified
> The ~50 ms start is secondary, and no 2026 Systrap per-syscall latency figure exists in the record ([[Open Questions and Unverified Claims]]). The HTTP −42% matters for an agent that runs `npm install` through a proxy; measure it with the broker in the path.

## Networking: the egress property the broker wants

- The Sentry's seccomp filter forbids host `connect(2)`; all networking goes through the in-Sentry netstack ([gVisor security intro](https://gvisor.dev/docs/architecture_guide/intro/)).
- **Proposal (research-note inference):** run `runsc` with `--network=none` plus a Unix socket to the broker. The workload then has no host-routable network at all, which is the gVisor form of [[Topology-Forced Egress]].
- A small open-source wrapper, agentjail, already uses "gVisor + MITM" as an optional transparent tunnel to enforce `network.allowed_hosts` ([agentjail docs](https://agentjail.io/docs/concepts/sandbox/)), and Modal runs gVisor containers with a beta domain allowlist, see [[Cloud Sandbox Runtimes]].

## Security record

- **No Sentry escape CVE was found for 2023–2026** in the research session. Whether that reflects real absence or poor indexing is unverified ([[Open Questions and Unverified Claims]]).
- The known gVisor-related "escape" is a **policy** failure: GKE Sandbox network policy allowed access to the GCE metadata API (30 Dec 2020, no CVE, found by Bastien Chatelard of Koyeb) (background, pre-2025) ([cloudvulndb](https://www.cloudvulndb.org/gke-gvisor-sandbox-escape)). The lesson carries directly into the broker: block link-local and metadata addresses (169.254.169.254) by default, which is part of [[I6 Single Canonicaliser]].

## Sharp edges

- Linux only; no macOS.
- Workloads needing exotic syscalls, device access, or high random I/O and network throughput suffer (research-note inference, consistent with the −42% HTTP figure).
- Not the only layer against a determined attacker when a VM is available (research-note inference): prefer [[Firecracker]] on bare metal.
- `runsc` is a drop-in OCI runtime for Docker, containerd and Kubernetes (research-note inference), which is convenient but tempts a design that reintroduces a container daemon; never expose that daemon's socket to the sandbox ([[Container Runtimes and Escape History]]).

## Verdict for the broker

**Proposal.**

- **Use it for:** the CI hard tier when the runner cannot do KVM (the report's CI row: "Firecracker on bare metal, else gVisor Systrap"); cloud workers; a clean egress choke point via `--network=none` plus a UDS to the broker.
- **Don't use it for:** macOS; laptops where bwrap already provides the standard tier; the sole boundary when KVM is available; workloads that are I/O- or network-bound without measuring.
- **How we integrate it.** Phase-2 `container`/`vm`-class backend in [[Sandbox Launcher]]:
  - invoke `runsc` directly with an OCI bundle generated by the launcher (no Docker daemon), `--network=none`, the repo as the only writable mount, and the broker's UDS bind-mounted as the egress endpoint (`EgressEndpoint::Uds`);
  - inside the gVisor sandbox, still apply the standard-tier inner layers where the Sentry supports them (seccomp inside is emulated by the Sentry; Landlock support inside gVisor is not documented in the record, so do not rely on it);
  - `probe()` reports the `runsc` version and platform (require Systrap or KVM; reject ptrace) and fails closed.

## How it connects

- part-of:: [[Two-Tier Isolation Design]] (CI and cloud hard tier without KVM)
- decided-by:: [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]
- contrasts-with:: [[Firecracker]] (needs KVM, stronger boundary on bare metal)
- contrasts-with:: [[Container Runtimes and Escape History]] (shared-kernel runtimes it replaces)
- implements:: [[Topology-Forced Egress]] (`--network=none` plus UDS)
- example-of:: [[Cursor and Gemini CLI]] (Gemini CLI offers a gVisor/runsc sandbox)
- example-of:: [[Cloud Sandbox Runtimes]] (Modal runs on gVisor)

## Implications for the build

- CI hard tier is phase 2; M3's CI acceptance runs the Linux standard tier inside the runner VM ([[M3 CI Identity and MCP]]).
- Add a CI matrix leg with `runsc` once the backend exists and run [[SandboxEscapeBench]] against it.
- Measure broker-in-path throughput under gVisor before recommending it for dependency-heavy tasks.

## Open questions

- No 2023–2026 Sentry escape CVE found; per-syscall Systrap latency in 2026 unknown ([[Open Questions and Unverified Claims]]).
- Landlock and seccomp semantics *inside* gVisor are not covered by the record.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
