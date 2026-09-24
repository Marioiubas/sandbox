---
title: "Firecracker"
aliases: ["Firecracker microVM"]
type: "primitive"
section: "primitives"
summary: "KVM microVM with a ~83k-line Rust VMM (<=125 ms to guest init, <=5 MiB overhead); hard tier for Linux CI on bare metal or nested-capable hosts; pin >=1.14.4/1.15.1 and prefer MMIO after the 2026 jailer and virtio-PCI CVEs."
tags: [sandbox/primitives, primitive, topic/isolation, platform/linux, platform/ci, platform/cloud, control/iso, boundary/tb2, milestone/phase2, evidence/secondary]
status: verified
confidence: high
milestone: phase2
created: 2026-09-24
updated: 2026-09-24
related: ["[[Two-Tier Isolation Design]]", "[[Cloud Hypervisor]]", "[[gVisor]]", "[[Sandbox Launcher]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[Filesystem Control and Rollback]]", "[[Core Trait Contracts]]", "[[Topology-Forced Egress]]", "[[Open Questions and Unverified Claims]]", "[[I2 Fail-Closed Launch]]", "[[Tech Stack]]", "[[SandboxEscapeBench]]", "[[Vercel Sandbox]]", "[[M0 Contained Run]]", "[[L4 Product Metrics]]", "[[Risk Register]]"]
---

# Firecracker

Firecracker is a KVM-based microVM monitor written in Rust that boots a minimal Linux guest to `/sbin/init` in at most 125 ms with at most 5 MiB of VMM overhead. It is the broker's hard-tier boundary for Linux CI runners and self-hosted Linux hosts that expose KVM (bare metal or nested-capable), not for macOS laptops. Two 2026 CVEs (jailer symlink, virtio-PCI out-of-bounds write) mean the VMM itself is attack surface: pin patched versions and prefer the MMIO transport.

## Boundary and trusted computing base

- **Mechanism.** Each sandbox is a separate guest kernel running under KVM, with a single-purpose Rust VMM process per microVM and a `jailer` helper that sets up the VMM's chroot, namespaces and cgroups before dropping privileges ([Firecracker SPECIFICATION.md](https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md); [AWS bulletin 2026-003](https://aws.amazon.com/security/security-bulletins/rss/2026-003-aws/)).
- **TCB size.** About 83k lines of Rust for the VMM, compared with roughly 106k for Cloud Hypervisor and ~40M lines of C in the Linux kernel that containers share (secondary source, March 2026) ([emirb.github.io](https://emirb.github.io/blog/microvm-2026/)). The TCB for a guest escape is KVM plus this VMM plus the jailer; the guest kernel is *not* in the host's TCB.
- **Production record.** Firecracker runs AWS Lambda and Fargate, "millions of production workloads, and trillions of requests per month" per the NSDI 2020 paper (background, pre-2025; the paper's numeric figures such as microVMs per second per host were not re-verified in the record) ([USENIX NSDI'20](https://www.usenix.org/conference/nsdi20/presentation/agache)).
- **Licence and platform.** Apache-2.0, Rust, KVM only, Linux hosts only (research note 01 comparison matrix). No macOS support, because there is no KVM on macOS.

### Devices the broker cares about

| Device / channel | What it gives | Broker relevance |
|---|---|---|
| vsock | Host↔guest socket with no IP stack | **Proposal:** the only guest↔broker channel in the hard tier (research-note inference) |
| tap / virtio-net | Guest NIC | Only if its sole peer is the broker; otherwise do not attach |
| MMDS (metadata service) | Per-VM metadata endpoint | **Proposal:** a slot for per-VM short-lived capability tokens (research-note inference) |
| Block devices | ext4 or overlay images | The repo must be shipped as an image and synced; there is **no virtiofs** |

Because Firecracker exposes block devices rather than a shared filesystem (1 GiB/s storage at ≤70% of a host core per the spec), a laptop "edit the repo in place" workflow does not map onto it; [[Cloud Hypervisor]] is the Linux choice when virtiofs is required ([Firecracker SPECIFICATION.md](https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md)).

## Performance (with dates and conditions)

All spec figures are from `SPECIFICATION.md` on `main`, measured on M5D.metal and M6G.metal hosts ([Firecracker SPECIFICATION.md](https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md)):

| Metric | Published figure | Condition |
|---|---|---|
| Boot to guest `/sbin/init` | ≤125 ms from the `InstanceStart` API call | minimal guest |
| VMM memory overhead | ≤5 MiB | 1 vCPU / 128 MiB guest |
| API socket available | within 8 CPU-ms (wall clock ~12 ms, range 6–60 ms) | VMM process start |
| Guest network | up to 14.5 Gbps at ≤80% of a host core; 25 Gbps at 100% | virtio-net |
| Added network latency | 0.06 ms average | |
| Storage | up to 1 GiB/s at ≤70% of a core | block device |
| Compute | >95% of bare metal | |

The scoreboard repeats the headline "under 125 ms with under 5 MiB" from the project site ([firecracker-microvm.github.io](https://firecracker-microvm.github.io/)).

> [!question] Unverified
> Snapshot restore at ~28 ms is a **secondary** figure, attributed to Lambda SnapStart by one write-up ([emirb.github.io, 27 Mar 2026](https://emirb.github.io/blog/microvm-2026/)) and reported for a hobby build by another ([DEV Community](https://dev.to/adwitiya/how-i-built-sandboxes-that-boot-in-28ms-using-firecracker-snapshots-i0k)). Treat it as a planning number and measure on the team's own CI hardware ([[Open Questions and Unverified Claims]]).

Memory in practice is dominated by the guest, not the VMM: a coding-agent guest with Node and Python toolchains will use tens to hundreds of MiB, so a laptop hosts only a handful of concurrent VMs (research-note inference; no primary density figure exists in the record).

## Security record

| CVE | Published | Component | Impact | Affected | Fixed |
|---|---|---|---|---|---|
| CVE-2026-1386 | 23 Jan 2026 | jailer | "arbitrary host file overwrite via symlink"; attacker needs access to the jailer folder; AWS services not affected | ≤1.13.1 and 1.14.0 | 1.13.2, 1.14.1 ([AWS bulletin 2026-003](https://aws.amazon.com/security/security-bulletins/rss/2026-003-aws/)) |
| CVE-2026-5747 | 8 Apr 2026 | virtio-PCI transport | OOB write by rewriting queue config registers after device activation; needs guest root; host code execution needs "custom guest kernel or specific snapshot configurations"; CVSS 3.1 7.5 / CVSS 4.0 8.7 | 1.13.0–1.14.3, 1.15.0 | 1.14.4, 1.15.1 ([cvefeed](https://cvefeed.io/vuln/detail/CVE-2026-5747)) |

Operational consequences (research-note inference): run the jailer with a root-owned jailer directory that no untrusted party can write (CVE-2026-1386), prefer the MMIO transport over virtio-PCI until virtio-PCI is audited (CVE-2026-5747), and pin ≥1.14.4 or ≥1.15.1.

## Sharp edges

- **KVM required.** Most hosted CI runners are themselves VMs; Firecracker then needs nested virtualization, which the report lists as a CI sharp edge ("nested virtualization costs"). For comparison, gVisor documents that its own KVM platform "runs best on bare-metal" and that nested virtualization adds significant overhead ([gVisor platforms](https://gvisor.dev/docs/architecture_guide/platforms/)). Where KVM is absent, the CI hard tier is [[gVisor]] Systrap instead.
- **No shared filesystem.** Repo sync, build caches and the git working copy need an image or a sync step, which interacts with [[Filesystem Control and Rollback]] (a CoW disk or snapshot becomes the rollback layer).
- **No GPU.** Not a target for GPU workloads (research-note inference).
- **Kernel exploits inside the guest are contained, VMM bugs are not.** The 2026 CVEs are exactly the class that breaks the hard tier; version pinning is a security control, not hygiene.

## Verdict for the broker

**Proposal.**

- **Use it for:** the hard tier on Linux CI runners on bare metal or nested-capable hosts (the report's primitive-table verdict and CI row); pre-warmed snapshot pools of agent VMs in self-hosted CI; any Linux deployment where the operator wants a kernel boundary rather than a namespace boundary.
- **Don't use it for:** macOS laptops (no KVM); Linux laptop workflows that need the repo mounted live (use [[Cloud Hypervisor]] with virtiofs); GPU work; the default tier (the standard tier is the OS process sandbox per [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]).
- **How we integrate it.** A `vm` backend of the `SandboxBackend` trait in [[Core Trait Contracts]], implemented in `crates/launcher/backends/vm` and delivered in phase 2 ([[Sandbox Launcher]]):
  - drive the Firecracker HTTP API over its Unix socket from Rust (hyper over a UDS); spawn through the jailer, never the bare VMM;
  - attach **only vsock** to the guest; the `EgressEndpoint::Vsock(cid, port)` variant is the only egress path, per [[Topology-Forced Egress]];
  - ship the repo as a per-session ext4 or overlay image; commit results back through a reviewed merge;
  - `probe()` must check `/dev/kvm`, the Firecracker version (refuse <1.14.4 on 1.14.x and <1.15.1 on 1.15.x) and the transport, and fail closed per [[I2 Fail-Closed Launch]].
  - Crate choice is open: the record names no Firecracker client crate; a thin hand-written API client is the default until one is verified ([[Tech Stack]]).

## How it connects

- part-of:: [[Two-Tier Isolation Design]] (hard tier, Linux CI and bare metal)
- decided-by:: [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]
- implements:: [[Topology-Forced Egress]] (vsock-only egress)
- depends-on:: [[Core Trait Contracts]] (`SandboxBackend`)
- delivered-by:: [[Sandbox Launcher]] (`vm` backend)
- contrasts-with:: [[Cloud Hypervisor]] (virtiofs, hotplug, slower boot)
- contrasts-with:: [[gVisor]] (no KVM needed)
- depends-on:: [[Filesystem Control and Rollback]] (image-based repo sync, CoW disk rollback)
- evaluated-by:: [[SandboxEscapeBench]]
- example-of:: [[Vercel Sandbox]] (Firecracker-based cloud runtime with a host firewall)

## Implications for the build

- Phase 2 work, not M0: M0 ships only the standard tier ([[M0 Contained Run]]).
- Add a version gate and a transport gate to `probe()`; record the Firecracker version and transport in every session's audit event.
- Measure cold boot, snapshot restore and per-VM RSS on the team's CI hardware before quoting any number in docs; the ≤150 ms native sandbox-start threshold in [[L4 Product Metrics]] applies to the standard tier, so the VM tier needs its own documented figure.
- Add Firecracker CVE tracking to [[Risk Register]]; a VMM advisory is a release blocker for the hard tier.

## Open questions

- Snapshot-restore latency and realistic per-VM memory for a coding-agent guest are secondary or missing ([[Open Questions and Unverified Claims]]).
- NSDI 2020 numeric figures were not re-verified.
- No Rust client crate for the Firecracker API is verified in the record.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
