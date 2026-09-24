---
title: "Cloud Hypervisor"
aliases: ["CLH", "libkrun", "Kata Containers"]
type: "primitive"
section: "primitives"
summary: "KVM plus ~106k-line Rust VMM with virtiofs, hotplug and VFIO (~<200 ms boot, secondary); hard tier for Linux laptops that need virtiofs; also Apple containerization's Linux backend. Notes libkrun, Kata and QEMU microvm as alternatives."
tags: [sandbox/primitives, primitive, topic/isolation, topic/filesystem, platform/linux, control/iso, boundary/tb2, milestone/phase2, evidence/secondary]
status: verified
confidence: medium
milestone: phase2
created: 2026-09-24
updated: 2026-09-24
related: ["[[Firecracker]]", "[[Apple Virtualization Framework]]", "[[Two-Tier Isolation Design]]", "[[Filesystem Control and Rollback]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[Sandbox Launcher]]", "[[Open Questions and Unverified Claims]]", "[[Seatbelt]]", "[[bubblewrap]]", "[[seccomp-bpf]]", "[[Landlock]]", "[[gVisor]]", "[[Topology-Forced Egress]]", "[[MVP Plan]]"]
---

# Cloud Hypervisor

Cloud Hypervisor is a KVM-based virtual machine monitor of about 106k lines of Rust that adds what [[Firecracker]] deliberately omits: virtiofs, CPU and memory hotplug, VFIO and nested KVM. It boots somewhat slower (under 200 ms with a stripped kernel, per a secondary source), and it is the broker's hard tier for Linux laptops that need the repository mounted live. This note also covers the alternatives the record assessed: libkrun/krunvm, Kata Containers and QEMU `microvm`.

## Boundary and trusted computing base

- **Mechanism.** A guest Linux kernel under KVM with a Rust VMM process on the host; the host-side TCB for an escape is KVM plus the VMM and its device backends (virtiofsd for virtiofs) ([emirb.github.io, Mar 2026](https://emirb.github.io/blog/microvm-2026/)).
- **TCB size.** ~106k lines of Rust versus ~83k for Firecracker (secondary source) ([emirb.github.io](https://emirb.github.io/blog/microvm-2026/)). The extra code buys virtiofs, hotplug and VFIO.
- **Adoption signal.** Apple's `containerization` package uses cloud-hypervisor on KVM as its Linux backend, and Virtualization.framework on macOS ([apple/containerization](https://github.com/apple/containerization)). That makes Cloud Hypervisor the Linux counterpart of the [[Apple Virtualization Framework]] hard tier in a design that already exists.
- **Licence and platform.** Apache-2.0, GA, Linux with KVM (research note 01 comparison matrix).
- **Security record.** No Cloud Hypervisor CVE was found in the research session (the report's primitive table lists "None found"). Absence of findings in one session is not evidence of absence.

## Performance (secondary figures)

> [!question] Unverified
> Every Cloud Hypervisor timing in the record is secondary. Plan with it, measure before quoting it ([[Open Questions and Unverified Claims]]).

| Runtime | Figure | Source and conditions |
|---|---|---|
| Cloud Hypervisor | under 200 ms boot with a stripped Linux 6.18 kernel; slightly slower than Firecracker | secondary blog, Mar 2026 ([emirb.github.io](https://emirb.github.io/blog/microvm-2026/)) |
| Kata Containers | +150–300 ms start overhead | same source |
| gVisor / E2B (for comparison) | ~50 ms / ~150 ms | same source |
| Kata with Cloud Hypervisor on Kubernetes | CPU −2.7%, HTTP req/s −89%, random 4K I/O −99% vs runc | early-2026 benchmark on DigitalOcean c5-8vcpu VMs (nested virtualization), 2 CPU / 4 Gi per pod, Kata v3.26.0, Cloud Hypervisor v48.0 ([container-runtime-benchmarks](https://github.com/bikramkgupta/container-runtime-benchmarks)) |

The Kubernetes numbers were taken under nested virtualization, which is exactly the condition that penalises KVM-based runtimes most; they are an upper bound on the pain in hosted CI, not a laptop figure.

## Filesystem: why virtiofs is the reason to pick it

- Virtiofs lets the guest see the host repo directory live, so an agent's edits land in the working tree without a sync step. virtio-fs was merged in Linux 5.4 with better performance than virtio-9p (background, pre-2025) ([Phoronix](https://www.phoronix.com/news/Linux-5.4-VirtIO-FS)).
- On Linux hosts virtiofs needs the Rust `virtiofsd`, and Lima describes Linux virtiofs as experimental ([Lima docs](https://lima-vm.io/docs/config/mount/)).
- A virtiofs share is a capability grant: whatever directory is shared is fully reachable from the guest. **Proposal:** share only the repo (or its CoW upper layer, see [[Filesystem Control and Rollback]]), never `$HOME`, and keep `.git/hooks` and `.git/config` read-only on the host side as in the standard tier.

## Alternatives assessed in the record

### libkrun / krunvm (aliases: libkrun)

- A dynamic library that gives a process "a partially isolated environment" using KVM on Linux and HVF on macOS/ARM64, with virtio-console, block, fs, gpu, net, vsock, balloon and rng devices ([containers/libkrun](https://github.com/containers/libkrun)).
- Networking is either **TSI** (Transparent Socket Impersonation over vsock, with the VMM proxying AF_INET/AF_INET6/AF_UNIX) or virtio-net with passt or gvproxy ([containers/libkrun](https://github.com/containers/libkrun)).
- The project's own caveat: "the guest and the VMM pertain to the same security context"; virtio-fs does not protect against cross-directory access within the same filesystem; with TSI, treat VMM and guest as one security entity and use host namespaces to protect host resources. v2.0 on `main` is unstable; production should use `stable-*` branches. Used by crun's `krun` handler, krunkit and muvm ([containers/libkrun](https://github.com/containers/libkrun)).
- **Verdict (inference):** attractive as one cross-platform process-in-a-VM library, but the VMM must itself be sandboxed (namespaces or [[Seatbelt]]); a strong second layer, not a drop-in hard boundary.

### Kata Containers

- Kata wraps a VMM (Cloud Hypervisor, QEMU or Firecracker) behind a Kubernetes RuntimeClass and adds 150–300 ms of start overhead (secondary) ([emirb.github.io](https://emirb.github.io/blog/microvm-2026/)).
- **Verdict (inference):** only for teams already running Kubernetes in CI or cloud; too heavy for laptops. Relevant to the phase-2 Kubernetes deployment mode.

### QEMU `microvm`

- No 2025–2026 primary benchmark was found; no figures are in the record. Do not quote numbers for it ([[Open Questions and Unverified Claims]]).

## Sharp edges

- Nested virtualization in hosted CI erodes performance (see the Kubernetes benchmark above).
- Virtiofs on Linux hosts is marked experimental in Lima's docs and pulls in `virtiofsd` as another host process in the TCB.
- More devices mean more VMM attack surface than Firecracker; enable hotplug and VFIO only when needed.

## Verdict for the broker

**Proposal.**

- **Use it for:** the opt-in hard tier on Linux laptops, where the agent must work on the live repo through virtiofs; the Linux side of a VM backend that mirrors the macOS [[Apple Virtualization Framework]] backend (Apple's own `containerization` made the same pairing).
- **Don't use it for:** the default Linux tier (that is [[bubblewrap]] + [[seccomp-bpf]] + [[Landlock]] per [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]); hosted CI without KVM (use [[gVisor]]); workloads where Firecracker's smaller VMM suffices.
- **How we integrate it.** Second implementation of the phase-2 `vm` backend in [[Sandbox Launcher]] behind `SandboxBackend`:
  - egress over vsock only (`EgressEndpoint::Vsock`), never a routed NIC;
  - one virtiofs share of the repo (or of an overlay upper directory) plus a read-only share of the CA bundle; no `$HOME`;
  - `probe()` reports `/dev/kvm`, VMM version and `virtiofsd` availability and fails closed;
  - libkrun is not a substitute for this backend unless the VMM process is also placed in the standard-tier sandbox.

## How it connects

- part-of:: [[Two-Tier Isolation Design]] (Linux laptop hard tier)
- decided-by:: [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]
- contrasts-with:: [[Firecracker]] (smaller VMM, faster boot, no virtiofs)
- contrasts-with:: [[Apple Virtualization Framework]] (the macOS counterpart; Apple pairs the two)
- depends-on:: [[Filesystem Control and Rollback]] (virtiofs share, CoW upper dir)
- delivered-by:: [[Sandbox Launcher]] (`vm` backend)
- implements:: [[Topology-Forced Egress]] (vsock only)

## Implications for the build

- Phase 2 only; no M0–M4 acceptance criterion depends on it ([[MVP Plan]]).
- Benchmark cold boot, RSS and virtiofs throughput (`git status`, `npm install` on a large repo) on reference laptops before documenting the hard tier.
- Treat libkrun, Kata and QEMU `microvm` as research spikes, not backends, until measured.

## Open questions

- All boot figures are secondary; QEMU `microvm` and krunvm have no figures at all ([[Open Questions and Unverified Claims]]).
- Realistic coding-agent VM density per laptop is missing from the record.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
