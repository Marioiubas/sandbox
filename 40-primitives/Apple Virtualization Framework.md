---
title: "Apple Virtualization Framework"
aliases: ["Apple containerization", "vminitd", "Virtualization.framework", "Lima vz", "VZ"]
type: "primitive"
section: "primitives"
summary: "Apple's hypervisor as used by Apple containerization (one VM per container, vminitd gRPC over vsock, macOS 26 + Apple silicon, sub-second) and Lima vz (virtiofs); the macOS hard tier and Seatbelt hedge."
tags: [sandbox/primitives, primitive, topic/isolation, topic/filesystem, platform/macos, control/iso, boundary/tb2, milestone/phase2, evidence/secondary]
status: verified
confidence: medium
milestone: phase2
created: 2026-09-24
updated: 2026-09-24
related: ["[[Seatbelt]]", "[[Two-Tier Isolation Design]]", "[[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]", "[[Cloud Hypervisor]]", "[[Filesystem Control and Rollback]]", "[[Sandbox Launcher]]", "[[Docker Sandboxes]]", "[[Open Questions and Unverified Claims]]", "[[Topology-Forced Egress]]", "[[M0 Contained Run]]", "[[Core Trait Contracts]]", "[[Risk Register]]"]
---

# Apple Virtualization Framework

Apple's Virtualization.framework (VZ) is the only practical hard boundary on macOS: each sandbox becomes a lightweight Linux VM on Apple's hypervisor. Apple's own Apache-2.0 `containerization` package runs one VM per container with a gRPC guest agent (`vminitd`) over vsock and "sub-second" start on macOS 26 and Apple silicon, while Lima's `vz` mode mounts host directories with virtiofs. It is the broker's macOS hard tier and the hedge against [[Seatbelt]]'s deprecation, at the cost of moving start time from under 5 ms to roughly 800 ms in one project's measurement.

## Boundary and trusted computing base

- **Mechanism.** A full Linux guest kernel per sandbox under Apple's hypervisor; the macOS host kernel and Virtualization.framework are the TCB; the guest has no path to host files or network except the devices the host attaches ([apple/containerization](https://github.com/apple/containerization)).
- **Security record.** No VZ or `containerization` escape was found in the research session (report primitive table: "None found").
- **Platform.** Apple `containerization` needs Apple silicon and macOS 26 (Xcode 26 to develop); Rosetta 2 is optional for amd64 images ([apple/containerization](https://github.com/apple/containerization)). Lima `vz` with virtiofs needs macOS 13+ ([Lima docs](https://lima-vm.io/docs/config/mount/)). Intel Macs and pre-26 Apple-silicon Macs therefore cannot use the `containerization` model and must stay on Seatbelt.

## Consumers the record documents

### Apple `containerization` (Swift, Apache-2.0)

- Each Linux container runs in its own lightweight VM, with "sub-second start times using an optimized Linux kernel configuration" ([apple/containerization](https://github.com/apple/containerization)).
- The guest agent `vminitd` speaks **gRPC over vsock**; the root filesystem is built as ext4; each container gets a dedicated IP ([apple/containerization](https://github.com/apple/containerization)).
- On Linux hosts the same package uses cloud-hypervisor on KVM ([apple/containerization](https://github.com/apple/containerization)), see [[Cloud Hypervisor]].
- Apple's `container` CLI 1.0 shipped on 9 June 2026 with "a small, dedicated lightweight virtual machine for every single container", persistent "container machines" and `container cp`; no millisecond figures beyond "sub-second" were published ([Saiyam Pathak](https://saiyampathak.substack.com/p/a-vm-for-every-container-apple-ships)).

### Lima `vz`

- With `vmType: vz` the default mount is **virtiofs**; with QEMU on Lima ≥1.0 the default is **9p**, which is slower (long-standing qualitative consensus, no 2025–2026 benchmark in the record) ([Lima docs](https://lima-vm.io/docs/config/mount/)).

### Docker Sandboxes

- Docker Sandboxes (GA 30 Jan 2026 on macOS and Windows) runs each agent in a microVM with its own Docker daemon and a host-side egress proxy that swaps sentinels for real credentials ([Docker blog](https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/); [Docker architecture](https://docs.docker.com/ai/sandboxes/architecture/)). Its docs do not name the hypervisor per OS ([Docker docs](https://docs.docker.com/ai/sandboxes/)), so do not assume it is VZ. It is the closest shipped precedent for a VM-per-agent macOS product; see [[Docker Sandboxes]].

## Performance

| Figure | Value | Source and caveat |
|---|---|---|
| Container start (`containerization`) | "sub-second" | vendor wording, no ms figure ([apple/containerization](https://github.com/apple/containerization)) |
| Seatbelt vs Linux-VM fallback | start rises from <5 ms to ~800 ms | one project's measurement ([apple/containerization#737](https://github.com/apple/containerization/issues/737)) |
| Per-VM memory overhead | **not published** | missing from the record |

> [!question] Unverified
> VZ per-VM memory overhead is not published, and realistic coding-agent VM density per laptop is missing ([[Open Questions and Unverified Claims]]). Expect the guest's working set (tens to hundreds of MiB for Node plus Python toolchains) to dominate (research-note inference).

## Why it is the Seatbelt hedge

- `sandbox-exec` is marked deprecated in the macOS 15.4 man page with no removal date, and Apple's issue thread suggests "Consider adopting the App Sandbox instead" ([openai/codex#215](https://github.com/openai/codex/issues/215); [apple/containerization#737](https://github.com/apple/containerization/issues/737)).
- The alternatives do not fit an arbitrary CLI: App Sandbox needs entitlements and signed app bundles, Endpoint Security is observation-only, and System Extensions are distribution-gated ([apple/containerization#737](https://github.com/apple/containerization/issues/737)).
- VZ therefore is the only supported, non-deprecated Apple primitive that can contain an arbitrary agent process tree, which is why [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]] keeps a VZ backend on the roadmap.

## Sharp edges

- **Start time and density.** ~800 ms versus <5 ms for Seatbelt in the measurement above; every session carries a guest kernel and userland.
- **Filesystem.** The agent must see the repo either via virtiofs (live, fast) or via a clone (rollback-friendly). Docker's clone mode (host source read-only at `/run/sandbox/source`, private clone inside) is the rollback precedent ([Docker architecture](https://docs.docker.com/ai/sandboxes/architecture/)); see [[Filesystem Control and Rollback]].
- **Commit signing.** Docker sbx cannot forward a host ssh-agent into the VM for signing ([Andrew Lock](https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/)); the broker signs host-side instead.
- **Tooling inside the guest.** The agent now runs Linux binaries; macOS-only toolchains (Xcode builds) do not work in this tier.
- **Hardware floor.** macOS 26 plus Apple silicon for the `containerization` model; older Macs have no hard tier.

## Verdict for the broker

**Proposal.**

- **Use it for:** the macOS opt-in hard tier ("one VM per session"), and as the fallback if Apple removes `sandbox-exec`; high-assurance runs where a kernel boundary is required on a Mac.
- **Don't use it for:** the macOS default (Seatbelt is zero-install and ~ms start per [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]); agents that need macOS-native toolchains; Intel Macs or macOS <26 for the `containerization` model.
- **How we integrate it.** A phase-2 `vm` backend in [[Sandbox Launcher]] for macOS:
  - model it on Apple `containerization`: one VM per session, a guest init agent reachable over vsock (reuse the `vminitd` gRPC-over-vsock pattern as the broker's control channel template);
  - no guest NIC with a routable peer; egress only over vsock to `brokerd` (`EgressEndpoint::Vsock`), per [[Topology-Forced Egress]];
  - repo via virtiofs share or clone mode; CA bundle via a read-only share; no `$HOME` share;
  - Swift is needed to call Virtualization.framework; **Proposal:** isolate it in a small signed helper that the Rust `brokerd` drives over a local socket, so the Rust core stays single-language (the record does not specify the binding approach);
  - `probe()` checks OS version, CPU architecture and VZ entitlement, and fails closed.

## How it connects

- part-of:: [[Two-Tier Isolation Design]] (macOS hard tier)
- decided-by:: [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]
- contrasts-with:: [[Seatbelt]] (standard tier it hedges)
- contrasts-with:: [[Cloud Hypervisor]] (Linux counterpart in Apple `containerization`)
- depends-on:: [[Filesystem Control and Rollback]] (virtiofs vs clone mode)
- delivered-by:: [[Sandbox Launcher]] (`vm` backend)
- example-of:: [[Docker Sandboxes]] (VM-per-agent product with a host proxy)
- implements:: [[Topology-Forced Egress]] (vsock-only egress)

## Implications for the build

- Not in M0–M4; the macOS MVP is Seatbelt only ([[M0 Contained Run]]).
- Keep the `SandboxBackend` abstraction clean enough that swapping Seatbelt for VZ is a backend change, not a redesign ([[Core Trait Contracts]]).
- Measure start latency, RSS and virtiofs `git status` / `npm install` on an M-series reference laptop before promising a hard-tier SLA.
- Track Apple's stance on `sandbox-exec` each macOS release in [[Risk Register]].

## Open questions

- Per-VM memory overhead, density, and virtiofs vs 9p vs gRPC-FUSE throughput on Apple silicon are not in the record ([[Open Questions and Unverified Claims]]).
- Which hypervisor Docker Sandboxes uses per OS is undocumented.
- The Rust↔Swift binding approach for VZ is not specified in the record.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
