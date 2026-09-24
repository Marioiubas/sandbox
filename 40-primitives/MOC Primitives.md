---
title: "MOC Primitives"
aliases: []
type: moc
section: primitives
tags: [sandbox/primitives, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Isolation is a solved commodity: per-primitive verdicts, the two-tier per-platform design, egress topology and filesystem control."
related: ["[[Firecracker]]", "[[Cloud Hypervisor]]", "[[Apple Virtualization Framework]]", "[[gVisor]]", "[[Container Runtimes and Escape History]]", "[[bubblewrap]]", "[[Landlock]]", "[[seccomp-bpf]]", "[[Seatbelt]]", "[[Wasmtime and WASI]]", "[[Topology-Forced Egress]]", "[[Two-Tier Isolation Design]]", "[[Filesystem Control and Rollback]]", "[[MOC Architecture]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[SandboxEscapeBench]]"]
sources: []
---

# MOC Primitives

> Isolation is a solved commodity: per-primitive verdicts, the two-tier per-platform design, egress topology and filesystem control.

The isolation layer needs no new invention, only careful composition. The design rule: never rely on one primitive. Pair a hard or OS-level boundary with an inner Landlock or seccomp layer, and put the *policy* boundary (network plus credentials) in the broker, so an escape yields a process with no secrets and no network except the capability-checked broker.

Start with [[Two-Tier Isolation Design]] for the per-platform recipe, then [[Topology-Forced Egress]] for why only topology (not `HTTP_PROXY`) forces traffic through the broker.

## Verdicts at a glance (Proposal)

| Primitive | Boundary | Verdict |
|---|---|---|
| [[Firecracker]] | KVM + Rust VMM | Hard tier for Linux CI on bare metal or nested-capable hosts |
| [[Cloud Hypervisor]] | KVM + Rust VMM with virtiofs | Hard tier for Linux laptops that need virtiofs |
| [[Apple Virtualization Framework]] | Apple hypervisor, VM per container | Hard tier on macOS |
| [[gVisor]] | Go user-space kernel | CI and cloud where KVM is absent or nested |
| [[Container Runtimes and Escape History]] | Shared host kernel | Packaging only, inside a VM or gVisor |
| [[bubblewrap]] + [[seccomp-bpf]] | Namespaces, no network interface | **Standard tier on Linux** and the MCP-server wrapper |
| [[Landlock]] | Unprivileged stackable LSM | Inner layer on every Linux agent and MCP process |
| [[Seatbelt]] | macOS kernel sandbox | **Standard tier on macOS**, with a VM hedge |
| [[Wasmtime and WASI]] | Capability imports | Purpose-built MCP tools and broker plugins, not shells or compilers |

Several start-time and memory figures come from secondary sources; no same-hardware 2026 benchmark exists, so measure on the team's own CI and reference laptops.

## Design

- [[Two-Tier Isolation Design]] — Standard tier (OS process sandbox, default) and hard tier (microVM, opt-in) for macOS laptops, Linux laptops, CI runners and local MCP servers, with the layering rule: pair an OS or hard boundary with an inner Landlock/seccomp layer and put the policy boundary in the broker.
- [[Topology-Forced Egress]] — Only topology forces traffic through the broker: no NIC plus UDS on Linux, Seatbelt loopback-only on macOS, vsock in VMs, host-side redirect in cloud; HTTP_PROXY alone is 'polite' and bypassable (ToolHive, Agent Vault).
- [[Filesystem Control and Rollback]] — Read-only root with writable repo bind, protected subpaths (.git/hooks, .git/config, agent config dirs) re-bound read-only, default deny-read secret dirs, the literal-path deny-glob hole, and copy-on-write rollback (overlayfs upper dir, APFS clone, Docker clone mode).

## Standard tier (OS process sandboxes)

- [[Seatbelt]] — macOS kernel sandbox driven by generated SBPL via sandbox-exec: deny writes except repo and tmp, deny secret reads, network only to the broker's localhost port, no Apple Events or trustd; deprecated in the man page with no removal date.
- [[bubblewrap]] — Namespace sandbox (bwrap) with --ro-bind / /, repo bind and --unshare-net so the sandbox has no network interface at all: the Linux standard tier and MCP wrapper used by srt and Codex; Ubuntu 24.04+ gates unprivileged userns via AppArmor.
- [[seccomp-bpf]] — Syscall filtering that blocks new AF_UNIX sockets after the broker bridge is set up, plus ptrace, bpf, raw sockets and keyctl, so the sandbox cannot open other channels or reach the control socket; cgroup sock_addr eBPF as a redirect alternative.
- [[Landlock]] — Unprivileged, stackable LSM for filesystem paths and (ABI 4+) TCP ports; ABI 9 on Linux 7.1, UDP (ABI 10/11) not yet in a released stable kernel; the inner layer on every Linux agent and MCP process, probed at runtime.

## Hard tier (microVMs and user-space kernels)

- [[Firecracker]] — KVM microVM with a ~83k-line Rust VMM (<=125 ms to guest init, <=5 MiB overhead); hard tier for Linux CI on bare metal or nested-capable hosts; pin >=1.14.4/1.15.1 and prefer MMIO after the 2026 jailer and virtio-PCI CVEs.
- [[Cloud Hypervisor]] — KVM plus ~106k-line Rust VMM with virtiofs, hotplug and VFIO (~<200 ms boot, secondary); hard tier for Linux laptops that need virtiofs; also Apple containerization's Linux backend. Notes libkrun, Kata and QEMU microvm as alternatives.
- [[Apple Virtualization Framework]] — Apple's hypervisor as used by Apple containerization (one VM per container, vminitd gRPC over vsock, macOS 26 + Apple silicon, sub-second) and Lima vz (virtiofs); the macOS hard tier and Seatbelt hedge.
- [[gVisor]] — Go user-space kernel (Sentry) whose seccomp filter forbids host connect(2); Systrap works inside VMs without nested virtualization (~50 ms start); the CI and cloud tier where KVM is absent.

## Other runtimes

- [[Container Runtimes and Escape History]] — runc/crun with seccomp and user namespaces share the host kernel and keep producing escapes (Leaky Vessels Jan 2024; three procfs/masked-path escapes Nov 2025): packaging only, inside a VM or gVisor, never the primary boundary, never docker.sock.
- [[Wasmtime and WASI]] — Capability-import runtime (WASI 0.3 default in Wasmtime 46) with no ambient authority: right for purpose-built MCP tools and broker plugins with host-implemented wasi:http, not for shells, git or compilers; 12 advisories incl. 2 critical escapes in Apr 2026.

## How this section connects

- The primitives are wrapped by the [[Sandbox Launcher]] behind the `SandboxBackend` trait ([[Core Trait Contracts]]), and the choice is recorded in [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]] and [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]].
- The egress topology feeds [[Netguard Ingress]] and [[ADR-003 Topology-Enforced Egress]].
- The isolation layer is regression-tested by [[SandboxEscapeBench]] (eval layer L6) and probe categories 5, 9, 10 and 12 of the [[Conformance Probe Matrix]].
- Platform risks (Seatbelt deprecation, Ubuntu AppArmor userns gate, Landlock ABI spread) are in [[Risk Register]].
