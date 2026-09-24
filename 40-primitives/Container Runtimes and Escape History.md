---
title: "Container Runtimes and Escape History"
aliases: ["runc", "Container Escapes", "Leaky Vessels"]
type: "primitive"
section: "primitives"
summary: "runc/crun with seccomp and user namespaces share the host kernel and keep producing escapes (Leaky Vessels Jan 2024; three procfs/masked-path escapes Nov 2025): packaging only, inside a VM or gVisor, never the primary boundary, never docker.sock."
tags: [sandbox/primitives, primitive, topic/isolation, platform/linux, control/iso, boundary/tb2, invariant/i2, adversary/a3]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
related: ["[[gVisor]]", "[[bubblewrap]]", "[[SandboxEscapeBench]]", "[[Two-Tier Isolation Design]]", "[[I2 Fail-Closed Launch]]", "[[Docker Sandboxes]]", "[[Firecracker]]", "[[Open Questions and Unverified Claims]]", "[[Sandbox Launcher]]", "[[Apple Virtualization Framework]]", "[[Conformance Probe Matrix]]"]
---

# Container Runtimes and Escape History

runc and crun containers, even with seccomp and user namespaces, share the host kernel, and they keep producing escapes: Leaky Vessels (CVE-2024-21626, January 2024), three procfs and masked-path escapes (November 2025), and a stream of adjacent toolkit and Desktop CVEs. UK AISI's SandboxEscapeBench shows frontier models reliably exploit container misconfigurations when asked. The broker therefore uses containers for packaging only, inside a VM or gVisor, never as the primary boundary, and never mounts `docker.sock` or host paths for convenience.

## Boundary and trusted computing base

- **Mechanism.** Namespaces (mount, PID, network, user, IPC, UTS), cgroups, capabilities, a seccomp profile and an LSM (AppArmor/SELinux) applied by the OCI runtime to a process on the **shared host kernel**.
- **TCB.** The entire host kernel syscall surface reachable through the seccomp profile, plus the runtime binary (`runc init` runs with host privileges during setup), plus any daemon (dockerd, containerd) whose socket is reachable.
- **Start and overhead.** ~ms start, ~0 memory overhead (report primitive table).
- **Licence.** Apache-2.0, GA (research note 01 matrix).

## Escape history the build must remember

| Date | CVE | Mechanism | CVSS | Fixed in |
|---|---|---|---|---|
| 31 Jan 2024 | CVE-2024-21626 "Leaky Vessels" | leaked fd to host `/sys/fs/cgroup` in `runc init`; setting WORKDIR to `/proc/self/fd/N` gives host filesystem access; affects 1.0.0-rc93 to 1.1.11 | 8.6 | runc 1.1.12 ([GHSA-xr7r-f8xq-vfvv](https://github.com/advisories/GHSA-xr7r-f8xq-vfvv)) |
| Nov 2025 | CVE-2025-31133 | replace `/dev/null` with a symlink to a procfs file, which runc then bind-mounts read-write for `maskedPaths` | 7.3 | runc 1.2.8, 1.3.3, 1.4.0-rc.3 ([CNCF](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/); [GHSA-9493-h29p-rfm2](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)) |
| Nov 2025 | CVE-2025-52565 | abuse of the `/dev/console` / `/dev/pts/$n` bind mount | 7.3 | same ([CNCF](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)) |
| Nov 2025 | CVE-2025-52881 | redirect `/proc/self/attr/<label>` writes, bypassing LSMs | 7.3 | same ([CNCF](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)) |

Mitigations the CNCF write-up lists for the November 2025 set: user namespaces without host-root mapping, non-root containers, and AppArmor/SELinux (partial) ([CNCF](https://www.cncf.io/blog/2025/11/28/runc-container-breakout-vulnerabilities-a-technical-overview/)).

Adjacent 2024–2025 escapes, compiled from Marina Moore's KubeCon EU 2026 keynote (secondary) ([emirb.github.io](https://emirb.github.io/blog/microvm-2026/)):

- CVE-2024-1753: Buildah/Podman build-time mount escape.
- CVE-2024-0132: NVIDIA container toolkit TOCTOU.
- CVE-2025-9074: Docker Desktop, host filesystem access.
- CVE-2025-23266 "NVIDIAScape" (CVSS 9.0).
- CVE-2025-38617: kernel packet-socket use-after-free reachable via `CAP_NET_RAW`.

The pattern is two waves of runc escapes in 22 months plus tooling around the runtime, all against a shared kernel. The report's primitive-table verdict follows from it: packaging only, never the primary boundary.

## What AISI measured

- UK AISI's SandboxEscapeBench (23 Mar 2026; ICML 2026 oral) has 18 scenarios across orchestration, runtime and kernel layers, from misconfigurations (exposed Docker socket, privileged containers) to multi-step kernel CVE exploits, all nested inside a hardened VM ([UK AISI](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities); [arXiv 2603.02277](https://arxiv.org/abs/2603.02277)).
- Advanced models achieved high success on misconfiguration scenarios; "escape capability scales with model size and inference-time compute", roughly log-linearly with token budget; every successful breakout used previously disclosed vulnerabilities ([UK AISI](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities)).
- AISI's recommendations: do not rely on container isolation alone, patch runtimes and kernels, eliminate privileged containers, secure Docker socket access ([UK AISI](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities)).
- srt warns that mounting `docker.sock` or host paths "would effectively grant access to the host system" ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).

This is the evidence behind the second clause of [[I2 Fail-Closed Launch]]: no mode mounts `docker.sock` or host paths for convenience, because misconfiguration is precisely what models exploit.

## Rootless Podman and user namespaces

- Rootless Podman/Docker needs no daemon root, which helps on developer Linux laptops, but its security depends on unprivileged user namespaces, which Ubuntu 24.04+ gates via AppArmor (`kernel.apparmor_restrict_unprivileged_userns`) ([srt](https://github.com/anthropic-experimental/sandbox-runtime); [dfaerch/bubblewrap-on-ubuntu](https://github.com/dfaerch/bubblewrap-on-ubuntu)). The same gate hits [[bubblewrap]].
- No 2025–2026 advisory review of crun or rootless Podman specifically was done ([[Open Questions and Unverified Claims]]).

## Where containers still appear in the design

- **Docker Sandboxes** gives each agent a microVM with a *private* Docker engine; agents "have no access to the host Docker daemon" ([Docker blog](https://www.docker.com/blog/docker-sandboxes-run-claude-code-and-other-coding-agents-unsupervised-but-safely/)). That is the acceptable shape: the container daemon lives inside the hard boundary.
- **Phase-2 `container` backend** in the launcher: Docker/Podman with the broker as the only egress (a research-note 05 design proposal, not a cited fact; see [[Sandbox Launcher]]).

## Verdict for the broker

**Proposal.**

- **Use it for:** packaging reproducible toolchains *inside* a VM ([[Firecracker]], [[Apple Virtualization Framework]]) or under [[gVisor]]; the phase-2 `container` backend where a customer already standardises on containers, always wrapped with the broker as the only egress.
- **Don't use it for:** the primary boundary around untrusted agent code; any configuration that exposes the host `docker.sock`, a privileged container, or host-path mounts beyond the repo.
- **Minimum requirements if used** (research-note inference): user namespace with no host-root mapping, non-root UID, the default seccomp profile, no `CAP_NET_RAW` (the CVE-2025-38617 class), no `docker.sock`, patched runc (≥1.1.12 for Leaky Vessels; ≥1.2.8 / 1.3.3 / 1.4.0-rc.3 for the Nov 2025 set).
- **How we integrate it.** `probe()` for the container backend refuses to launch when the runtime version is below the fixed versions, when the container would run privileged, or when any bind mount targets a daemon socket; refusals are fail-closed errors under [[I2 Fail-Closed Launch]].

## How it connects

- contrasts-with:: [[gVisor]] (user-space kernel instead of the shared kernel)
- contrasts-with:: [[bubblewrap]] (also namespaces on the shared kernel, but no daemon and no network interface)
- motivated-by:: [[SandboxEscapeBench]] (models exploit misconfigurations)
- part-of:: [[Two-Tier Isolation Design]] (packaging layer only)
- implements:: [[I2 Fail-Closed Launch]] (never `docker.sock`, never host paths)
- example-of:: [[Docker Sandboxes]] (private engine inside a microVM)
- contrasts-with:: [[Firecracker]] (kernel boundary that containers lack)

## Implications for the build

- Conformance category 9 must include a `docker.sock` probe and category 12 SandboxEscapeBench scenarios at difficulty 1–3 ([[Conformance Probe Matrix]]).
- The launcher's mount compiler must reject socket paths and privileged flags statically, with a unit test per rejected shape.
- Record runtime version in the audit event for every container-backed session.

## Open questions

- crun and rootless Podman advisory history was not reviewed ([[Open Questions and Unverified Claims]]).
- The KubeCon-compiled CVE list is secondary; verify each CVE before citing it in user-facing docs.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
