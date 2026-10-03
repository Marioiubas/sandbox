---
title: "ADR-042 Release Packaging as Built"
aliases: ["ADR-042"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/supply-chain, topic/build, platform/linux, platform/macos, milestone/m4]
status: built
confidence: medium
created: 2026-10-01
updated: 2026-10-01
summary: "`release.yml` builds static musl binaries for x86_64 and aarch64 with cargo-zigbuild, .deb and .rpm with nfpm (all three programs in /usr/bin; the AppArmor profile is a plain package file loaded only where the userns gate exists and unloaded on removal; never the sysctl, never the trust store), a lipo-merged universal2 macOS build that stays unsigned until the owner's Developer ID exists, per-program CycloneDX SBOMs, SHA256SUMS, GitHub SLSA provenance and keyless cosign bundles (not stored cosign keys); tags make draft releases only."
related: ["[[Tech Stack]]", "[[M4 Harden and Ship]]", "[[bubblewrap]]", "[[I2 Fail-Closed Launch]]", "[[I5 Config Outside Writable Mounts]]", "[[Sandbox Launcher]]", "[[MOC Decisions]]"]
sources: []
superseded_by: 
code: [".github/workflows/release.yml", "code/packaging/nfpm.yaml", "code/packaging/scripts/postinstall.sh", "code/packaging/scripts/preremove.sh", "code/packaging/check-static.sh", "code/packaging/sbom.sh", "code/docs/deployment/packages.md"]
---

# ADR-042 Release Packaging as Built

> Every release artifact is built, proven and signed by one workflow; the Linux installer grants bwrap a user namespace only through a profile that leaves with the package.

## Status

built (2026-10-01, M4) for Linux packages, the static tarballs, the unsigned macOS build and the supply-chain files. Developer ID signing, notarisation and the Homebrew tap wait for the owner's accounts.

## Context

The [[Tech Stack]] supply-chain row and its packaging steps (Proposal) ask for musl static binaries, a universal2 macOS binary, Developer ID signing and notarisation, a Homebrew tap, `.deb` and `.rpm` via nfpm, cosign, a CycloneDX SBOM and SLSA provenance, and an installer that handles Ubuntu's AppArmor user-namespace restriction ([[bubblewrap]]). [[M4 Harden and Ship]] lists "cosign keys" among its prerequisites. The Tech Stack note names no cross toolchain.

Two facts from the code fix the package layout: `broker` starts `brokerd` from its own directory (`broker-cli/src/cmd/ctl.rs`) and `brokerd` runs `broker-sandbox-shim` from its own directory (`launcher::default_shim_path`), so the three programs must be installed together.

## Decision

1. **Linux binaries.** `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, release profile, `--locked`, built on one x86_64 runner with `cargo zigbuild` (cargo-zigbuild 0.23.4, zig 0.16.0; both pinned and SHA-256-verified). A check fails the build unless `file` reports a static (or static-pie) ELF with no program interpreter and no `DT_NEEDED`; on the native architecture `ldd` must agree. **Found while building:** the launcher's seccomp filter did not compile for musl, where libc types `TIOCSTI` and `TIOCLINUX` as `c_int` (glibc: `c_ulong`); both now go through `u32`, exact for the filter's 32-bit comparison and the kernel's `unsigned int` request (`launcher/src/backends/linux/inner.rs`).
2. **Packages.** nfpm 2.47.0 (`code/packaging/nfpm.yaml`). `broker`, `brokerd` and `broker-sandbox-shim` in `/usr/bin` (root-owned, outside every writable mount); `Depends: bubblewrap` (deb and rpm); SBOMs and README under `/usr/share/doc/broker/`.
3. **AppArmor.** `/etc/apparmor.d/broker-bwrap` ships as an ordinary package file, **not a conffile**. The post-install script loads it with `apparmor_parser -r` only when AppArmor is enabled and `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` exists; the pre-removal script unloads it on removal (not on upgrade). Neither script changes the sysctl or the system trust store. A failed load warns and lets the install finish: the product still fails closed at launch ([[I2 Fail-Closed Launch]]).
4. **macOS.** Both slices built on macos-15 and merged with `lipo` into universal2 programs; the build checks both architectures are present and runs `broker --version` and `broker doctor`. Developer ID signing (`codesign --options runtime --timestamp`) and notarisation (`xcrun notarytool submit --wait`) are written as steps that run only when the `APPLE_DEVELOPER_ID_*` and `APPLE_NOTARY_*` secrets exist; until then the build ships **unsigned** and the docs say so.
5. **Supply chain.** A CycloneDX 1.5 SBOM per program and target (cargo-cyclonedx 0.5.9, every dependency) inside each package and tarball and as release assets; `SHA256SUMS` over all assets; SLSA build provenance through `actions/attest-build-provenance` (GitHub artifact attestations); a keyless cosign signature (cosign v3.0.6, one Sigstore bundle per asset). The workflow verifies every signature and attestation before anything is released.
6. **Release.** A `v*` tag must equal the workspace version; the run then creates or updates a **draft** release and fails rather than modify a published one. Pushes to the `packaging` branch and manual runs build, test, attest and sign the same way without a release; their certificates name `refs/heads/packaging`, so verification pinned to a tag rejects them.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| `cross` (Docker images per target) | A container per target and older bundled C toolchains; zigbuild builds both architectures on one runner without containers. |
| Native per-architecture runners with `musl-gcc` | Works, but ties the aarch64 build to an arm runner; the arm runner is used to test the aarch64 package instead. |
| cosign with a stored key pair (the M4 prerequisite's "cosign keys") | A long-lived signing secret in CI to protect and rotate; keyless binds each signature to the workflow, ref and commit and logs it publicly. |
| AppArmor profile as a conffile | dpkg keeps conffiles after `remove`, and AppArmor reloads them at boot, so bwrap would keep its user-namespace exception after the broker is gone. |
| Lifting `kernel.apparmor_restrict_unprivileged_userns` in the installer | Weakens every program on the host; the CI test jobs' fallback for 22.04 runners is not an installer option. |
| Shim in `/usr/libexec/broker/` | The code finds the shim next to the running executable; a split layout would refuse every launch. |
| Signing and attesting tags only | The chain would first run on a real release; branch builds prove it, and pinning the tag ref keeps them from passing as a release. |

## Consequences

- E9 ("all artifacts verify") holds for checksums, cosign and SBOMs; notarisation cannot verify until the owner's Apple account is set up.
- Verification depends on the public Sigstore instance and GitHub's attestation API, or on the bundles shipped with the release.
- Branch builds appear in the public transparency log and the repository's attestation list.
- Still open: Developer ID signing and notarisation, the Homebrew tap, apt and yum repositories, GPG-signed packages.

## Invariants affected

Upholds [[I5 Config Outside Writable Mounts]] (programs in root-owned `/usr/bin`) and [[I2 Fail-Closed Launch]] (the installer never weakens a layer; launch still refuses without one). The broker CA never reaches a system trust store. Weakens none.

## Tests

In `.github/workflows/release.yml`: `linux` (static check of every program per architecture; shellcheck of the package scripts), `macos` (both architectures in each universal2 program; `broker doctor`), `smoke` on Ubuntu 24.04 x86_64 and arm64 (static checks with `ldd`; with the gate on, bwrap cannot build a sandbox before the install, since the gate leaves its namespaces without capabilities; `.deb` layout; profile loaded and not a conffile; the same bwrap command then succeeds, and `broker --version`, `broker doctor`, `broker run -- /bin/true` and `broker audit verify` succeed as the runner user; after removal the profile is unloaded and deleted and bwrap fails again; the gate stays on throughout; the `.rpm` installs and removes on Fedora 43), `supply-chain` (`cosign verify-blob` and `gh attestation verify` for every asset).

## Relationships

- decided-by:: M4 build
- implements:: [[Tech Stack]]
- part-of:: [[M4 Harden and Ship]]
- depends-on:: [[bubblewrap]]

## Build log

- 2026-10-01: created and built; proven on the `packaging` branch by `release.yml` runs 36910376549 (commit f4422c6) and 36912092416 (commit cc86cf5), every job green.
