---
title: "ADR-013 Seatbelt for macOS MVP with VZ Hedge"
aliases: ["ADR-013"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/isolation, topic/egress, platform/macos, control/iso, control/fs, boundary/tb2, boundary/tb3, invariant/i2, invariant/i5, milestone/m0, milestone/phase2]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Use generated Seatbelt profiles on macOS for the MVP with a Virtualization.framework backend as hedge; reject a Network Extension and VM-only."
related: ["[[Seatbelt]]", "[[Apple Virtualization Framework]]", "[[Risk Register]]", "[[Sandbox Launcher]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[Netguard Ingress]]", "[[Claude Code and sandbox-runtime]]", "[[OpenAI Codex CLI]]", "[[Cursor and Gemini CLI]]", "[[Docker Sandboxes]]", "[[Two-Tier Isolation Design]]", "[[Topology-Forced Egress]]", "[[Sentinel Swap Pattern]]", "[[I2 Fail-Closed Launch]]", "[[I5 Config Outside Writable Mounts]]", "[[I8 No Flag Disables Isolation]]", "[[L4 Product Metrics]]", "[[M0 Contained Run]]", "[[Open Questions and Unverified Claims]]", "[[MOC Decisions]]"]
sources: ["https://github.com/openai/codex/issues/215", "https://github.com/apple/containerization/issues/737", "https://github.com/apple/containerization", "https://github.com/anthropic-experimental/sandbox-runtime", "https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/", "https://lima-vm.io/docs/config/mount/", "https://learn.chatgpt.com/codex/sandboxing", "https://geminicli.com/docs/cli/sandbox/", "https://docs.docker.com/ai/sandboxes/security/defaults/"]
superseded_by:
---

# ADR-013 Seatbelt for macOS MVP with VZ Hedge

> Use generated Seatbelt profiles on macOS for the MVP with a Virtualization.framework backend as hedge; reject a Network Extension and VM-only.

## Status

Proposed (2026-09-24). The Seatbelt backend is delivered by [[M0 Contained Run]], whose acceptance runs `broker run -- claude` and `-- codex` on macOS 15 and 26. The VZ backend is phase 2, as the `vm` backend in [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]].

## Context

macOS offers two usable primitives, and neither is clean.

**Seatbelt works everywhere today and is deprecated.**

- `man sandbox-exec` on macOS 15.4 reads "execute within a sandbox (DEPRECATED)" ([openai/codex#215](https://github.com/openai/codex/issues/215)).
- There is no published removal date. Apple suggests "Consider adopting the App Sandbox instead", which needs entitlements and signed app bundles. Endpoint Security is observation-only, and System Extensions are "distribution-gated" ([apple/containerization#737](https://github.com/apple/containerization/issues/737)).
- The tool "still works today", but deprecation creates "long-term uncertainty" ([Infralovers](https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/)).
- Every incumbent depends on it. srt generates Seatbelt profiles at runtime and allows network only to "a specific localhost port" ([srt](https://github.com/anthropic-experimental/sandbox-runtime)). Codex uses Seatbelt on macOS ([Codex docs](https://learn.chatgpt.com/codex/sandboxing)). Gemini CLI ships Seatbelt profiles ([Gemini CLI docs](https://geminicli.com/docs/cli/sandbox/)).
- Two srt options show the sharp edges. `allowAppleEvents` "removes code-execution isolation", and `enableWeakerNetworkIsolation` re-allows `com.apple.trustd.agent`, which Go TLS verification needs and which srt calls an exfiltration vector ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).

**Virtualization.framework is supported and heavier.**

- Apple's Apache-2.0 `containerization` runs each Linux container in its own lightweight VM with "sub-second" starts. Its guest agent `vminitd` speaks gRPC over vsock. It needs Apple silicon and macOS 26 ([apple/containerization](https://github.com/apple/containerization)).
- Lima's `vz` mode mounts with virtiofs and needs macOS 13+ ([Lima docs](https://lima-vm.io/docs/config/mount/)).
- A Linux-VM fallback raised start time from under 5 ms to about 800 ms in one project's measurement ([apple/containerization#737](https://github.com/apple/containerization/issues/737)).
- Docker Sandboxes already puts a microVM around each agent ([Docker docs](https://docs.docker.com/ai/sandboxes/security/defaults/); [[Docker Sandboxes]]).

**Egress without a Network Extension.** Transparent interception on macOS without a Network Extension is unvalidated. Under a Seatbelt localhost-only profile, clients that ignore proxy variables simply fail, because nothing else is reachable. That fails closed ([[Netguard Ingress]]).

The proposed L4 threshold for native sandbox start is **≤150 ms** ([[L4 Product Metrics]]).

## Decision

**Proposal.**

1. **Standard tier on macOS = generated SBPL via `/usr/bin/sandbox-exec`.** The `macos-seatbelt` backend of [[Sandbox Launcher]] compiles each session's filesystem grants into a profile that:
   - denies writes except the repo and tmp;
   - denies reads of secret directories (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`, `~/.docker/config.json` and the rest of the default deny list);
   - allows network outbound only to the per-session broker localhost port;
   - denies Apple Events and `trustd`.
2. **The profile is protected.** It is written to a broker-owned path outside every writable mount. The launcher uses an absolute `sandbox-exec` path. Because any local process can reach a loopback port, each session authenticates to the proxy with a sentinel `Proxy-Authorization` value.
3. **The backend fails closed.** `probe()` confirms `sandbox-exec` exists and that a canary profile really denies a secret read. If not, `broker run` exits non-zero. No weakened mode exists: no Apple Events or `trustd` toggles in the MVP. Go clients that need `trustd` go on a documented compatibility list.
4. **No Network Extension or System Extension in the MVP.** Proxy-ignoring clients fail closed.
5. **The hedge is a `vm` backend on Virtualization.framework.** Phase 2 ships one VM per session on the Apple `containerization` / `vminitd` model. The repo is shared through virtiofs or clone mode, and vsock is the only egress. It sits behind the same `SandboxBackend` trait, so policy, broker and audit do not change.

**Testable as:** M0 on macOS 15 and 26 (the agent task passes; `~/.ssh/id_ed25519` read denied; conformance categories 3, 4, 5, 9 and 10 at 100% denial); launch refuses to run when `sandbox-exec` is missing or the canary is not denied; native start ≤150 ms.

## Alternatives considered

| Alternative | Pros | Cons | Why rejected |
|---|---|---|---|
| **Network Extension or System Extension** | Transparent interception of proxy-ignoring clients; supported Apple API | "Distribution-gated": signing, entitlements and user approval make a zero-install CLI impractical | Distribution friction; the Seatbelt localhost rule already fails closed |
| **VM-only on macOS** (Docker sbx model) | Strongest boundary; not deprecated | ~800 ms versus <5 ms start; macOS 26 plus Apple silicon floor for `containerization` excludes Intel and older Macs; per-VM memory unpublished; macOS-native toolchains unavailable in a Linux guest | Misses the start-time threshold and much of the installed base; kept as the hard tier |
| **App Sandbox** | Apple's recommended replacement | Needs entitlements and signed app bundles; not practical for wrapping arbitrary CLIs (research-note inference) | Cannot wrap `claude` or `codex` as-is |
| **Endpoint Security** | Rich telemetry | Observation-only | Not an enforcement boundary |

## Consequences

- **Easier:** zero-install, millisecond starts, and the same mechanism the incumbents ship. The broker's generated profiles can be compared directly with srt's and Codex's.
- **Harder:** tools that ignore proxy variables fail on macOS, and Go binaries that need `trustd` need a documented exception path. These are compatibility costs, not security holes.
- **Riskier:** Apple could remove or break `sandbox-exec`. Claude Code, Codex and Gemini CLI share the dependency, so Apple breaking it would break the incumbents too. That is a mitigating factor, not a guarantee ([[Risk Register]], row "macOS Seatbelt removal").
- **Coverage gap:** Intel Macs and pre-26 Apple-silicon Macs have no hard tier.

## Revisit triggers

- Apple announces a removal date or a replacement per-process sandbox API; none was documented as of September 2026.
- A macOS beta changes `sandbox-exec` behaviour. The CI matrix must run on each macOS release.
- Transparent interception without a Network Extension is validated, or Apple eases extension distribution.
- VZ start time or memory improves enough to meet the ≤150 ms threshold, which would make VM-by-default viable.
- A Seatbelt escape relevant to agent workloads is published.

## Invariants and components affected

- **Upholds [[I2 Fail-Closed Launch]]:** a missing `sandbox-exec` or a failed canary blocks launch.
- **Upholds [[I5 Config Outside Writable Mounts]]:** the profile and broker binary live outside writable mounts.
- **Upholds [[I8 No Flag Disables Isolation]]:** there is no flag for Apple Events or `trustd`.
- **Upholds I1** through secret-directory read denials.
- Components: [[Sandbox Launcher]] (`launcher/backends/seatbelt`, later `vm`), [[Netguard Ingress]] (loopback listener plus session sentinel), [[Seatbelt]], [[Apple Virtualization Framework]].

## How it connects

- depends-on:: [[Seatbelt]]
- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[Netguard Ingress]]
- depends-on:: [[Sentinel Swap Pattern]] (loopback session credential)
- part-of:: [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]
- part-of:: [[Two-Tier Isolation Design]]
- implements:: [[Topology-Forced Egress]] (macOS form)
- contrasts-with:: [[Apple Virtualization Framework]] (the hedge, not the default)
- contrasts-with:: [[Docker Sandboxes]] (microVM by default)
- motivated-by:: [[Claude Code and sandbox-runtime]]
- motivated-by:: [[OpenAI Codex CLI]]
- mitigates:: [[Risk Register]] (row "macOS Seatbelt removal", via the VZ backend)
- evaluated-by:: [[L4 Product Metrics]]
- delivered-by:: [[M0 Contained Run]]
- part-of:: [[MOC Decisions]]

## Implications for the build

- Keep SBPL generation a pure function from `CompiledFsPolicy` plus egress endpoint to profile text, with golden-file tests for every built-in agent profile.
- Read the system sandbox violation log to populate `broker why` for filesystem denials.
- Put macOS 15 and 26 runners in CI from week one; add each new macOS beta when it ships.
- Design the `vm` backend's vsock channel now, even though it ships in phase 2, so the data-plane protocol does not assume a loopback port.

## Open questions

- Exactly which SBPL operations the profile needs beyond the localhost-port rule is background knowledge; verify against a working profile on macOS 15 and 26.
- How many common developer tools break without `trustd`, and without honouring proxy variables? No data in the record.
- Transparent interception without a Network Extension remains unvalidated ([[Open Questions and Unverified Claims]]).
- Per-VM memory on Apple silicon is unpublished.

## Sources

- [openai/codex#215: sandbox-exec deprecation](https://github.com/openai/codex/issues/215)
- [apple/containerization#737](https://github.com/apple/containerization/issues/737)
- [apple/containerization](https://github.com/apple/containerization)
- [anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- [Infralovers: sandboxing Claude Code on macOS](https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/)
- [Lima docs: mounts](https://lima-vm.io/docs/config/mount/)
- [Codex docs: sandboxing](https://learn.chatgpt.com/codex/sandboxing)
- [Gemini CLI docs: sandbox](https://geminicli.com/docs/cli/sandbox/)
- [Docker docs: Sandboxes default security posture](https://docs.docker.com/ai/sandboxes/security/defaults/)
- Report: decisions row "macOS", the macOS row of the layered-design table and the risk row "macOS Seatbelt removal"; research notes 01 Q1, Q3 and 05 sections 3–4.
