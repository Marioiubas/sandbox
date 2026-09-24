---
title: "I2 Fail-Closed Launch"
aliases: ["Fail Closed"]
type: concept
section: architecture
tags: [sandbox/architecture, concept, invariant/i2, topic/isolation, control/iso, boundary/tb2, milestone/m0]
status: proposal
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Launch fails closed if any isolation layer or the proxy cannot start; no convenience mode mounts docker.sock or host paths."
related: ["[[Sandbox Launcher]]", "[[Claude Code and sandbox-runtime]]", "[[M0 Contained Run]]", "[[Core Trait Contracts]]", "[[Container Runtimes and Escape History]]", "[[Gemini CLI Prefix Allowlist Bypass]]", "[[sandbox-runtime Empty Allowlist Bypass]]", "[[SandboxEscapeBench]]", "[[Landlock]]", "[[Broker CLI and Daemon]]", "[[Netguard Ingress]]", "[[I8 No Flag Disables Isolation]]", "[[Conformance Probe Matrix]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]"]
sources: ["https://code.claude.com/docs/en/sandboxing", "https://github.com/anthropic-experimental/sandbox-runtime", "https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities", "https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack", "https://github.com/advisories/GHSA-9gqj-5w7c-vx47", "https://docs.kernel.org/userspace-api/landlock.html"]
milestone: M0
---

# I2 Fail-Closed Launch

> Launch fails closed if any isolation layer or the proxy cannot start; no convenience mode mounts docker.sock or host paths.

## Statement

**Proposal.** `broker run` (and every other entry point that starts a sandboxed principal, including `broker mcp wrap` and `brokerd`-launched MCP servers) must exit non-zero **before the agent's first instruction executes** unless all of the following are true for the selected backend:

1. every *required* isolation layer for that backend was applied and verified (see the table below);
2. the broker's egress listener for the session is up, bound to the session's channel, and answered a readiness probe;
3. the per-session CA, trust bundle and sentinel set were generated;
4. the policy bundle loaded, validated against the schema and passed its signature and max-age check.

Additionally, no configuration value, profile or flag may mount `docker.sock`, a host service socket, or any host path outside the compiled filesystem grants "for convenience". Empty allowlists mean deny, never allow.

## Rationale

- **The incumbent default is fail-open.** Claude Code "warns and runs unsandboxed" if its sandbox cannot start, unless `sandbox.failIfUnavailable` is set ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)). See [[Claude Code and sandbox-runtime]].
- **Sandbox off by default made a command allowlist load-bearing.** Gemini CLI's prefix-matched allowlist was bypassed while its sandboxing options were off by default ([Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)); see [[Gemini CLI Prefix Allowlist Bypass]].
- **Empty means allow-all is a fail-open bug.** sandbox-runtime < 0.0.16 did not enforce network restrictions when no allowed domains were configured ([GHSA-9gqj-5w7c-vx47](https://github.com/advisories/GHSA-9gqj-5w7c-vx47)); see [[sandbox-runtime Empty Allowlist Bypass]].
- **Convenience mounts are escapes.** srt warns that mounting `docker.sock` "would effectively grant access to the host system" ([srt](https://github.com/anthropic-experimental/sandbox-runtime)), and UK AISI found frontier models reliably exploit container misconfigurations such as exposed Docker sockets and privileged containers ([UK AISI](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities)). See [[SandboxEscapeBench]] and [[Container Runtimes and Escape History]].

A broker that silently degrades gives "a false sense of safety", which the NUL-byte researcher called worse than none. Refusing to start is the only honest behaviour.

## Required layers per backend

**Proposal.** The required set is data in the backend, reported by `SandboxBackend::probe` ([[Core Trait Contracts]]):

| Backend | Required | Degradable (org policy only, audited) |
|---|---|---|
| `macos-seatbelt` | generated SBPL applied via `sandbox-exec`; network only to the session loopback port; loopback listener up | none |
| `linux-native` | bwrap user+mount+PID namespaces; `--unshare-net` (no interface); seccomp filter (no new `AF_UNIX` after the bridge, no ptrace, bpf, raw sockets, keyctl); `PR_SET_NO_NEW_PRIVS`; UDS bridge up | Landlock network rules below ABI 4; Landlock FS layer only if an org bundle sets it best-effort |
| `container` / `vm` (phase 2) | runtime reachable, broker as the only egress, vsock or broker-peered NIC | none |

Landlock is the inner layer on Linux; its ABI must be probed at runtime ([Landlock docs](https://docs.kernel.org/userspace-api/landlock.html)). The [[Risk Register]] accepts "best-effort Landlock" for platform variance; this note narrows that to: only an **org-signed bundle** may mark Landlock best-effort, never a CLI flag ([[I8 No Flag Disables Isolation]]), and the degraded state is written to the audit event and shown by `broker doctor`.

## How it is enforced

- [[Sandbox Launcher]]: `probe()` runs before `launch()`; any required capability missing returns `Err`, and `launch()` re-verifies after applying (for example by attempting a forbidden `connect` inside the child before exec, and reading back the Landlock status).
- [[Broker CLI and Daemon]]: `session.start` returns an error rather than a handle when the netguard listener, CA or bundle is not ready; `broker run` maps every error to a non-zero exit with a `broker doctor` hint.
- [[Netguard Ingress]]: listeners start before the child and the launcher waits on their readiness; if the proxy dies mid-session, the sandbox has no route out, so traffic fails closed by topology.
- Schema: empty lists deny, unknown hosts deny, unmatched L7 requests deny (see [[CLAUDE]] working rules).

## Minimal test

**Proposal.** `tests/e2e/fail_closed`: for each backend and each required layer, inject a fault (remove `bwrap` from PATH, set the AppArmor userns sysctl to deny, make seccomp installation fail, stop the netguard listener, corrupt the bundle signature, simulate Landlock ABI 0) and assert that `broker run -- true` exits non-zero, that no child process was spawned, and that a `launch_refused` audit event names the missing layer. Add a config fuzz case asserting no profile can produce a mount of `/var/run/docker.sock` or any path outside the grants. This is the [[M0 Contained Run]] acceptance criterion "launch refuses to run if any layer is missing" and probe category 9 in [[Conformance Probe Matrix]].

## What would violate it

- A `--no-sandbox`, `--allow-unsandboxed` or automatic fallback path.
- Treating a missing seccomp helper as a warning.
- A profile option to bind-mount `docker.sock` or `$HOME` "for Docker workflows".
- Starting the agent first and the proxy "shortly after".
- Interpreting an empty `egress` list as unrestricted.

## How it connects

- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[Broker CLI and Daemon]]
- part-of:: [[Core Trait Contracts]]
- contrasts-with:: [[Claude Code and sandbox-runtime]]
- motivated-by:: [[Gemini CLI Prefix Allowlist Bypass]]
- motivated-by:: [[sandbox-runtime Empty Allowlist Bypass]]
- motivated-by:: [[Container Runtimes and Escape History]]
- motivated-by:: [[SandboxEscapeBench]]
- evaluated-by:: [[Conformance Probe Matrix]]
- delivered-by:: [[M0 Contained Run]]
- decided-by:: [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]

## Implications for the build

- Write the fault-injection harness in week one of M0, before the happy path.
- `BackendReport` must enumerate every layer with a status so the audit event and `broker doctor` share one source of truth.
- Installers (Homebrew, deb, rpm) must ship the Ubuntu AppArmor userns profile so fail-closed does not become "fails for everyone" on Ubuntu 24.04+.

## Open questions

- Whether any Landlock degradation should be allowed at all, or whether kernels without Landlock should be unsupported. An ADR must settle it before M0 closes.
- How to verify SBPL was actually applied on macOS from outside the child (srt reads violations from the system log); not in the record.

## Sources

- https://code.claude.com/docs/en/sandboxing
- https://github.com/anthropic-experimental/sandbox-runtime
- https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities
- https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack
- https://github.com/advisories/GHSA-9gqj-5w7c-vx47
- https://docs.kernel.org/userspace-api/landlock.html
- Report: invariant I2, "Fail closed" Proposal, Linux platform row, risk "Linux platform variance"; research note 05 section 3.2.
