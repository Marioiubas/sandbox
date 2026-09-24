---
title: "Seatbelt"
aliases: ["sandbox-exec", "SBPL"]
type: "primitive"
section: "primitives"
summary: "macOS kernel sandbox driven by generated SBPL via sandbox-exec: deny writes except repo and tmp, deny secret reads, network only to the broker's localhost port, no Apple Events or trustd; deprecated in the man page with no removal date."
tags: [sandbox/primitives, primitive, topic/isolation, topic/egress, topic/filesystem, platform/macos, control/iso, control/fs, control/egress, boundary/tb2, boundary/tb3, milestone/m0]
status: verified
confidence: high
milestone: M0
created: 2026-09-24
updated: 2026-09-24
related: ["[[Apple Virtualization Framework]]", "[[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]", "[[Sandbox Launcher]]", "[[Topology-Forced Egress]]", "[[Two-Tier Isolation Design]]", "[[Risk Register]]", "[[Claude Code and sandbox-runtime]]", "[[Netguard Ingress]]", "[[Sentinel Swap Pattern]]", "[[Open Questions and Unverified Claims]]", "[[I5 Config Outside Writable Mounts]]", "[[M0 Contained Run]]"]
---

# Seatbelt

Seatbelt is macOS's kernel sandbox, driven from the command line by `sandbox-exec` with a profile written in SBPL (Sandbox Profile Language). Both Anthropic's sandbox-runtime and OpenAI's Codex CLI generate SBPL at runtime to confine coding agents, and the broker does the same: deny writes except the repo and tmp, deny reads of secret directories, allow network only to the broker's per-session localhost port, and deny Apple Events and `trustd`. `sandbox-exec` has been marked deprecated in its man page since at least macOS 15.4 with no removal date, so a Virtualization.framework backend is the hedge.

## Mechanism and boundary

- `sandbox-exec -p '<SBPL>' -- cmd` applies a kernel-enforced profile to the process and all descendants. Profiles are S-expressions of `(allow …)` / `(deny …)` operations (`file-read*`, `file-write*`, `network-outbound`, `mach-lookup`, `process-exec`…) with path and address filters (SBPL syntax is background knowledge; the record cites srt's generated profiles, not the grammar).
- **TCB.** The macOS kernel sandbox (Sandbox.kext) plus whatever Mach services the profile leaves reachable (research note 01 matrix). The kernel is shared, so kernel exploits are out of scope for this tier.
- **Start and overhead.** ~ms start, ~0 memory overhead; a VM fallback raised start from <5 ms to ~800 ms in one project's measurement ([apple/containerization#737](https://github.com/apple/containerization/issues/737)).

## How srt, Codex and others use it

- **srt:** `sandbox-exec` with Seatbelt profiles generated at runtime; network allowed only to "a specific localhost port" where the proxies listen; violations read from the system sandbox violation log; globs supported in paths (unlike Linux) ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).
- srt's two escape hatches show what the profile must never allow:
  - `allowAppleEvents` "removes code-execution isolation" (the agent can script other apps) ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).
  - `enableWeakerNetworkIsolation` re-allows `com.apple.trustd.agent`, which Go programs need for TLS verification, and which srt calls an exfiltration vector ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).
- **Codex CLI** uses Seatbelt on macOS for its `read-only` / `workspace-write` / `danger-full-access` modes; "the sandbox applies to spawned commands, not just to built-in file operations" ([Codex docs](https://learn.chatgpt.com/codex/sandboxing)). Its exact base policy was not retrieved.
- **Gemini CLI** ships Seatbelt profiles (`permissive-open` default, `restrictive-proxied`, `strict-open`…) ([Gemini CLI docs](https://geminicli.com/docs/cli/sandbox/)).
- A user write-up reports Claude Code's `/sandbox` (built on srt) gives "roughly 84% fewer permission prompts" (figure attributed to Anthropic, no methodology) and struggles with Docker workflows, MCP server network access and browser automation ([Infralovers](https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/)).

## The broker's generated profile

**Proposal** (report macOS row). Shape only; the SBPL is generated from Cedar `fs.*` grants and the session's egress port. Not compiled or tested.

```scheme
(version 1)
(deny default)
(allow process-fork process-exec)                 ; confined by the rules below
(allow file-read* (subpath "/usr") (subpath "/System") (subpath "/Library")
                  (subpath "${REPO}") (subpath "${TMP}") (subpath "${TOOLCHAINS}"))
(deny  file-read* (subpath "${HOME}/.ssh") (subpath "${HOME}/.aws")
                  (subpath "${HOME}/.config/gh") (literal "${HOME}/.netrc")
                  (literal "${HOME}/.docker/config.json") (subpath "${HOME}/Library/Keychains"))
(allow file-write* (subpath "${REPO}") (subpath "${TMP}"))
(deny  file-write* (subpath "${REPO}/.git/hooks") (literal "${REPO}/.git/config")
                   (subpath "${REPO}/.claude") (subpath "${REPO}/.vscode") (subpath "${REPO}/.cursor"))
(allow network-outbound (remote ip "localhost:${BROKER_PORT}"))   ; the only egress
(deny  network-outbound (remote unix-socket (path-literal "${CTL_SOCK}")))
(deny  mach-lookup (global-name "com.apple.trustd.agent"))         ; no trustd exfil path
(deny  appleevent-send)                                            ; no Apple Events
```

The `network-outbound (remote ip "localhost:PORT")` form is the research note's recommended rule (research note 01 Q5), matching srt's documented localhost-port-only design ([srt](https://github.com/anthropic-experimental/sandbox-runtime)); the other operation names are background knowledge to be verified against a working profile on macOS 15 and 26.

### Why localhost needs a session credential

On macOS any local process can reach a loopback port, so the data plane authenticates each session with a sentinel `Proxy-Authorization` value; leaking it grants nothing beyond that session's own policy, and only on that host (report interfaces paragraph; see [[Sentinel Swap Pattern]] and [[Netguard Ingress]]).

### Transparent interception is not available

Without a Network Extension, transparent interception on macOS is unvalidated; tools that ignore proxy variables simply fail because nothing else is reachable. That fails closed and is accepted for the MVP ([[Open Questions and Unverified Claims]]).

## Deprecation and platform risk

- `man sandbox-exec` on macOS 15.4: "execute within a sandbox (DEPRECATED)" ([openai/codex#215](https://github.com/openai/codex/issues/215)). The tool "still works today", but deprecation creates "long-term uncertainty" ([Infralovers](https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/)).
- Apple suggests "Consider adopting the App Sandbox instead", with **no published removal date**; App Sandbox needs entitlements and signed app bundles; Endpoint Security is observation-only; System Extensions are distribution-gated ([apple/containerization#737](https://github.com/apple/containerization/issues/737)).
- Apple has made no statement on removal or a replacement per-process API ([[Open Questions and Unverified Claims]]).
- Mitigating factor: Claude Code, Codex and Gemini CLI all depend on the same mechanism, so Apple breaking it would break the incumbents too (research note 05 §4 inference).

## Verdict for the broker

**Proposal.**

- **Use it for:** the zero-install macOS standard tier and the wrapper for local stdio MCP servers on macOS.
- **Don't use it for:** long-term sole dependence; any profile with Apple Events or `trustd` re-enabled (Go clients that need `trustd` go on a documented compatibility list rather than weakening every session); kernel-exploit resistance.
- **How we integrate it.** `macos-seatbelt` backend in [[Sandbox Launcher]]: generate SBPL from the compiled FS policy, write it to a root- or broker-owned path outside every writable mount ([[I5 Config Outside Writable Mounts]]), exec `/usr/bin/sandbox-exec -f <profile> -- <agent>` with an absolute path, set proxy variables and the merged CA bundle environment, and read the sandbox violation log for `broker why`. `probe()` checks that `sandbox-exec` exists and that a canary profile actually denies a secret read, and fails closed. Keep the VZ backend ([[Apple Virtualization Framework]]) on the roadmap per [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]].

## How it connects

- part-of:: [[Two-Tier Isolation Design]] (macOS standard tier)
- decided-by:: [[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]
- contrasts-with:: [[Apple Virtualization Framework]] (the hard-tier hedge)
- delivered-by:: [[Sandbox Launcher]] (`macos-seatbelt` backend)
- implements:: [[Topology-Forced Egress]] (loopback-port-only egress)
- depends-on:: [[Netguard Ingress]] (per-session proxy port and credential)
- example-of:: [[Claude Code and sandbox-runtime]] (runtime-generated SBPL)
- mitigated-by:: [[Risk Register]] ("macOS Seatbelt removal" risk row)
- delivered-by:: [[M0 Contained Run]]

## Implications for the build

- M0 acceptance runs `broker run -- claude` and `-- codex` on macOS 15 and 26 ([[M0 Contained Run]]); reading `~/.ssh/id_ed25519` must be denied.
- Conformance category 9 must include "connect to another localhost port", "connect to `ctl.sock`" and "`osascript` Apple Event" probes.
- Track `sandbox-exec` behaviour each macOS beta in CI; a behavioural change is a release blocker.

## Open questions

- No Apple statement on removal or replacement ([[Open Questions and Unverified Claims]]).
- Transparent interception on macOS without a Network Extension is unvalidated.
- Codex's exact SBPL base policy was not retrieved; the operation names in the sketch above need a working test profile.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
