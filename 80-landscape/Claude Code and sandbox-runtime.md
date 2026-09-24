---
title: "Claude Code and sandbox-runtime"
aliases: ["srt", "sandbox-runtime", "Claude Code Sandbox", "Claude Code mask"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/isolation, topic/egress, topic/credentials, platform/macos, platform/linux, evidence/conflict, evidence/secondary]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Anthropic's srt (Apache-2.0 beta: Seatbelt; bwrap with netns removed and socat bridges) and Claude Code's sandbox with mask sentinels, injectHosts, experimental tlsTerminate and SigV4 re-signing; single-vendor, static-secret swap, warns and runs unsandboxed by default."
related: ["[[Seatbelt]]", "[[bubblewrap]]", "[[Sentinel Swap Pattern]]", "[[I2 Fail-Closed Launch]]", "[[sandbox-runtime Empty Allowlist Bypass]]", "[[sandbox-runtime SOCKS NUL-Byte Bypass]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[Native Config Exporters]]", "[[Gap Analysis]]", "[[Risk Register]]", "[[seccomp-bpf]]", "[[Topology-Forced Egress]]", "[[Claude Code DNS Exfiltration CVE-2025-55284]]", "[[Git Smart-HTTP Adapter]]", "[[I7 Reject Foreign Credentials]]", "[[L4 Product Metrics]]", "[[Open Questions and Unverified Claims]]", "[[OpenAI Codex CLI]]", "[[Just-in-Time Credential Minting]]", "[[Two-Tier Isolation Design]]", "[[broker.toml Human Policy Layer]]", "[[Claude Code Pre-Trust Config Execution]]", "[[Claude Code Path and Command Injection CVEs]]"]
sources: ["https://github.com/anthropic-experimental/sandbox-runtime", "https://code.claude.com/docs/en/sandboxing", "https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/", "https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/", "https://github.com/advisories/GHSA-9gqj-5w7c-vx47", "https://www.anthropic.com/engineering/claude-code-sandboxing", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://anthropic.com/engineering/claude-code-auto-mode", "https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/", "https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/", "https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/"]
---

# Claude Code and sandbox-runtime

> Anthropic's srt (Apache-2.0 beta: Seatbelt; bwrap with netns removed and socat bridges) and Claude Code's sandbox with mask sentinels, injectHosts, experimental tlsTerminate and SigV4 re-signing; single-vendor, static-secret swap, warns and runs unsandboxed by default.

## What it is

Two related Anthropic artifacts:

- **`sandbox-runtime` (`srt`)**, an open-source TypeScript/npm package with a static seccomp helper. It is Apache-2.0, labelled "Beta Research Preview", and was at v0.0.64 on 7 Jul 2026 ([GitHub](https://github.com/anthropic-experimental/sandbox-runtime)).
- **Claude Code's built-in sandbox**, built on srt, plus a credential feature (`sandbox.credentials`) that is the most direct bundled competitor to this product ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)).

The network sandbox went GA on 20 Oct 2025 in v2.0.24 ([Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)). Pricing is not separate; it ships inside Claude Code (plan pricing is not in the record).

## Architecture teardown

### Isolation

- **macOS:** `sandbox-exec` with Seatbelt profiles generated at runtime. Network is allowed only to "a specific localhost port" where the proxies listen. Violations are read from the system sandbox violation log. `allowAppleEvents` "removes code-execution isolation", and `enableWeakerNetworkIsolation` re-allows `com.apple.trustd.agent`, which srt itself calls an exfiltration vector ([GitHub](https://github.com/anthropic-experimental/sandbox-runtime); [[Seatbelt]]).
- **Linux:** bubblewrap applies bind-mount filesystem rules. "The network namespace of the sandboxed process is removed entirely", and traffic reaches host proxies over Unix sockets through socat bridges. A static `apply-seccomp` binary blocks new `AF_UNIX` socket creation (x64 and arm64 only). Filesystem rules take literal paths only. Dependencies are bwrap, socat and ripgrep, and Ubuntu 24.04+ needs the AppArmor userns sysctl relaxed ([GitHub](https://github.com/anthropic-experimental/sandbox-runtime); [[bubblewrap]], [[seccomp-bpf]]).
- **Windows (alpha):** a dedicated `srt-sandbox` local user plus WFP filters that block all outbound connections except loopback to proxy ports 60080-60089. Known gaps: "DNS resolution bypasses the fence", `proxyAuthToken` is visible on the command line, and CRL/OCSP fetches bypass the WFP filter ([GitHub](https://github.com/anthropic-experimental/sandbox-runtime)). Claude Code itself runs on macOS, Linux and WSL2, not native Windows ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)).

This is the same topology the broker adopts as its standard tier ([[Topology-Forced Egress]], [[Two-Tier Isolation Design]]).

### Network

- An HTTP proxy handles HTTP/HTTPS and a SOCKS5 proxy handles other TCP, with domain allow/deny lists and deny-all by default. `deniedDomains` wins over `allowedDomains` ([GitHub](https://github.com/anthropic-experimental/sandbox-runtime)).
- Config lives in `~/.srt-settings.json`: `network.allowedDomains/deniedDomains/allowUnixSockets` and `filesystem.denyRead/allowRead/allowWrite/denyWrite`. Writes are deny-by-default and reads allow-by-default. `.bashrc`, `.zshrc`, `.gitconfig`, `.vscode/`, `.idea/` and `.claude/` are always write-denied ([GitHub](https://github.com/anthropic-experimental/sandbox-runtime)).
- Self-documented limits: the filter "does not otherwise inspect traffic", broad domains like github.com enable exfiltration, domain fronting may bypass it, and programs that ignore proxy variables on Linux may bypass filtering ([GitHub](https://github.com/anthropic-experimental/sandbox-runtime)).
- Claude Code's proxy "by default, does not terminate or inspect TLS traffic", and there is "no built-in credential deny list" ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)).

### Credentials: `mask`

`sandbox.credentials` entries use `deny` or `mask`. With `mask`, the sandboxed process sees a per-session sentinel, and the proxy swaps in the real value only on requests to `injectHosts`. This requires `network.tlsTerminate`, which is experimental and needs v2.1.199+. It covers headers and bodies and **re-signs AWS SigV4** (`credentials.awsPairs`, v2.1.224+). It masks secrets inside files such as `~/.config/gh/hosts.yml` via an `extract` regex on Linux/WSL2; macOS blocks the file instead. **Repository-level settings cannot set `mask` or `tlsTerminate`** ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)). This is the [[Sentinel Swap Pattern]], shipped.

> [!question] Unverified
> One research session got a 404 on the srt README, so srt's own TLS-termination and sentinel-swap claims there rest on a secondary blog ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)). Another session read the README and reports optional experimental MITM with `excludeDomains` and `extraCaCertPaths`. Claude Code's docs independently document `mask`. See [[Open Questions and Unverified Claims]].

### Enterprise controls

`allowManagedDomainsOnly`, `strictAllowlist` (v2.1.219+), `allowUnsandboxedCommands: false` ("strict sandbox mode"), upstream corporate proxy chaining and `sandbox.failIfUnavailable` ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)). Without the last one, **if the sandbox cannot start, Claude Code warns and runs unsandboxed** by default.

### Related Anthropic designs

- Claude Code on the web keeps git credentials outside the sandbox. A custom git proxy checks that a push goes only "to the configured branch", then attaches the token ([Anthropic](https://www.anthropic.com/engineering/claude-code-sandboxing)).
- Cowork (a local VM): credentials stay in the host keychain. Its MITM proxy "only passes requests carrying the VM's own provisioned session token; an attacker-embedded key is rejected". This followed an incident in which an attacker key reached the allowlisted `api.anthropic.com` ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude); [[Claude Cowork Allowed-Domain Abuse]]).

## Security history

| Issue | What happened | Source |
|---|---|---|
| CVE-2025-55284 | Auto-approved `dig`/`nslookup` encoded `.env` secrets in DNS queries | [Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/); [[Claude Code DNS Exfiltration CVE-2025-55284]] |
| CVE-2025-66479 | `allowedDomains: []` meant allow-all (srt < v0.0.16) | [GHSA](https://github.com/advisories/GHSA-9gqj-5w7c-vx47); [[sandbox-runtime Empty Allowlist Bypass]] |
| SOCKS5 NUL-byte differential | `attacker.example\x00.google.com` passed the suffix check and resolved to the attacker; fixed in srt and in Claude Code 2.1.88-2.1.90; disclosed 20 May 2026; about 5.5 months of versions at risk | [Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/); [Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/); [[sandbox-runtime SOCKS NUL-Byte Bypass]] |

> [!warning] Conflict
> The NUL-byte fix is dated 27 March 2026 by Penligent and 1 April 2026 by the researcher; the affected range 2.0.24-2.1.89 is the researcher's claim.

Anthropic's own lesson: "Be wary of custom components", and its custom proxy repeatedly introduced vulnerabilities ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).

### Published metrics

- "Sandboxing safely reduces permission prompts by 84%", from internal usage, with no sample size or method ([Anthropic](https://www.anthropic.com/engineering/claude-code-sandboxing)).
- Users approve 93% of permission prompts. The auto-mode classifier has 0.4% FPR on 10,000 real tool calls, 17% FNR on 52 real overeager actions and 5.7% FNR on 1,000 synthetic exfiltrations ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)).
- In a red-team exercise, credential exfiltration succeeded 24 times in 25 retries before mitigations ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).

These anchor [[L4 Product Metrics]]. A user write-up reports that `/sandbox` struggles with Docker workflows, MCP server network access and browser automation ([Infralovers](https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/)).

## Strengths

- The standard-tier recipe in production on both OSes, open source and Apache-2.0.
- Credential masking with SigV4 re-signing, and a correct rule that repository settings cannot enable injection.
- Enterprise lock-down flags exist.

## Weaknesses (versus this thesis)

- **Single vendor.** It protects Claude Code, not Codex, Cursor or stdio MCP servers run by other hosts.
- **Static-secret swap, no minting.** The real long-lived secret is attached; nothing is repo-, branch- or task-scoped ([[Just-in-Time Credential Minting]]).
- **Host-level injection only.** No method, path or git-ref semantics ([[Git Smart-HTTP Adapter]]).
- **Fail-open default** (warn and run unsandboxed), which [[I2 Fail-Closed Launch]] rejects.
- **Enforcement-layer bugs** in the custom proxy, as the table above shows.

## What we reuse or interoperate with

- **Reuse the shape:** netns removed + UDS bridge + seccomp `AF_UNIX` block on Linux; generated SBPL with a localhost-only port on macOS.
- **Adopt** "repository settings cannot enable injection" as [[I4 Repo Policy Only Narrows]] plus no credentials in repo layers ([[broker.toml Human Policy Layer]]).
- **Adopt** Cowork's sentinel-only rule as [[I7 Reject Foreign Credentials]].
- **Export to it:** managed settings via [[Native Config Exporters]], so Claude Code's own controls become a second layer.

## How we differentiate

Cross-agent neutrality, minting bound to user, agent, repo and task, developer-protocol semantics, a verified learning loop and one audit stream ([[Gap Analysis]]). Bundling is the sharpest threat: Claude Code already ships `mask` with SigV4 re-signing ([[Risk Register]]).

## How it connects

- competes-with:: [[Product Thesis]] (the named bundling threat)
- depends-on:: [[Seatbelt]]
- depends-on:: [[bubblewrap]]
- example-of:: [[Sentinel Swap Pattern]]
- contrasts-with:: [[I2 Fail-Closed Launch]]
- mitigated-by:: [[I7 Reject Foreign Credentials]]
- motivated-by:: [[sandbox-runtime Empty Allowlist Bypass]]
- motivated-by:: [[sandbox-runtime SOCKS NUL-Byte Bypass]]
- motivated-by:: [[Claude Cowork Allowed-Domain Abuse]]
- contrasts-with:: [[OpenAI Codex CLI]]
- Export target of: [[Native Config Exporters]]
- Analysed in: [[Gap Analysis]] and [[Risk Register]] (row "Vendors bundle the feature")

## Implications for the build

- Reproduce srt's three enforcement bugs (empty list, NUL byte, DNS) as permanent regression probes in [[L1 Conformance Suite]].
- Measure prompt reduction on replayed traces rather than quoting 84% ([[L4 Product Metrics]]).
- `broker run -- claude` must work with Claude Code's own sandbox disabled *and* enabled; test both, since nested bwrap may fail.

## Open questions

- Does Claude Code export audit events to a SIEM natively? Not in the record.
- Will Claude Code's hook API expose enough task context for a broker to bind credentials to a task? Unknown ([[Open Questions and Unverified Claims]]).

## Sources

- [anthropic-experimental/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- [Claude Code docs: sandboxing](https://code.claude.com/docs/en/sandboxing)
- [Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/); [Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/); [GHSA-9gqj-5w7c-vx47](https://github.com/advisories/GHSA-9gqj-5w7c-vx47); [Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)
- [Anthropic: Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing); [Anthropic: How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude); [Anthropic: auto mode](https://anthropic.com/engineering/claude-code-auto-mode)
- [Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/); [Infralovers](https://www.infralovers.com/blog/2026-02-15-sandboxing-claude-code-macos/)
