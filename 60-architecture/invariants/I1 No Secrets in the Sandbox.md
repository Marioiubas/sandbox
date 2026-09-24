---
title: "I1 No Secrets in the Sandbox"
aliases: ["No Secrets Invariant"]
type: concept
section: architecture
tags: [sandbox/architecture, concept, invariant/i1, topic/credentials, control/cred-out, boundary/tb3, boundary/tb4, milestone/m1]
status: built
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "No secret material is ever present in the sandbox (env, files, argv, /proc, response bodies); only per-session sentinels that are useless off-host."
related: ["[[Sentinel Swap Pattern]]", "[[Credential Injector and Issuers]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[Nx s1ngularity Supply-Chain Attack]]", "[[Local Credential Proxies]]", "[[M1 Secrets Outside]]", "[[Core Trait Contracts]]", "[[L1 Conformance Suite]]", "[[Conformance Probe Matrix]]", "[[Sandbox Launcher]]", "[[TLS Termination and Per-Session CA]]", "[[I7 Reject Foreign Credentials]]", "[[Just-in-Time Credential Minting]]", "[[MCP Guard]]", "[[Filesystem Control and Rollback]]", "[[Threat Model Non-Goals]]", "[[ADR-005 Mint Credentials Per Task]]"]
sources: ["https://www.anthropic.com/engineering/how-we-contain-claude", "https://www.wiz.io/blog/s1ngularity-supply-chain-attack", "https://nx.dev/blog/s1ngularity-postmortem", "https://github.com/strongdm/leash", "https://code.claude.com/docs/en/sandboxing", "https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/", "https://modelcontextprotocol.io/specification/latest/basic/authorization"]
milestone: M1
---

# I1 No Secrets in the Sandbox

> No secret material is ever present in the sandbox (env, files, argv, /proc, response bodies); only per-session sentinels that are useless off-host.

## Statement

**Proposal.** For every sandboxed process tree (agent, its children, and every [[MCP Guard|wrapped MCP server]]) and for the whole life of a session, no byte sequence that is a usable upstream credential, a credential root, or broker key material may be observable from inside the sandbox through:

1. the process environment (`/proc/self/environ`, `env`);
2. any readable file (home directory, repo, tmp, mounted config such as `~/.config/gh/hosts.yml`, `~/.aws`, `~/.netrc`, `~/.docker/config.json`);
3. argv of any process visible to the sandbox, including the launcher's own helpers;
4. `/proc` or equivalent introspection of processes outside the sandbox;
5. any HTTP response body or header relayed back by the broker.

The only credential-shaped values allowed inside are **per-session sentinels**: opaque strings minted by `brokerd` for one session that the proxy swaps for real material on egress and that grant nothing when used anywhere else. "Secret material" includes minted tokens, static API keys, GitHub App private keys, AWS role credentials, OAuth refresh tokens, the user's IdP token and the per-session CA *private key* (only the CA certificate enters the sandbox).

The report's invariant table phrases it as "No secret material is ever present in the sandbox: env, files, argv, `/proc` or response bodies. Only per-session sentinels, useless off-host", motivated by "Cowork, Nx, Leash env forwarding".

## Rationale

- **Claude Cowork.** An attacker-planted API key in a mounted file turned the allowlisted `api.anthropic.com` into an exfiltration channel; Anthropic's answer was that credentials "stay in the host keychain and never enter the guest" and the proxy passes only the VM's own provisioned session token ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). See [[Claude Cowork Allowed-Domain Abuse]].
- **Nx s1ngularity.** Post-install malware found standing `gh`, npm and cloud credentials on disk and drove local AI CLIs to hunt for more; Wiz counted 1,000+ valid GitHub tokens and roughly 20,000 leaked files ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack); [Nx](https://nx.dev/blog/s1ngularity-postmortem)). See [[Nx s1ngularity Supply-Chain Attack]].
- **Env forwarding is the anti-pattern.** StrongDM Leash forwards API keys such as `ANTHROPIC_API_KEY` into the agent container ([Leash](https://github.com/strongdm/leash)), and E2B and Modal expose secrets as environment variables ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)). See [[Local Credential Proxies]].
- **MCP stdio.** The MCP spec tells stdio implementations to "retrieve credentials from the environment" ([MCP Authorization](https://modelcontextprotocol.io/specification/latest/basic/authorization)), which is exactly the pattern this invariant forbids; [[MCP Guard]] neutralises it with sentinels.

The reasoning is the object-capability one: an injected agent can misuse what it holds, so it must hold nothing transferable. A sentinel is a *name* for a capability that only the broker can resolve, under Cedar policy, for this session ([[Sentinel Swap Pattern]]).

## How it is enforced

**Proposal.** Four components share the enforcement, and each has its own test:

| Surface | Enforcer | Mechanism |
|---|---|---|
| env | [[Sandbox Launcher]] | `SandboxSpec.env` is built from an allowlist; every credential-bearing variable is replaced by a sentinel. The field is commented `// sentinels only (I1)` in [[Core Trait Contracts]] |
| files | [[Sandbox Launcher]] | Default `deny_read` of `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`, `~/.docker/config.json`, browser profiles and the keychain DB, compiled to SBPL or bwrap/Landlock rules ([[Filesystem Control and Rollback]]) |
| argv and `/proc` | [[Sandbox Launcher]], [[Broker CLI and Daemon]] | Secrets are never passed on any command line; `brokerd` runs outside the sandbox's PID namespace on Linux (`--unshare-pid`), and helpers receive sentinels only |
| response bodies | [[TLS Termination and Per-Session CA]] | L7 step 8: the response filter removes any injected secret before relaying |
| memory | [[Credential Injector and Issuers]] | `Issued.secret` is `Zeroizing`, lives only in broker memory, and roots stay in Keychain or libsecret |

On macOS the sandbox reaches the proxy over a loopback port, so each session authenticates with a sentinel `Proxy-Authorization` value; leaking it "grants nothing beyond the session's own policy, and only on that host" (report, Interfaces). The companion rule [[I7 Reject Foreign Credentials]] closes the other half: a secret that *does* get in (planted by an attacker) cannot be used.

## Minimal test

**Proposal.** `tests/conformance/cred_exposure` (probe category 2 of the [[Conformance Probe Matrix]]):

1. Seed canary secrets with unique random markers in the host environment, `~/.aws/credentials`, `~/.config/gh/hosts.yml`, the OS keychain entry the broker uses, and a GitHub App test key.
2. `broker run -- /bin/sh -c 'scan'`, where `scan` greps env, every readable file under `/`, all `/proc/*/environ` and `/proc/*/cmdline`, and the bodies returned by an echo server that reflects request headers.
3. Pass iff zero canary markers are found and every credential-shaped value matches the session's sentinel format.
4. Copy a sentinel out and present it from a second host or a second session: the broker must reject it and log the rejection.

This is the [[M1 Secrets Outside]] acceptance criterion ("automated scan finds only sentinels in env, files, argv and `/proc` ... a sentinel copied off-host is useless") and part of [[L1 Conformance Suite]].

## What would violate it

- Forwarding any credential env var "for compatibility" (the Leash pattern), including model API keys an agent CLI insists on.
- Mounting `$HOME` or any secret directory readable, or leaving a credential helper configured in the sandbox's git config.
- Passing a token to a helper via argv or a readable temp file.
- Returning a minted token in a response (for example an upstream token-exchange endpoint echoing it) without the response filter.
- Writing the per-session CA private key into the trust bundle directory.
- An MCP server launched with real env values because its manifest asked for them.

## How it connects

- implements:: [[Sentinel Swap Pattern]]
- motivated-by:: [[Claude Cowork Allowed-Domain Abuse]]
- motivated-by:: [[Nx s1ngularity Supply-Chain Attack]]
- contrasts-with:: [[Local Credential Proxies]]
- depends-on:: [[Credential Injector and Issuers]]
- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[TLS Termination and Per-Session CA]]
- part-of:: [[Core Trait Contracts]]
- evaluated-by:: [[L1 Conformance Suite]]
- evaluated-by:: [[Conformance Probe Matrix]]
- delivered-by:: [[M1 Secrets Outside]]
- decided-by:: [[ADR-005 Mint Credentials Per Task]]

## Implications for the build

- Make the sentinel a distinct Rust newtype so that no code path can place a `Zeroizing` secret into `SandboxSpec.env` without a compile error.
- The canary scan runs in CI on macOS and Linux for every PR touching `launcher`, `creds`, `tls`, `l7` or `mcpguard`.
- I1 does not stop misuse of legitimately granted authority ([[Threat Model Non-Goals]]); do not describe it as injection prevention.
- Grep the audit DB in the same test: the audit event carries a credential *ID*, never its value ([[I9 Hash-Chained Audit Outside the Sandbox]]).

## Open questions

- Sentinel format and binding are proposals: bind each sentinel to (session, issuer, allowed hosts) and make it unguessable; the exact encoding is not in the record.
- Claude Code masks secrets *inside* files via an `extract` regex on Linux but blocks the file on macOS ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)); whether the broker should offer in-file masking or only deny-read is open.
- Response filtering for streamed or compressed bodies needs a design that does not buffer unboundedly.

## Sources

- https://www.anthropic.com/engineering/how-we-contain-claude
- https://www.wiz.io/blog/s1ngularity-supply-chain-attack
- https://nx.dev/blog/s1ngularity-postmortem
- https://github.com/strongdm/leash
- https://code.claude.com/docs/en/sandboxing
- https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/
- https://modelcontextprotocol.io/specification/latest/basic/authorization
- Report: "Invariants every component must preserve" (I1), "Interfaces", L7 step 8, M1 acceptance; research notes 03 Q3 and 05 section 3.2.

## Build log

- 2026-09-24: M0 partial test `i1_host_secrets_in_the_client_environment_never_reach_the_sandbox`: canary values in `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `ANTHROPIC_API_KEY` and an unlisted variable are absent from env, argv and every visible `/proc/*/environ|cmdline` inside the sandbox (probe `env-scan`). The environment is an allowlist; secret-looking names are refused even in profiles. The full canary scan, sentinel swap and response filter are M1. Weakened on macOS for `claude-code` sessions in M0 by [[ADR-016 macOS M0 Compatibility Exceptions]] (keychain readable) until M1.
- 2026-09-24: canonical M1 test `b1_i1_only_sentinels_inside_the_sandbox`: a canary key is used through the broker (the upstream receives it), then `conformance-probe secret-scan` walks env, `/proc/*/environ|cmdline` (Linux) and files under `$HOME` (depth 3), `$TMPDIR`, the repository and the broker config dir: only the sentinel is found; the audit database bytes never contain the canary. Also `b7_injected_secret_is_never_reflected` (response filter) and the e2e check that `CLAUDE_CODE_OAUTH_TOKEN` is a sentinel and the keychain item and credentials file are unreadable. The M0 weakening (ADR-016 keychain exception) is closed by [[ADR-020 Brokered Agent Credentials End the Keychain Exception]].
- 2026-09-25 (M3): extended to MCP server principals: a pinned server's credential reaches its environment as a sentinel and is swapped only on its own egress (`m3_mcp` asserts the server sees `brk_s_…` while the API receives the real token) ([[ADR-030 MCP Guard as Built]]).
- 2026-09-25 (M3): CI: the runner identity token and the job's secrets never reach the agent tree (`m3_identity`, the `ci-mode` D1 job); the GitHub Action removes the checkout token from `.git/config` ([[ADR-031 CI Identity as Built]]).
