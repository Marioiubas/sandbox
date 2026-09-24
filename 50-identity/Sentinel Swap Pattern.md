---
title: "Sentinel Swap Pattern"
aliases: ["Placeholder Swap", "Sentinels", "mask"]
type: "concept"
section: "identity"
summary: "Per-session sentinel values stand in for secrets inside the sandbox and are swapped for real credentials only on egress to permitted hosts; the placeholder pattern eight products ship in 2026 and this design's static-credential fallback."
tags: [sandbox/identity, concept, topic/credentials, topic/egress, topic/tls, control/cred-out, boundary/tb3, boundary/tb4, invariant/i1, invariant/i7, milestone/m1]
status: verified
confidence: high
milestone: M1
created: 2026-09-24
updated: 2026-09-24
related: ["[[I1 No Secrets in the Sandbox]]", "[[I7 Reject Foreign Credentials]]", "[[Credential Injector and Issuers]]", "[[Claude Code and sandbox-runtime]]", "[[Docker Sandboxes]]", "[[Local Credential Proxies]]", "[[Just-in-Time Credential Minting]]", "[[MCP Guard]]", "[[Gap Analysis]]", "[[M1 Secrets Outside]]", "[[Open Questions and Unverified Claims]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[Conformance Probe Matrix]]"]
---

# Sentinel Swap Pattern

Inside the sandbox, every secret is replaced by a per-session sentinel value; the broker's TLS-terminating proxy swaps the sentinel for the real credential only on requests to hosts, methods and paths the policy permits, and rejects any credential it did not issue. By September 2026 eight products ship this placeholder pattern, so it is commodity, not a wedge. In this design it is the fallback for static credentials that providers cannot mint, and the mechanism that lets unmodified tools and stdio MCP servers keep "reading secrets from the environment".

## Mechanics

1. **Session start.** For each static credential the task may use, the broker generates a random sentinel (per session, never reused) and records `(sentinel → credential ref, allowed hosts, methods, path prefixes, TTL, session id)`. The research note's binding tuple is (sandbox id, domain, method, path prefix, TTL) (research note 01 inference).
2. **Sandbox environment.** The sentinel is placed where the tool expects the secret: an env var (`ANTHROPIC_API_KEY=brk_s_…`), a masked config file, or a stdio MCP server's env ([[I1 No Secrets in the Sandbox]]).
3. **Egress.** The request reaches the broker (topology guarantees it); for hosts with credential rules the proxy terminates TLS with the per-session CA, parses HTTP, and authorizes with Cedar (`credential.use` on that credential with `dest_host`, method, path).
4. **Strip and reject.** Every client-supplied `Authorization`, `x-api-key`, cookie and `Proxy-Authorization` header is stripped, and **any request carrying a credential the broker did not issue is rejected** ([[I7 Reject Foreign Credentials]]).
5. **Swap.** If allowed, the sentinel is replaced with the real value in the header (and in bodies where configured); SigV4 requests are re-signed rather than swapped.
6. **Response filter.** The response is scanned so injected secrets are never reflected back into the sandbox.
7. **Off-host.** A sentinel copied off-host is useless: it is only honoured by this broker, for this session, on this host ([[M1 Secrets Outside]]).

## Who ships it (September 2026)

| Product | How it swaps | Notable detail |
|---|---|---|
| Claude Code (`sandbox.credentials` `mask`) | per-session sentinel swapped only on requests to `injectHosts`; needs experimental `network.tlsTerminate` (v2.1.199+); covers headers and bodies; re-signs SigV4 (`credentials.awsPairs`, v2.1.224+); masks secrets inside files such as `~/.config/gh/hosts.yml` via an `extract` regex on Linux/WSL2 (macOS blocks the file) | repository-level settings cannot set `mask` or `tlsTerminate` ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)) |
| Docker Sandboxes | "The proxy replaces the sentinel with the real credential after the request has left the microVM"; "the real credential stays outside the sandbox throughout the request" | injection limited to built-in providers; custom rules requested ([Docker architecture](https://docs.docker.com/ai/sandboxes/architecture/); [desktop-feedback #130](https://github.com/docker/desktop-feedback/issues/130)) |
| Infisical Agent Vault | placeholders like `__anthropic_api_key__` swapped per host and path; `unmatched_host_policy=deny` | relies on `HTTPS_PROXY`; no sandbox ([Agent Vault](https://github.com/Infisical/agent-vault)) |
| Vercel, Cloudflare, E2B, Runloop, OpenShell | host-side proxy injects headers from stored secrets (per-sandbox CA at Vercel and Cloudflare; devbox-bound tokens at Runloop) | [Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall); [Cloudflare](https://blog.cloudflare.com/sandbox-auth/); [E2B docs](https://docs.e2b.dev/network/internet-access.md); [Runloop](https://docs.runloop.ai/docs/devboxes/agent-gateways); [NVIDIA OpenShell](https://github.com/NVIDIA/openshell) |

"Eight products put a host-side proxy with a per-sandbox CA in front of the agent and inject secrets so they never enter the sandbox: Claude Code (v2.1.199+), Docker, Vercel, Cloudflare, E2B, Runloop, OpenShell and Agent Vault" (report, "The gap to own"). A new entrant cannot win on that ([[Gap Analysis]]).

> [!question] Unverified
> The claim that sandbox-runtime itself swaps per-session sentinels at a TLS-terminating proxy rests on a secondary blog ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)); the srt README fetch returned 404 in one session. Claude Code's docs independently document `mask` ([[Open Questions and Unverified Claims]]).

## Anti-patterns it replaces

- **Env-var secrets inside the sandbox.** E2B and Modal expose secrets as environment variables readable inside the VM; E2B docs say they "are not private in the OS" ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)). StrongDM Leash forwards `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` into the agent container ([Leash](https://github.com/strongdm/leash)).
- **Allowlist without credential binding.** In the Cowork incident, an attacker-planted API key in a mounted file used the allowlisted `api.anthropic.com` to exfiltrate; Anthropic's fix is a proxy that "only passes requests carrying the VM's own provisioned session token; an attacker-embedded key is rejected" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). Swap without step 4 is not enough; see [[Claude Cowork Allowed-Domain Abuse]].
- **Matchers that never block.** Vercel passes unmatched requests unchanged, just without the credential ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)); in the broker, method and path rules are authorization, default-deny within an allowed domain ([[ADR-006 Deny Unmatched L7 Requests]]).

## Limits of the pattern

- It "prevents theft but not misuse": an agent with a legitimate `repo:write` token can still act maliciously through the proxy ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)).
- The swapped secret is still **static and long-lived** upstream; if the broker is compromised or the upstream leaks it, scope and lifetime are whatever the static key had. That is why the design prefers [[Just-in-Time Credential Minting]] and uses the swap only where providers cannot mint (static SaaS API keys, LLM API keys).
- Certificate-pinned clients cannot be terminated; they go on a passthrough list with **no** injection.

## Verdict for the broker

**Proposal.**

- **Use it for:** LLM API keys and static SaaS keys; stdio MCP server env secrets; masked config files; the macOS loopback session credential (`Proxy-Authorization` sentinel).
- **Don't use it for:** GitHub or AWS when minting is available; pinned clients; any host without an explicit credential rule.
- **How we integrate it.** The sentinel store and `static` issuer in `crates/creds` ([[Credential Injector and Issuers]]): sentinels generated with a CSPRNG and a recognisable prefix so the canary scanner can find them; real values fetched from the OS keychain (or 1Password/Vault/AWS SM) and held in `Zeroizing` buffers; header and body swap in the L7 path after Cedar allows; a foreign-credential detector (known key formats plus "any auth header that is not a live sentinel") that rejects and logs.

## How it connects

- implements:: [[I1 No Secrets in the Sandbox]]
- implements:: [[I7 Reject Foreign Credentials]]
- delivered-by:: [[Credential Injector and Issuers]] (sentinel store, `static` issuer)
- example-of:: [[Claude Code and sandbox-runtime]] (`mask`)
- example-of:: [[Docker Sandboxes]]
- example-of:: [[Local Credential Proxies]] (Agent Vault)
- contrasts-with:: [[Just-in-Time Credential Minting]] (preferred where providers allow)
- depends-on:: [[MCP Guard]] (stdio server env sentinels)
- motivated-by:: [[Gap Analysis]] (commodity, not a wedge)
- mitigates:: [[Claude Cowork Allowed-Domain Abuse]]
- delivered-by:: [[M1 Secrets Outside]]

## Implications for the build

- M1 acceptance: an automated scan finds only sentinels in env, files, argv and `/proc`; an attacker-planted API key to an allowed host is rejected; a sentinel copied off-host is useless ([[M1 Secrets Outside]]).
- Conformance category 1 (foreign key to an allowed host) and 2 (credential exposure, echo endpoints reflecting headers) ([[Conformance Probe Matrix]]).
- Fuzz the body-swap path: the swap must not change framing (Content-Length, chunking) incorrectly.

## Open questions

- srt's own sentinel implementation details are secondary-sourced ([[Open Questions and Unverified Claims]]).

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.

## Build log

- 2026-09-24: implemented in `creds::sentinel` and the L7 pipeline: per-session sentinels bound to the credential's hosts; a sentinel on a bound host is replaced by the broker's credential, on any other host it is `sentinel_wrong_host`; body swap is opt-in per credential (`swap_body`). Off-host uselessness tested by `b5_sentinel_copied_off_host_is_useless`.
