---
title: "Registry and LLM API Adapters"
aliases: ["npm adapter", "LLM API adapter", "Package Registry Adapter"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/egress, topic/credentials, topic/supply-chain, control/egress, control/cred-out, boundary/tb4, invariant/i1, invariant/i4, invariant/i7, milestone/m1, evidence/conflict]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Package-registry adapters (npm, PyPI, crates, Go proxy read-only via GET/HEAD; publish denied unless granted; read-only tokens for private registries) and LLM API adapters (Anthropic, OpenAI, Gemini keys injected, base URL fixed by the broker, model and spend logged); gRPC and WebSocket handling."
related: ["[[Claude Code Pre-Trust Config Execution]]", "[[Credential Injector and Issuers]]", "[[Core Trait Contracts]]", "[[broker.toml Human Policy Layer]]", "[[July 2026 Artifactory Egress Incident]]", "[[Audit Recorder and Event Schema]]", "[[M1 Secrets Outside]]", "[[Sentinel Swap Pattern]]", "[[TLS Termination and Per-Session CA]]", "[[Policy Engine and Entity Builder]]", "[[Broker Cedar Schema]]", "[[I1 No Secrets in the Sandbox]]", "[[I4 Repo Policy Only Narrows]]", "[[I7 Reject Foreign Credentials]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[Nx s1ngularity Supply-Chain Attack]]", "[[SymCC CI Gates]]", "[[Conformance Probe Matrix]]", "[[Hostname Canonicaliser]]", "[[Sandbox Launcher]]", "[[Open Questions and Unverified Claims]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[Policy Learning Loop]]"]
sources: ["https://nvd.nist.gov/vuln/detail/CVE-2026-21852", "https://nvd.nist.gov/vuln/detail/CVE-2025-59536", "https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53", "https://www.anthropic.com/engineering/how-we-contain-claude", "https://vercel.com/docs/sandbox/concepts/firewall", "https://developers.openai.com/codex/cloud/internet-access", "https://www.wiz.io/blog/s1ngularity-supply-chain-attack"]
milestone: M1
code: ["code/crates/policy/src/l7.rs", "code/profiles/claude-code.toml", "code/profiles/claude-code-apikey.toml", "code/profiles/codex.toml", "code/profiles/gemini-cli.toml"]
---

# Registry and LLM API Adapters

> Package-registry adapters (npm, PyPI, crates, Go proxy read-only via GET/HEAD; publish denied unless granted; read-only tokens for private registries) and LLM API adapters (Anthropic, OpenAI, Gemini keys injected, base URL fixed by the broker, model and spend logged); gRPC and WebSocket handling.

## Responsibility

Four `ProtocolAdapter` implementations in `crates/l7/src/adapters/` ([[Core Trait Contracts]]): `npm.rs`, `pypi.rs`, `crates.rs` (plus a Go module proxy adapter, not scheduled in the milestone checklist) and `llm_apis.rs`. They sit on the L7 path of [[TLS Termination and Per-Session CA]] and turn registry and model-API traffic into Cedar requests with a meaningful audit verb.

- **Registries (report, Proposal).** "npm, PyPI, crates and the Go proxy are read-only (GET and HEAD). `publish` is denied unless explicitly granted. Private registries get a read-only token injected."
- **LLM APIs (report, Proposal).** "Anthropic, OpenAI and Gemini keys are injected, and model and spend metadata are logged. The base URL is fixed by the broker, which closes the CVE-2026-21852 redirect class" ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)).
- **gRPC and WebSocket (report).** "gRPC fits the same model, since it is HTTP/2 with `:path=/pkg.Service/Method`. For WebSockets, policy applies at the upgrade request."

**It must never:** allow a registry write method without an explicit publish grant; attach a registry token with write scope when a read-only one exists; let a model API key reach any host other than the provider host it is bound to; let the agent or the repo choose the provider base URL; log prompt or completion bodies by default; treat an unrecognised registry path as allowed (unmatched L7 requests deny, [[ADR-006 Deny Unmatched L7 Requests]]).

## Why these adapters exist

- **Repo config redirecting API calls.** Claude Code CVE-2026-21852: a malicious repo's project-load configuration could redirect API calls and "exfiltrate data including Anthropic API keys before users confirmed trust" ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-21852)); CVE-2025-59536 let code run before the trust dialog ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-59536)). See [[Claude Code Pre-Trust Config Execution]]. With the key held by the broker and bound to the canonical provider host, a redirected client carries only a sentinel to a host where it is worthless.
- **Allowed-domain abuse.** An attacker-planted key used against the allowlisted `api.anthropic.com` exfiltrated data ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)); the LLM adapter therefore relies on [[I7 Reject Foreign Credentials]], not on the host allowlist ([[Claude Cowork Allowed-Domain Abuse]]).
- **Registries as egress.** In the July 2026 incident the verified path "was actually a zero-day chain through the sanctioned Artifactory egress point", with details unconfirmed ([axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53)); see [[July 2026 Artifactory Egress Incident]]. Research note 01 lists "package registries acting as proxies" among the remaining exfiltration channels, mitigated by method- and path-scoped capabilities, request-body size limits and logging.
- **Stolen publish authority.** s1ngularity leaked 1,000+ valid GitHub tokens ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)); a sandbox that holds no registry token and cannot issue write methods removes the equivalent registry path ([[Nx s1ngularity Supply-Chain Attack]]).

## Inputs and outputs

- **Input:** a terminated request whose `CanonicalHost` matches a registry or provider host from the compiled policy, plus the session context.
- **Output:** `Vec<AuthzRequest>`: one `http.<METHOD>` on the canonical `PathPrefix`, plus `credential.use` when a credential is bound; an audit verb (`pkg.fetch npm:left-pad`, `pkg.publish crates:foo`, `llm.call anthropic model=<m>`); after the response, model and usage metadata for the audit event ([[Audit Recorder and Event Schema]]).

## Interface

**Proposal; not compiled.**

```rust
pub enum Ecosystem { Npm, PyPi, Crates, GoProxy }

pub struct RegistryAdapter { eco: Ecosystem, hosts: Vec<HostPattern> }
pub struct LlmApiAdapter  { provider: Provider, host: CanonicalHost }   // one per provider
pub enum Provider { Anthropic, OpenAi, Gemini }

impl ProtocolAdapter for RegistryAdapter {
    fn claims(&self, host: &CanonicalHost, _h: &http::request::Parts) -> bool;   // host match only
    async fn classify(&self, req: &mut BufferedRequest, s: &SessionCtx)
        -> anyhow::Result<Vec<AuthzRequest>>;   // http.GET/HEAD => verb pkg.fetch; write => pkg.publish
}

impl ProtocolAdapter for LlmApiAdapter { /* http.POST on PathPrefix + credential.use; verb llm.call */ }

/// Extracted after the response for audit only; never used for authorization.
pub struct LlmUsage { pub model: Option<String>, pub input_tokens: Option<u64>, pub output_tokens: Option<u64> }
```

Human layer ([[broker.toml Human Policy Layer]]): the first and last tables are verbatim from the report; the rest are **Proposal**.

```toml
[[egress]]
host = "api.anthropic.com"
credential = { kind = "static", ref = "keychain:anthropic" }

[[egress]]
host = "registry.npmjs.org"
methods = ["GET", "HEAD"]

# Proposal: private registry with an injected read-only token
[[egress]]
host = "npm.internal.example"
protocol = "npm"
methods = ["GET", "HEAD"]
credential = { kind = "static", ref = "keychain:npm-readonly" }

# Proposal: explicit publish grant (user or org scope only; never repo scope, I4)
[[egress]]
host = "registry.npmjs.org"
protocol = "npm"
allow = { publish = ["@acme/web-sdk"] }
credential = { kind = "static", ref = "keychain:npm-publish" }
approval = "required"
```

The compiler rejects `credential` tables in repo scope ([[I4 Repo Policy Only Narrows]]).

## Internal design

### Registries

**Proposal.**

1. **Path choice.** Registry hosts take the **L7** path even when public and credential-free, because a method rule is an L7 rule and because I7 cannot be checked on the L4 path ([[I7 Reject Foreign Credentials]] scope limit).
2. **Classification.** `GET`/`HEAD` → `http.GET`/`http.HEAD` on `PathPrefix::"<host>/<package path>"`, verb `pkg.fetch`. Any other method → the write request plus verb `pkg.publish`, which default policy denies. The precedent for method-level read-only egress is Codex cloud, whose HTTP-method restriction can limit requests to `GET`/`HEAD`/`OPTIONS` ([OpenAI Codex docs](https://developers.openai.com/codex/cloud/internet-access)).
3. **Private registries.** A `static` issuer holding a read-only token attaches it after Cedar allows; the sentinel swap follows [[Sentinel Swap Pattern]].
4. **Pull-through cache (optional).** Research note 03 suggests routing registries "through a pull-through cache for supply-chain scanning (Vercel `forwardURL` use case)" ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)). The cache host is itself a registry host under the same method rules, never a blanket allow.

> [!note] Background, not in the research record
> Publish endpoints (npm `PUT /<package>`, PyPI uploads to a separate upload host, crates `PUT /api/v1/crates/new`) and the read-only Go module proxy protocol come from ecosystem documentation, not the record. The method rule alone denies all of them; per-ecosystem path tables only improve audit verbs. Verify before relying on them.

> [!warning] Conflict
> Research note 03 says to allowlist public registry hosts "at L4" and terminate only private ones; the report makes all registries GET/HEAD-only, which needs L7. **Proposal:** follow the report (L7 for every registry host), since L4 cannot enforce methods or reject foreign tokens; revisit if L4 latency on large installs breaches the budget, and record the choice in an ADR.

### LLM APIs

**Proposal.**

1. **Fixed base URL.** The launcher sets the provider base-URL variables in `SandboxSpec.env` to the canonical provider URLs and ignores repo- or agent-config overrides ([[Sandbox Launcher]]); the API-key variable holds a sentinel bound to that provider host only.
2. **Classification.** `POST` to the provider's API paths → `http.POST` on `PathPrefix` plus `credential.use` on the provider credential; `GET` for model listing is allowed only if policy says so.
3. **Model and spend metadata.** After the response, parse the request's model field and the response's usage fields when present and add them to the audit event. Parsing is best-effort and never affects the decision; spend is computed from an org-configured price table. Field names are provider-specific and not in the record.
4. **Streaming.** Streamed responses pass through the response filter with a bounded rolling window.

### gRPC and WebSocket

**Proposal (report and research note 03).** gRPC is classified on HTTP/2 `:path` into `http.POST` on `PathPrefix::"<host>/<pkg.Service>/<Method>"`, so method-level policy works. WebSocket and other HTTP/1.1 `Upgrade` requests are authorized once at the upgrade request; "frames after the upgrade are opaque unless a protocol-specific inspector is added". Upgrades on hosts with injected credentials need explicit policy, because frames cannot be filtered for reflected secrets.

## State

None beyond the request; the static issuer's secret lives in `creds`. Per-session counters (bytes, requests, tokens used) live in netguard and audit.

## Failure modes and fail-closed behaviour

- Unrecognised method on a registry host: deny with `cedar_deny` (no publish grant).
- Credential location found in an undeclared place (for example an `_authToken` in a request body): reject as foreign.
- LLM usage parse failure: log `usage_unparsed`; never deny for that reason alone.
- Upgrade without matching policy: deny.
- Mint or keychain failure: deny with `mint_failed`.

## Security considerations

- **Adapter-declared credential locations.** Each adapter declares where its ecosystem carries credentials (headers, npm-style auth fields, provider key headers) so I7 strips and checks all of them.
- **Allowed hosts stay exfiltration channels.** Rate and volume limits apply on registry and model hosts; body-size limits on writes (publish grants) are advised by research note 01.
- **Prompt content in logs.** Only metadata is logged; prompts may contain secrets the agent read before the sandbox existed.
- **Supply chain.** Install scripts run inside the sandbox with no credentials; the adapter does not scan packages (a cache may).

## Performance budget

Classification is a host lookup plus method check (sub-microsecond) and one Cedar call (4.0–11.0 µs median, per [[Policy Engine and Entity Builder]]). The cost is TLS termination: registry installs open many connections, so leaf-certificate caching and upstream connection pooling matter. Warm p50 ≤5 ms, p95 ≤25 ms.

## Invariants upheld

[[I1 No Secrets in the Sandbox]] (keys held by the broker; sentinels only), [[I7 Reject Foreign Credentials]] (declared credential locations), [[I4 Repo Policy Only Narrows]] (no repo-scope credentials or publish grants), I6 via canonical host and path inputs.

## Test plan

- **Unit:** method and path tables per ecosystem; verb mapping; base-URL override ignored; usage extraction on recorded fixtures.
- **Property:** for random requests to registry hosts, no method other than GET/HEAD is ever allowed without a publish grant; a key sentinel is never attached to a host other than its provider host.
- **Fuzz:** the JSON extraction used for model and usage fields; the gRPC `:path` splitter.
- **Conformance** ([[Conformance Probe Matrix]]): category 1 (package publish on an allowed forge; foreign API key to an LLM host), category 2 (echo endpoint reflecting headers), category 5 (WebSocket upgrade without policy), category 8 (framing).
- **E2E** ([[M1 Secrets Outside]]): LLM calls succeed with the injected key; `npm publish` from the sandbox is denied and explained by `broker why`; a repo config that points the base URL at an attacker host yields no key.

## Crates

`l7` (adapters), `creds` (static issuer), `policy`; `serde_json` for bounded JSON extraction; `hyper` for h2 and upgrade handling.

## Delivering milestone

[[M1 Secrets Outside]]: `llm_apis.rs` and `{npm,pypi,crates}.rs` with interim method tables; they move to Cedar in M2. Go proxy and gRPC/WebSocket inspection follow when a design partner needs them.

## How it connects

- implements:: [[Core Trait Contracts]]
- implements:: [[Sentinel Swap Pattern]]
- depends-on:: [[Credential Injector and Issuers]]
- depends-on:: [[TLS Termination and Per-Session CA]]
- depends-on:: [[broker.toml Human Policy Layer]]
- depends-on:: [[Audit Recorder and Event Schema]]
- mitigates:: [[Claude Code Pre-Trust Config Execution]]
- mitigates:: [[July 2026 Artifactory Egress Incident]]
- mitigates:: [[Claude Cowork Allowed-Domain Abuse]]
- evaluated-by:: [[Conformance Probe Matrix]]
- delivered-by:: [[M1 Secrets Outside]]
- decided-by:: [[ADR-006 Deny Unmatched L7 Requests]]

## Implications for the build

- The broker's Cedar schema has no `pkg.*` actions ([[Broker Cedar Schema]]), yet the SymCC "deny rules stay live" gate names `pkg.publish` ([[SymCC CI Gates]]). **Proposal:** add `pkg.fetch` and `pkg.publish` actions (resource `PathPrefix`, context `HttpCtx`) in an ADR during M2, so "never publish without approval" is one analysable forbid.
- The [[Policy Learning Loop]] must classify `pkg.publish` as high-risk and never auto-grant it.

## Open questions

- Per-provider request and usage field names for model and spend logging are not in the record.
- Whether an org spend ceiling should become Cedar context (for example `context.session.spend`) or stay a logged metric.
- Go module proxy and checksum-database hosts: exact host list and whether `GOPROXY=direct` fetches (VCS over HTTPS) should be routed through the git adapter.
- L4 versus L7 for public registries (conflict above); see [[Open Questions and Unverified Claims]].

## Sources

- https://nvd.nist.gov/vuln/detail/CVE-2026-21852
- https://nvd.nist.gov/vuln/detail/CVE-2025-59536
- https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53
- https://www.anthropic.com/engineering/how-we-contain-claude
- https://vercel.com/docs/sandbox/concepts/firewall
- https://developers.openai.com/codex/cloud/internet-access
- https://www.wiz.io/blog/s1ngularity-supply-chain-attack
- Report: "Protocol adapters are the moat" (package registries, LLM APIs, gRPC/WebSocket), `broker.toml` example, SymCC gates; research notes 03 Q4 (package registries, gRPC/WebSocket), 01 (remaining exfil channels), 05 §3.2 (pkg-registries, llm-apis).

## Build log

- 2026-09-24: built as policy, not separate adapters: `protocol = "registry"` (GET/HEAD unless `methods` says otherwise), method/path rules for any terminated host, and static credentials for LLM APIs. Built-in profiles broker the agents' keys: Claude Code OAuth token or API key, `OPENAI_API_KEY` (codex), `GEMINI_API_KEY` (gemini-cli) ([[ADR-020 Brokered Agent Credentials End the Keychain Exception]]). A key is attached only on its declared host, so a base-URL redirect (the CVE-2026-21852 class) reaches a host with no credential.
- 2026-09-24: tests: `policy::l7::tests::methods_paths_and_default_deny` (registry publish denied), conformance `b1_i1_only_sentinels_inside_the_sandbox`, `b4_i7_planted_key_to_allowed_host_is_rejected`, `b5_sentinel_copied_off_host_is_useless`, `b6_llm_call_succeeds_with_injected_key`, `b7_injected_secret_is_never_reflected`, `cat2_unmatched_paths_and_methods_deny` (`tests/conformance/tests/m1_secrets.rs`); e2e `tests/e2e/fix_failing_test.sh claude` on macOS 26 (real `api.anthropic.com`, brokered OAuth token).
