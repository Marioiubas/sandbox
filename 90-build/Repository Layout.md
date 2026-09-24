---
title: "Repository Layout"
aliases: ["Repo Layout", "Workspace Layout"]
type: concept
section: build
tags: [sandbox/build, concept, topic/build]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Repository Layout

> The Cargo workspace tree that code/ must follow: crates (broker-cli, brokerd, launcher, netguard, tls, l7, creds, policy, grant, audit, learn, mcpguard), profiles, policies, integrations, ee/, tests (e2e, conformance, bypass-corpus, fuzz), eval, packaging and docs.

## Summary

`code/` at the vault root is the repository root of the product ([[CLAUDE]] section 7). It follows the report's `broker/` tree exactly: one Cargo workspace, twelve crates that meet at four traits ([[Core Trait Contracts]]), Apache-2.0 everywhere except `ee/` ([[ADR-014 Apache-2.0 Endpoint with Commercial ee]]). This note gives the verbatim tree, a file-level expansion Claude Code creates milestone by milestone, and the rules that keep the layout honest.

## Details

### The report tree (verbatim; Proposal, not compiled)

```
broker/
├── Cargo.toml                 # workspace; Apache-2.0 except ee/
├── crates/
│   ├── broker-cli/            # run, init, learn, suggest, why, audit, login, mcp {wrap,connect}, doctor
│   ├── brokerd/               # session manager, ctl.sock JSON-RPC, bundle sync, keychain access
│   ├── launcher/              # SandboxBackend trait; backends/{seatbelt,linux,container,vm}
│   ├── netguard/              # canonicaliser, DNS policy resolver, CONNECT/SOCKS5/transparent ingress
│   ├── tls/                   # per-session CA, leaf cache, trust-bundle writer
│   ├── l7/                    # http1/h2; adapters/{git_smart_http,github_api,npm,pypi,crates,llm_apis,mcp}
│   ├── creds/                 # sentinel store; issuers/{static,github_app,aws_sts,oauth_exchange,vault}
│   ├── policy/                # cedar schema, entity builder, TOML→Cedar compiler, exporters/{claude,codex,cursor,openshell}
│   ├── grant/                 # Txn-Token-shaped grant JWT, DPoP binding (CI/gateway)
│   ├── audit/                 # SQLite hash chain, OCSF mapping, OTLP exporter
│   ├── learn/                 # trace aggregation, generaliser, risk classifier, Cedar diff
│   └── mcpguard/              # stdio relay, manifest pinning, tools/call policy
├── profiles/                  # built-in agent profiles: claude-code, codex, gemini-cli, cursor-agent
├── policies/                  # org ceiling templates, default deny lists, SymCC gate specs
├── integrations/{github-action,k8s}/
├── ee/                        # control plane (commercial): server, SCIM, SIEM sinks, approvals, UI
├── tests/{e2e,conformance,bypass-corpus,fuzz}/
├── eval/{agentdojo_shim,agentdyn,swebench_ab,tbench_ab,escapebench}/
├── packaging/                 # homebrew, notarize, nfpm, cosign, SBOM
└── docs/                      # threat model, policy reference, deployment guides
```

Research note 05's variant adds an `aider` profile, splits `launcher` into `seatbelt/`, `linux/` and `container/` (the container backend marked "phase 1.5"), and places `mcp_http` under `l7` adapters. Where the two differ, follow the report tree above; the variant's extra detail is folded into the expansion below.

### File-level expansion under `code/` (Proposal)

The expansion names the modules each milestone creates. Module names are proposals; changing them needs no ADR, but changing crate boundaries does.

```
code/
├── Cargo.toml                         # [workspace] members = crates/*; license = "Apache-2.0"
├── Cargo.lock
├── rust-toolchain.toml
├── LICENSE                            # Apache-2.0
├── crates/
│   ├── broker-cli/src/{main.rs, cmd/{run,init,learn,suggest,why,audit,login,mcp,doctor}.rs}
│   ├── brokerd/src/{main.rs, session.rs, ctl_rpc.rs, peercred.rs, bundle_sync.rs, keychain.rs}
│   ├── launcher/src/{lib.rs, spec.rs, probe.rs, fs_compile.rs,
│   │                 backends/{seatbelt/{mod.rs, sbpl.rs}, linux/{mod.rs, bwrap.rs, netns_bridge.rs,
│   │                 landlock.rs, seccomp.rs}, container/mod.rs, vm/mod.rs}}
│   ├── netguard/src/{lib.rs, canon.rs, resolver.rs, dns_stub.rs, ingress/{connect.rs, socks5.rs,
│   │                 transparent.rs}, splice.rs}
│   ├── tls/src/{lib.rs, session_ca.rs, leaf_cache.rs, trust_bundle.rs, sni_peek.rs}
│   ├── l7/src/{lib.rs, http1.rs, h2.rs, redirect.rs, response_filter.rs,
│   │           adapters/{git_smart_http.rs, pktline.rs, github_api.rs, npm.rs, pypi.rs, crates.rs,
│   │           llm_apis.rs, mcp.rs}}
│   ├── creds/src/{lib.rs, sentinel.rs, foreign_reject.rs, cache.rs,
│   │              issuers/{static_.rs, github_app.rs, aws_sts.rs, sigv4.rs, oauth_exchange.rs, vault.rs}}
│   ├── policy/src/{lib.rs, schema.cedarschema, entities.rs, authorize.rs, toml_compile.rs, trifecta.rs,
│   │               exporters/{claude.rs, codex.rs, cursor.rs, openshell.rs}}
│   ├── grant/src/{lib.rs, txn_token.rs, dpop.rs}
│   ├── audit/src/{lib.rs, chain.rs, store.rs, ocsf.rs, otlp.rs, verify.rs}
│   ├── learn/src/{lib.rs, record.rs, templatize.rs, generalise.rs, risk.rs, diff.rs, replay.rs}
│   └── mcpguard/src/{lib.rs, relay.rs, manifest_pin.rs, tools_call.rs, wrap.rs}
├── profiles/{claude-code, codex, gemini-cli, cursor-agent}.toml
├── policies/{ceiling/org-ceiling.cedar, deny/default-deny.toml, gates/*.toml}
├── integrations/github-action/{action.yml, README.md}
├── integrations/k8s/                  # phase 2
├── ee/                                # commercial licence; phase 2
├── tests/
│   ├── e2e/                           # real agents × OS matrix, scripted tasks
│   ├── conformance/<category>/        # one directory per probe category 1-12
│   ├── bypass-corpus/                 # public regression cases (data files)
│   └── fuzz/fuzz_targets/{canon.rs, http1.rs, h2.rs, pktline.rs, jsonrpc.rs, socks5.rs}
├── eval/{agentdojo_shim, agentdyn, swebench_ab, tbench_ab, escapebench}/
├── packaging/{homebrew/, notarize.sh, nfpm.yaml, cosign/, sbom/}
└── docs/{threat-model.md, policy-reference.md, deployment/}
```

### Crate-to-note map

| Crate | Specified in | First milestone |
|---|---|---|
| `broker-cli`, `brokerd` | [[Broker CLI and Daemon]] | [[M0 Contained Run]] |
| `launcher` | [[Sandbox Launcher]] | M0 |
| `netguard` | [[Netguard Ingress]], [[Hostname Canonicaliser]], [[Broker DNS Resolver]] | M0 |
| `tls` | [[TLS Termination and Per-Session CA]] | [[M1 Secrets Outside]] |
| `l7` | [[Git Smart-HTTP Adapter]], [[GitHub API Adapter]], [[Registry and LLM API Adapters]] | M1 |
| `creds` | [[Credential Injector and Issuers]] | M1 |
| `policy` | [[Policy Engine and Entity Builder]], [[Broker Cedar Schema]], [[Native Config Exporters]] | M0 (host allowlist), full at [[M2 Policy Audit and Learn]] |
| `audit` | [[Audit Recorder and Event Schema]] | M0 (deny log), full at M2 |
| `learn` | [[Policy Learning Loop]] | M2 |
| `grant` | [[Internal Grant JWT]] | [[M3 CI Identity and MCP]] |
| `mcpguard` | [[MCP Guard]] | M3 |
| `ee/` | [[Control Plane and Policy Bundles]] | phase 2 ([[MVP Plan]]) |

### Layout rules (Proposal)

1. **Licence boundary.** Everything outside `ee/` is Apache-2.0; `ee/` carries its own licence file and no crate outside `ee/` may depend on it.
2. **Trait seams.** Crates meet only at the four traits in [[Core Trait Contracts]] (`SandboxBackend`, `ProtocolAdapter`, `CredentialIssuer`, `Recorder`) plus plain data types; no crate reaches into another's internals.
3. **Secrets confinement.** Only `creds` holds secret material, in `Zeroizing` buffers; `audit` stores credential IDs, never values ([[I1 No Secrets in the Sandbox]]).
4. **Tests beside parsers.** Every parser module (`canon.rs`, `http1.rs`, `h2.rs`, `pktline.rs`, `socks5.rs`, MCP JSON-RPC) has a matching fuzz target in `tests/fuzz` and property tests in the crate ([[L1 Conformance Suite]]).
5. **Public corpus as data.** `tests/bypass-corpus` holds data files, not code, so it can be published unchanged with the product.
6. **Eval harnesses separate.** `eval/` holds benchmark shims and A/B drivers ([[Evaluation Harness]]); they never ship in release artifacts.

## How it connects

- part-of:: [[CLAUDE]]
- depends-on:: [[Tech Stack]]
- depends-on:: [[Core Trait Contracts]]
- implements:: [[Broker CLI and Daemon]]
- implements:: [[Sandbox Launcher]]
- implements:: [[Netguard Ingress]]
- implements:: [[TLS Termination and Per-Session CA]]
- implements:: [[Credential Injector and Issuers]]
- implements:: [[Policy Engine and Entity Builder]]
- implements:: [[Audit Recorder and Event Schema]]
- implements:: [[MCP Guard]]
- implements:: [[Internal Grant JWT]]
- decided-by:: [[ADR-014 Apache-2.0 Endpoint with Commercial ee]]
- evaluated-by:: [[L1 Conformance Suite]]
- evaluated-by:: [[Evaluation Harness]]

## Implications for the build

- Create the full crate skeleton in [[M0 Contained Run]] even for crates that stay empty until later milestones, so dependency direction is fixed early.
- The `tests/conformance` directories are numbered by probe category from [[Conformance Probe Matrix]]; a milestone is not done until its categories have probes.
- Add a CI check that fails if any crate outside `ee/` depends on `ee/`, and one that fails if the string form of any canary secret appears in `audit` output.

## Open questions

- Whether `grant` needs to exist before M3 (it is only used across hosts; laptop mode keeps grants as Cedar entities per [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]).
- Whether `aider` joins `profiles/` (in research note 05's variant only).

## Sources

- Report: "Repository layout" tree and licence line.
- Research note 05 section 5.1 (variant tree).
- [[CLAUDE]] section 7 (code/ is the repository root).

## Build log

- 2026-09-24: created `code/` with the twelve crates (`tls` holds only the SNI peek, and `l7`, `creds`, `grant`, `learn`, `mcpguard` are placeholders until their milestones), `profiles/*.toml` (embedded into brokerd), `tests/conformance` (a workspace crate with the `conformance-probe` binary and the harness), `tests/conformance/NN-*/` category directories, `tests/bypass-corpus/hosts.toml`, `tests/fuzz` (cargo-fuzz, outside the workspace), `tests/e2e/fix_failing_test.sh`, `packaging/apparmor/broker-bwrap`, `docs/threat-model.md`, `docs/policy-reference.md`. CI lives at the repository root (`.github/workflows/ci.yml`) because the vault and `code/` share one git repository.
- 2026-09-24 (M1): `crates/tls/src/{session_ca,trust_bundle,upstream}.rs`; `crates/creds/src/{sentinel,foreign,secrets,session}.rs`, `issuers/{mod,github_app}.rs`; `crates/l7/src/{head,filter,classify}.rs`, `git/{pktline,receive_pack,pack}.rs`; `crates/policy/src/{l7,repo,glob}.rs`; `crates/brokerd/src/{l7_pipeline,upstream,rewind,session_l7,session_util}.rs`; `profiles/claude-code-apikey.toml`; `tests/conformance/src/m1.rs` and `tests/m1_{secrets,git,redirect_fronting}.rs`; fuzz targets `pktline`, `pack`, `delta`, `filter`, `remote_url`, `foreign`.
