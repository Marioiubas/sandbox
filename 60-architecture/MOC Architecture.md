---
title: "MOC Architecture"
aliases: []
type: moc
section: architecture
tags: [sandbox/architecture, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "One Rust binary across three planes: the nine invariants, every component and interface, and the request/session data flow."
related: ["[[Architecture Overview]]", "[[Request and Session Lifecycle]]", "[[I1 No Secrets in the Sandbox]]", "[[I2 Fail-Closed Launch]]", "[[I3 Probabilistic Components Only Narrow]]", "[[I4 Repo Policy Only Narrows]]", "[[I5 Config Outside Writable Mounts]]", "[[I6 Single Canonicaliser]]", "[[I7 Reject Foreign Credentials]]", "[[I8 No Flag Disables Isolation]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[Broker CLI and Daemon]]", "[[Sandbox Launcher]]", "[[Netguard Ingress]]", "[[Hostname Canonicaliser]]", "[[Broker DNS Resolver]]", "[[TLS Termination and Per-Session CA]]", "[[Git Smart-HTTP Adapter]]", "[[GitHub API Adapter]]", "[[Registry and LLM API Adapters]]", "[[MCP Guard]]", "[[Credential Injector and Issuers]]", "[[Policy Engine and Entity Builder]]", "[[Audit Recorder and Event Schema]]", "[[Control Plane and Policy Bundles]]", "[[Core Trait Contracts]]", "[[Internal Grant JWT]]", "[[MOC Policy]]", "[[MOC Build]]", "[[MOC Primitives]]", "[[MOC Identity]]", "[[Repository Layout]]"]
sources: []
---

# MOC Architecture

> One Rust binary across three planes: the nine invariants, every component and interface, and the request/session data flow.

One Rust binary across three planes. The **endpoint data plane** (broker CLI plus the per-user `brokerd` daemon) launches the agent in an OS sandbox whose only route out is the broker's own proxy; the proxy canonicalises, resolves, optionally terminates TLS, classifies each request through a protocol adapter into Cedar requests, and only if all allow does it mint and attach a credential and append a hash-chained audit event. The **control plane** (commercial `ee/`) distributes signed policy bundles, binds identity and ingests audit. The **learning plane** turns audit-mode traces into reviewable Cedar diffs ([[MOC Policy]]).

Start with [[Architecture Overview]], then [[Request and Session Lifecycle]], then the invariants, then [[Core Trait Contracts]].

## The nine invariants (Proposal)

Treat these as testable. A pull request that weakens one of them is a security regression and needs an ADR (see [[CLAUDE]]).

| # | Invariant | Motivating evidence |
|---|---|---|
| I1 | [[I1 No Secrets in the Sandbox]] | No secret material is ever present in the sandbox (env, files, argv, /proc, response bodies); only per-session sentinels that are useless off-host. |
| I2 | [[I2 Fail-Closed Launch]] | Launch fails closed if any isolation layer or the proxy cannot start; no convenience mode mounts docker.sock or host paths. |
| I3 | [[I3 Probabilistic Components Only Narrow]] | Probabilistic components (LLM policy drafts, explainers, detectors) may only narrow authority, never widen it; an LLM may explain a diff but never merge it. |
| I4 | [[I4 Repo Policy Only Narrows]] | Repository-supplied policy can only narrow user and org policy; widening requires user or org scope, proved by SymCC implication gates. |
| I5 | [[I5 Config Outside Writable Mounts]] | Policy, agent config, hooks, MCP manifests and the broker binary sit outside every writable mount and are loaded only after content-hash approval. |
| I6 | [[I6 Single Canonicaliser]] | One canonicaliser for every hostname and path; match on the canonical name and on the broker-resolved address; reject what cannot be canonicalised. |
| I7 | [[I7 Reject Foreign Credentials]] | The proxy strips every client-supplied Authorization, x-api-key, cookie and Proxy-Authorization header and rejects any credential it did not issue. |
| I8 | [[I8 No Flag Disables Isolation]] | No flag (--yolo, auto-approve, dangerously-skip-permissions) can disable isolation, egress or brokering; flags only relax in-sandbox prompts. |
| I9 | [[I9 Hash-Chained Audit Outside the Sandbox]] | Every decision is logged outside the sandbox, hash-chained, and attributed to user, agent, task and session; the model's self-reports are never evidence. |

## Overview and data flow

- [[Architecture Overview]] — One Rust binary across three planes (control plane, endpoint data plane, learning plane), the component diagram, and the four deployment modes: laptop daemon, CI, Kubernetes (phase 2) and remote-sandbox gateway (phase 2).
- [[Request and Session Lifecycle]] — The six-step life of a session and its requests: session.start resolves user, agent hash and repo into a Task entity; CA, sentinels and sandbox rules are compiled; each request is canonicalised, resolved, optionally terminated and classified; all Cedar requests must allow before minting and attach; response filter and audit append; teardown destroys the CA and cached tokens.

## Invariants

- [[I1 No Secrets in the Sandbox]] — No secret material is ever present in the sandbox (env, files, argv, /proc, response bodies); only per-session sentinels that are useless off-host.
- [[I2 Fail-Closed Launch]] — Launch fails closed if any isolation layer or the proxy cannot start; no convenience mode mounts docker.sock or host paths.
- [[I3 Probabilistic Components Only Narrow]] — Probabilistic components (LLM policy drafts, explainers, detectors) may only narrow authority, never widen it; an LLM may explain a diff but never merge it.
- [[I4 Repo Policy Only Narrows]] — Repository-supplied policy can only narrow user and org policy; widening requires user or org scope, proved by SymCC implication gates.
- [[I5 Config Outside Writable Mounts]] — Policy, agent config, hooks, MCP manifests and the broker binary sit outside every writable mount and are loaded only after content-hash approval.
- [[I6 Single Canonicaliser]] — One canonicaliser for every hostname and path; match on the canonical name and on the broker-resolved address; reject what cannot be canonicalised.
- [[I7 Reject Foreign Credentials]] — The proxy strips every client-supplied Authorization, x-api-key, cookie and Proxy-Authorization header and rejects any credential it did not issue.
- [[I8 No Flag Disables Isolation]] — No flag (--yolo, auto-approve, dangerously-skip-permissions) can disable isolation, egress or brokering; flags only relax in-sandbox prompts.
- [[I9 Hash-Chained Audit Outside the Sandbox]] — Every decision is logged outside the sandbox, hash-chained, and attributed to user, agent, task and session; the model's self-reports are never evidence.

## Endpoint: session and isolation

- [[Broker CLI and Daemon]] — broker-cli (run, init, learn, suggest, why, audit, login, mcp wrap/connect, doctor) and brokerd, the per-user daemon: session manager, ctl.sock JSON-RPC control API (mode 0600, peer credentials checked, unreachable from any sandbox), bundle sync and keychain access.
- [[Sandbox Launcher]] — The launcher crate: SandboxBackend implementations (macos-seatbelt, linux-native, container, vm; remote later) that compile Cedar fs.* grants into SBPL or bwrap/Landlock/seccomp rules, probe the platform, write the CA bundle and sentinel env, and fail closed.

## Endpoint: network path

The order a request traverses.

- [[Netguard Ingress]] — The only route out and its listeners: the sandbox-broker channel (UDS from an empty netns, loopback port with sentinel Proxy-Authorization on macOS, vsock in VMs) feeding HTTP CONNECT, SOCKS5 and transparent (nftables redirect, original-dst plus SNI) ingress into one canonicaliser.
- [[Hostname Canonicaliser]] — The single canonicaliser: reject NUL, CR/LF and % in hostnames, trailing dots, mixed IDNA, IP-literal encodings, link-local, metadata (169.254.169.254) and RFC 1918 unless granted; match on canonical name and broker-resolved address; fuzzed and differential-tested.
- [[Broker DNS Resolver]] — Broker-owned name resolution: no UDP/53 or ICMP from the sandbox, names resolved inside the proxy or by a namespace stub forwarding only to the policy resolver, which answers only allowlisted names and blocks DoH endpoints; IP-literal CONNECTs denied by default.
- [[TLS Termination and Per-Session CA]] — Per-connection path choice: the L4 fast path splices bytes after an SNI peek when no credential or L7 rule applies; the L7 path terminates with a just-in-time per-session CA leaf, enforces CONNECT=SNI=Host, parses h1/h2, authorizes, strips client credentials, injects, re-originates verified TLS and filters responses; CA bundle env vars; QUIC and SNI-less protocols blocked.

## Endpoint: protocol adapters (the moat)

- [[Git Smart-HTTP Adapter]] — Protocol adapter that rewrites SSH remotes to HTTPS, denies port 22, parses info/refs and git-receive-pack pkt-lines into per-ref git.push requests (repo, ref, force), enforces rules such as 'agent/* on the task repo, never force', attaches a repo-scoped installation token and signs commits broker-side.
- [[GitHub API Adapter]] — Maps GitHub REST method+path or the GraphQL operation to verbs (pr.create, pr.merge, issue.comment, contents.write) so 'open a PR but never merge' is one rule, and reports repository visibility to set the sensitive_read label.
- [[Registry and LLM API Adapters]] — Package-registry adapters (npm, PyPI, crates, Go proxy read-only via GET/HEAD; publish denied unless granted; read-only tokens for private registries) and LLM API adapters (Anthropic, OpenAI, Gemini keys injected, base URL fixed by the broker, model and spend logged); gRPC and WebSocket handling.
- [[MCP Guard]] — mcpguard: pinned MCP servers defined only in user/org config, reached by name via broker mcp connect, launched by brokerd in their own sandbox as separate McpServer principals with sentinel env; tools/list hashed and any change revokes grants; tools/call authorized with arguments; the broker acts as full OAuth client toward remote servers.

## Endpoint: decision, credentials and audit

- [[Policy Engine and Entity Builder]] — The policy crate at request time: builds Cedar entities and context from parsed traffic (Task, Host, PathPrefix, Repo, Credential, McpServer; trifecta labels; sequence-automaton state) and authorizes every derived request in-process with cedar-policy; all must allow.
- [[Credential Injector and Issuers]] — The creds crate: sentinel store plus CredentialIssuer implementations (static, github_app, aws_sts, oauth_exchange, vault) that mint or reuse per scope digest, attach headers or re-sign SigV4, keep material only in broker memory (Zeroizing) and hold roots in Keychain or libsecret.
- [[Audit Recorder and Event Schema]] — The audit crate: SQLite WAL hash-chained decision log (each hash covers the previous hash concatenated with the canonical JSON event) and the per-request OTel/OCSF event carrying user, agent and binary hash, task, session, method, redacted URL, adapter verb, Cedar decision with policy IDs and mode, credential ID (never value), status, bytes and chain hash.

## Control plane

- [[Control Plane and Policy Bundles]] — The commercial ee/ control plane (policy repo -> compiler + SymCC gates -> signed bundles; OIDC/SCIM; issuer config; audit ingest to SIEM; review UI; fleet inventory) and the bundle format (schema.cedarschema, policies/*.cedar, entities.json, broker.toml, manifest signed with Ed25519 or cosign, max age offline).

## Interfaces

- [[Core Trait Contracts]] — The four Rust traits where crates meet, with SandboxSpec: SandboxBackend (probe, launch, must fail closed), ProtocolAdapter (claims, classify into Cedar requests that must all allow), CredentialIssuer (mint, attach; material never leaves broker memory) and Recorder (append returns chain hash).
- [[Internal Grant JWT]] — When sandbox and broker are on different hosts (CI sidecar, gateway mode) the grant travels as a Txn-Token-shaped, DPoP-bound JWT (iss, aud, sub, nested act chain, txn, scope, tctx with repo, branch_prefix, allowed method/host/path and labels, 15-minute exp, cnf.jkt); on one laptop it stays Cedar entity data.

## How this section connects

- The isolation primitives behind the launcher are in [[MOC Primitives]]; the credential standards behind the injector in [[MOC Identity]]; the policy language, schema and learning loop in [[MOC Policy]].
- Every invariant traces back to incidents in [[MOC Threat Model]].
- Crate boundaries and directories are fixed in [[Repository Layout]]; build order in [[MOC Build]]; recorded choices in [[MOC Decisions]].
