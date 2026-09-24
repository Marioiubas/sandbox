---
title: "Glossary"
aliases: ["Terms"]
type: meta
section: meta
tags: [sandbox/meta, meta]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Every term of art (ocap, confused deputy, lethal trifecta, sentinel, SymCC, Txn-Token, pkt-line, TB1-TB7, A1-A6, control codes...) with a one-line definition and a link to its note."
related: ["[[Object Capabilities]]", "[[Lethal Trifecta]]", "[[Sentinel Swap Pattern]]", "[[SymCC CI Gates]]", "[[Trust Boundaries]]", "[[Adversary Classes]]", "[[Threat Model Overview]]", "[[Just-in-Time Credential Minting]]", "[[Cedar]]", "[[Git Smart-HTTP Adapter]]"]
sources: []
---

# Glossary

One line per term; follow the link for the full note. Terms merged into a larger note are listed under that note's aliases too.

## Threat-model vocabulary

| Term | Definition | Note |
|---|---|---|
| A1-A6 | Adversary classes: A1 remote injection author, A2 malicious or compromised publisher, A3 misbehaving model, A4 malicious operator, A5 over-privileged user who disables controls, A6 opportunistic scanner. | [[Adversary Classes]] |
| TB1-TB7 | Trust boundaries: human-agent, agent process-OS, sandbox-broker, broker-external services, workspace-agent context, tool supply chain-registry, CI trigger-CI credentials. | [[Trust Boundaries]] |
| ISO | Control code: process isolation. | [[Threat Model Overview]] |
| FS | Control code: filesystem capability boundary (explicit read/write grants; agent cannot write its own config, hooks or rc files). | [[Filesystem Control and Rollback]] |
| EGRESS | Control code: deny-by-default egress through the broker with broker-owned DNS and canonicalised matching. | [[Topology-Forced Egress]] |
| CRED-OUT | Control code: credentials held outside the sandbox; the broker attaches auth per request. | [[I1 No Secrets in the Sandbox]] |
| TASK-TOK | Control code: task-scoped, short-lived, least-privilege tokens. | [[Just-in-Time Credential Minting]] |
| PIN | Control code: content-hash pinning of tool manifests and config; re-approval on change. | [[MCP Guard]] |
| AUDIT | Control code: tamper-evident audit of every decision, held outside the sandbox. | [[I9 Hash-Chained Audit Outside the Sandbox]] |
| HITL | Control code: human approval for irreversible or high-impact actions. | [[Fatigue-Resistant Approval Interfaces]] |
| Root-cause categories (a)-(g) | (a) untrusted input steering tools, (b) over-broad standing credentials, (c) unrestricted egress, (d) missing filesystem boundary, (e) unpinned tools or supply chain, (f) parser flaw in the enforcement layer, (g) approval fatigue or gate design. | [[Threat Model Overview]] |
| Lethal trifecta | Private data plus untrusted content plus external communication in one session. | [[Lethal Trifecta]] |
| Rule of Two | Meta's rule: a session may hold at most two of untrusted input [A], sensitive access [B], state change or external communication [C]. | [[Agents Rule of Two]] |
| Ambient authority | Credentials and access an agent inherits from the developer's environment rather than being granted per task. | [[Problem Statement]] |
| Allowed-domain abuse | Exfiltration through an allowlisted host using a credential the attacker supplied. | [[Claude Cowork Allowed-Domain Abuse]] |
| Parser differential | Two components (filter and resolver) parse the same input differently, e.g. a NUL byte in a hostname. | [[sandbox-runtime SOCKS NUL-Byte Bypass]] |
| Rug pull | An approved tool or MCP server changes its behaviour or description after approval. | [[postmark-mcp Rug Pull]] |
| Tool poisoning, shadowing | Hidden instructions in tool descriptions; one server's description overriding another server's tool behaviour. | [[MCP Guard]] |
| OWASP ASI01-ASI10 | OWASP Top 10 for Agentic Applications (Dec 2025). | [[Threat Model Overview]] |
| MITRE ATLAS AML.T0080-T0086 | Agent-specific ATLAS techniques added Oct 2025 (context poisoning, modify agent config, credentials from agent config, exfiltration via tool invocation...). | [[Threat Model Overview]] |
| Non-goals | What the product explicitly does not promise (misuse inside granted scope, text-only manipulation, host-kernel zero-days in the standard tier, operator abuse). | [[Threat Model Non-Goals]] |

## Research vocabulary

| Term | Definition | Note |
|---|---|---|
| Object capability (ocap) | An unforgeable reference that both designates a resource and carries the authority to use it. | [[Object Capabilities]] |
| POLA | Principle of least authority. | [[Object Capabilities]] |
| Confused deputy | A privileged program tricked into misusing its authority on behalf of a less privileged caller; a named attack on MCP proxies. | [[Object Capabilities]] |
| Caretaker, membrane | Miller's revocable forwarders; a membrane wraps a whole object graph so access can be revoked at once. | [[Revocable Sub-Agent Delegation]] |
| Macaroon | Chained-HMAC bearer token whose holders can append (never remove) caveats. | [[Macaroons and Biscuit]] |
| Biscuit | Public-key-signed token with offline attenuation and Datalog authorization caveats. | [[Macaroons and Biscuit]] |
| IFC | Information-flow control: labels for confidentiality and integrity propagate with data and gate sinks. | [[Information Flow Control]] |
| Label creep | Over-conservative label propagation that taints everything and destroys utility. | [[Information Flow Control]] |
| Typed quarantine | Untrusted tool output converted into narrow typed values; free text auto-labelled untrusted. | [[Information Flow Control]] |
| Selective hiding | FIDES technique: high-label results stored in variables, not the model's context. | [[FIDES]] |
| Dual LLM | Privileged LLM with tools plus quarantined LLM that reads untrusted content, mediated by a non-LLM controller. | [[Design Patterns for Securing LLM Agents]] |
| P-LLM, Q-LLM | Privileged and quarantined LLMs in the Dual LLM and CaMeL designs. | [[CaMeL]] |
| Execution modes | Design-pattern modes (Action-Selector, Plan-Then-Execute, Map-Reduce, Dual LLM, Code-Then-Execute, Context-Minimization) mapped to capability profiles. | [[Design Patterns for Securing LLM Agents]] |
| Branch steering | Attack that makes a valid, pre-approved plan branch fire by manipulating what the agent observes. | [[Branch-Steering Resistance]] |
| Monotonic confinement | Progent's rule: narrowing is automatic, widening needs approval, decided by an SMT solver. | [[Progent]] |
| In-band vs out-of-band defense | Defenses inside the model (prompting, fine-tuning, detectors) versus deterministic enforcement outside it. | [[The Attacker Moves Second]] |
| Adaptive attack | An attack optimised against the specific defense (gradient, RL, search, human-guided). | [[The Attacker Moves Second]] |
| ASR, ASR@k | Attack success rate; success within k adaptive attempts. | [[L2 Injection Benchmarks]] |
| Benign utility, utility under attack | Task success without attacks; task success while under attack. | [[AgentDyn]] |
| AgentDojo, AgentDyn | The reference injection benchmark (97 tasks) and its open-ended 2026 successor (60 tasks, 560 cases). | [[AgentDyn]] |
| SandboxEscapeBench | UK AISI container-breakout benchmark, eval layer L6. | [[SandboxEscapeBench]] |

## Isolation vocabulary

| Term | Definition | Note |
|---|---|---|
| Standard tier, hard tier | Default OS process sandbox versus opt-in microVM per session. | [[Two-Tier Isolation Design]] |
| Seatbelt, SBPL, sandbox-exec | macOS kernel sandbox, its profile language and its (deprecated) CLI. | [[Seatbelt]] |
| bubblewrap (bwrap) | Unprivileged namespace sandbox used by srt and Codex on Linux. | [[bubblewrap]] |
| seccomp-bpf | Syscall filter; here it blocks new AF_UNIX sockets, ptrace, bpf, raw sockets and keyctl. | [[seccomp-bpf]] |
| Landlock ABI | Versioned feature set of the Landlock LSM (ABI 4 adds TCP port rules; ABI 9 on Linux 7.1). | [[Landlock]] |
| Systrap | gVisor's default platform using seccomp traps; works inside VMs without nested virtualization. | [[gVisor]] |
| vminitd | Apple containerization's in-VM agent speaking gRPC over vsock. | [[Apple Virtualization Framework]] |
| vsock | Host-guest socket transport; the only egress device in the hard tier. | [[Topology-Forced Egress]] |
| Topology-forced egress | Making the broker the only reachable network peer (no NIC, loopback-only, vsock) instead of trusting `HTTP_PROXY`. | [[Topology-Forced Egress]] |
| CoW rollback, clone mode | Agent writes into a copy-on-write layer or private clone; changes reach the repo only via reviewed merge. | [[Filesystem Control and Rollback]] |
| WASI, wasi:http | WebAssembly system interface; HTTP is a host-implemented capability import. | [[Wasmtime and WASI]] |

## Broker vocabulary

| Term | Definition | Note |
|---|---|---|
| Broker, brokerd | The product: CLI plus per-user daemon holding policy, credentials and audit outside the sandbox. | [[Broker CLI and Daemon]] |
| Control API, ctl.sock | JSON-RPC 2.0 over a per-user Unix socket (0600, peer-cred checked), unreachable from the sandbox. | [[Broker CLI and Daemon]] |
| Data plane, control plane, learning plane | Endpoint enforcement; fleet policy/identity/audit (ee/); trace-to-policy mining. | [[Architecture Overview]] |
| Gateway mode | The broker as upstream proxy for remote sandboxes (E2B, Vercel, Docker sbx, Cloudflare). | [[Architecture Overview]] |
| Ingress modes | HTTP CONNECT, SOCKS5 and transparent listeners inside the sandbox netns, all bridged to the broker. | [[Netguard Ingress]] |
| UDS bridge | Unix-domain-socket path from an empty network namespace to the broker. | [[Netguard Ingress]] |
| Canonicaliser | The single hostname/path normaliser that rejects NUL, CR/LF, `%`, trailing dots, mixed IDNA and IP-literal tricks. | [[Hostname Canonicaliser]] |
| IMDS, 169.254.169.254 | Cloud metadata endpoint; denied unless explicitly granted. | [[Hostname Canonicaliser]] |
| DoH, DoT | DNS over HTTPS/TLS; blocked by name so the broker stays the only resolver. | [[Broker DNS Resolver]] |
| L4 fast path, L7 path | Splice after SNI peek versus terminate, parse, authorize, inject and re-originate TLS. | [[TLS Termination and Per-Session CA]] |
| Per-session CA | Just-in-time CA created at session start, used to mint leaf certs for L7 hosts, destroyed at session end. | [[TLS Termination and Per-Session CA]] |
| SNI, domain fronting | TLS server name; reaching another vhost by making SNI and Host disagree (blocked by CONNECT = SNI = Host). | [[TLS Termination and Per-Session CA]] |
| ECH | Encrypted ClientHello; would defeat SNI peeking; a watch item. | [[Risk Register]] |
| Protocol adapter | Parser that turns a request into one or more Cedar requests (all must allow). | [[Core Trait Contracts]] |
| pkt-line | Git smart-HTTP framing; parsed to extract repo, ref updates and force pushes. | [[Git Smart-HTTP Adapter]] |
| API verb | Semantic operation such as `pr.create`, `pr.merge`, `issue.comment`, `contents.write`. | [[GitHub API Adapter]] |
| Sentinel | Per-session placeholder value visible in the sandbox, swapped for a real secret only on permitted egress. | [[Sentinel Swap Pattern]] |
| Minting | Issuing a fresh short-lived, audience-bound credential per task scope just before forwarding. | [[Just-in-Time Credential Minting]] |
| Scope digest | Cache key for a minted token: the hash of the grant scope it was minted for. | [[Credential Injector and Issuers]] |
| SigV4 re-signing | Recomputing an AWS request signature with the broker-held key. | [[Credential Injector and Issuers]] |
| Foreign credential | Any credential in a request that the broker did not issue; stripped or rejected. | [[I7 Reject Foreign Credentials]] |
| MCP guard | Component that pins, sandboxes and authorizes MCP servers as separate principals. | [[MCP Guard]] |
| Hash chain | Each audit row stores H(previous hash, canonical event), making tampering detectable. | [[Audit Recorder and Event Schema]] |
| OCSF, OTel | Open Cybersecurity Schema Framework and OpenTelemetry, the audit export formats. | [[Audit Recorder and Event Schema]] |
| Policy bundle | Signed tarball of schema, policies, entities, broker.toml and manifest distributed to endpoints. | [[Control Plane and Policy Bundles]] |
| Internal grant | Txn-Token-shaped, DPoP-bound JWT carrying task scope when sandbox and broker are on different hosts. | [[Internal Grant JWT]] |
| SandboxBackend, ProtocolAdapter, CredentialIssuer, Recorder | The four core Rust traits. | [[Core Trait Contracts]] |
| Zeroizing | Rust wrapper that wipes secret memory on drop; used for minted credentials. | [[Core Trait Contracts]] |

## Policy vocabulary

| Term | Definition | Note |
|---|---|---|
| Cedar | Lean-verified authorization language: default deny, forbid wins, order-independent. | [[Cedar]] |
| Principal, action, resource, context | Cedar's request model; here principal = Task. | [[Broker Cedar Schema]] |
| Grants as entities | Grants stored as Cedar entity data so expiry and revocation need no policy recompile. | [[Broker Cedar Schema]] |
| Trifecta labels | Session context `untrusted_input`, `sensitive_read`, `external_effect` computed by the broker. | [[Trifecta Session Labels]] |
| Sequence rule | Ordered-call constraint (Invariant's `->`) kept as a broker-side automaton and exposed as Cedar context. | [[Trifecta Session Labels]] |
| SymCC | `cedar-policy-symcc`, Cedar's sound and complete symbolic analyzer on cvc5. | [[SymCC CI Gates]] |
| Narrowing, widening | A policy change implied by the old policy (safe, automatic) versus one that grants more (needs approval). | [[SymCC CI Gates]] |
| Org ceiling | Org-level policy (and deny list) that every learned or repo policy must be implied by. | [[Policy Miner Safeguards]] |
| Record, shadow, enforce | Learning-loop modes: allow-and-log, log would-deny, then deny. | [[Policy Learning Loop]] |
| Record-then-restrict | Deriving least-privilege policy from observed runs, then enforcing it. | [[Policy Learning Loop]] |
| broker.toml | Human-facing TOML policy layer that compiles to Cedar. | [[broker.toml Human Policy Layer]] |
| Compile-to-native | Exporting the one policy to Claude Code, Codex, Cursor and OpenShell configs. | [[Native Config Exporters]] |

## Identity vocabulary

| Term | Definition | Note |
|---|---|---|
| Installation token | GitHub App token limited to selected repos and permissions, 1-hour TTL. | [[GitHub App Installation Tokens]] |
| Session policy, SourceIdentity | STS inline policy intersected with the role; identity string visible in CloudTrail. | [[AWS STS Session Policies]] |
| Credential Access Boundary | GCP downscoping rules, Cloud Storage only. | [[GCP Credential Access Boundaries]] |
| Token exchange, act claim | RFC 8693 exchange; nested `act` expresses delegation chains. | [[RFC 8693 Token Exchange]] |
| RAR, authorization_details | RFC 9396 typed authorization objects (actions, locations...). | [[RFC 9396 Rich Authorization Requests]] |
| Resource indicator | RFC 8707 `resource` parameter pinning token audience; mandatory in MCP. | [[MCP Authorization Spec]] |
| DPoP, cnf.jkt | Proof-of-possession binding a token to a key thumbprint (RFC 9449); mTLS binding is RFC 8705. | [[DPoP and mTLS-Bound Tokens]] |
| Transaction token, Txn-Token, tctx | Minutes-long JWT with immutable transaction context propagated inside a trust domain. | [[Transaction Tokens and Agent Auth Drafts]] |
| AAuth, WIMSE, AIMS | Unsettled IETF agent-identity drafts (signed requests; workload identity for AI agents). | [[Transaction Tokens and Agent Auth Drafts]] |
| ID-JAG, XAA, SEP-990 | Okta's Identity Assertion JWT Authorization Grant ("Cross App Access"), the MCP enterprise-managed authorization extension. | [[Okta Cross App Access]] |
| OBO, blueprint | Entra Agent ID on-behalf-of flow; the blueprint app obtains T1 for the agent identity. | [[Entra Agent ID]] |
| Token passthrough ban | MCP servers must not accept or transit tokens not issued for them. | [[MCP Authorization Spec]] |
| stdio exemption | MCP spec text telling stdio servers to read credentials from the environment. | [[MCP Authorization Spec]] |
| CIMD | Client ID Metadata Documents, preferred over dynamic client registration in MCP 2026-07-28. | [[MCP Authorization Spec]] |
| insufficient_scope step-up | MCP 403 challenge the broker treats as the approval hook. | [[MCP Authorization Spec]] |

## Build and evaluation vocabulary

| Term | Definition | Note |
|---|---|---|
| I1-I9 | The nine architecture invariants. | [[MOC Architecture]] |
| M0-M4 | The five MVP milestones. | [[MVP Plan]] |
| L1-L6 | Evaluation layers: conformance, injection benchmarks, real-work utility, product metrics, formal gates, boundary regression. | [[Evaluation Harness]] |
| Conformance probe | Deterministic, non-LLM script asserting a specific deny or allow. | [[Conformance Probe Matrix]] |
| Bypass corpus | Public regression set of egress-bypass inputs (NUL, CRLF, IDNA, IP literals...). | [[L1 Conformance Suite]] |
| HTTP Garden | Differential fuzzer for HTTP parsing across servers and gateways. | [[L1 Conformance Suite]] |
| False-deny rate | Denied actions that were necessary for the task, per action and per task. | [[Evaluation Harness]] |
| Model complied, broker blocked | Count of attacks the model attempted that the broker stopped; the defense-in-depth metric. | [[Evaluation Harness]] |
| Proposal | Reading convention: a design recommendation, not a sourced fact. | [[Vault Conventions]] |
| ee/ | Commercially licensed control-plane directory beside the Apache-2.0 endpoint. | [[ADR-014 Apache-2.0 Endpoint with Commercial ee]] |
