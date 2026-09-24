---
title: "Broker CLI and Daemon"
aliases: ["brokerd", "broker-cli", "Control API", "ctl.sock"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/isolation, topic/approval, platform/macos, platform/linux, boundary/tb1, boundary/tb3, invariant/i2, invariant/i8, milestone/m0]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "broker-cli (run, init, learn, suggest, why, audit, login, mcp wrap/connect, doctor) and brokerd, the per-user daemon: session manager, ctl.sock JSON-RPC control API (mode 0600, peer credentials checked, unreachable from any sandbox), bundle sync and keychain access."
related: ["[[Request and Session Lifecycle]]", "[[Sandbox Launcher]]", "[[Control Plane and Policy Bundles]]", "[[seccomp-bpf]]", "[[Seatbelt]]", "[[M0 Contained Run]]", "[[Policy Learning Loop]]", "[[Repository Layout]]", "[[I8 No Flag Disables Isolation]]", "[[I2 Fail-Closed Launch]]", "[[I5 Config Outside Writable Mounts]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[Netguard Ingress]]", "[[MCP Guard]]", "[[Credential Injector and Issuers]]", "[[Audit Recorder and Event Schema]]", "[[Policy Engine and Entity Builder]]", "[[broker.toml Human Policy Layer]]", "[[Okta Cross App Access]]", "[[Entra Agent ID]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[Core Trait Contracts]]", "[[Architecture Overview]]", "[[M1 Secrets Outside]]", "[[M2 Policy Audit and Learn]]", "[[M3 CI Identity and MCP]]", "[[Tech Stack]]", "[[L4 Product Metrics]]"]
sources: ["https://github.com/anthropic-experimental/sandbox-runtime", "https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md", "https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/"]
milestone: M0
code: ["code/crates/broker-cli/src/main.rs", "code/crates/broker-cli/src/cmd/", "code/crates/brokerd/src/server.rs", "code/crates/brokerd/src/session.rs", "code/crates/brokerd/src/proto.rs", "code/crates/brokerd/src/profiles.rs", "code/crates/brokerd/src/session_l7.rs", "code/crates/brokerd/src/session_util.rs", "code/crates/broker-cli/src/cmd/why.rs"]
---

# Broker CLI and Daemon

> broker-cli (run, init, learn, suggest, why, audit, login, mcp wrap/connect, doctor) and brokerd, the per-user daemon: session manager, ctl.sock JSON-RPC control API (mode 0600, peer credentials checked, unreachable from any sandbox), bundle sync and keychain access.

## Responsibility

Two crates (`crates/broker-cli`, `crates/brokerd` in [[Repository Layout]]) that form the user-facing edge and the trusted core of the endpoint.

- **`broker` (CLI).** A thin client. It parses commands, talks to `brokerd` over the control socket, renders results (authority diffs, `why` explanations, doctor reports) and, for `run`, attaches the user's terminal to the sandboxed agent. It holds no secrets and makes no policy decisions.
- **`brokerd` (daemon).** One per user: a launchd agent on macOS or a systemd user unit on Linux (laptop deployment row). It owns the session manager, the netguard listeners, the per-session CAs, the sentinel store, the credential issuers, the Cedar engine, the audit recorder, bundle sync with the control plane and access to the OS keychain (Keychain on macOS, libsecret on Linux). In CI it runs in the runner outside the sandbox; in both cases it is the "broker" of [[Architecture Overview]].

**It must never:** be reachable from inside any sandbox; expose a method or flag that disables isolation, egress or brokering ([[I8 No Flag Disables Isolation]]); start an agent before every layer is up ([[I2 Fail-Closed Launch]]); read policy or config from inside a writable mount without content-hash approval ([[I5 Config Outside Writable Mounts]]); write a secret to disk outside the keychain; forward a user's IdP token as-is to any upstream.

## Inputs and outputs

| Input | From | Output | To |
|---|---|---|---|
| CLI commands | human user, CI step | JSON-RPC requests | `brokerd` |
| `session.start` | CLI | `SandboxSpec`, listener config, Task entity | [[Sandbox Launcher]], [[Netguard Ingress]], [[Policy Engine and Entity Builder]] |
| Signed bundles | [[Control Plane and Policy Bundles]] | Active policy set, entities | policy crate |
| OIDC login | Okta/Entra device flow | Cached identity (subject, groups) | Task entity owner |
| Approvals | human via CLI or control plane | approval records | policy, audit |
| Decisions | all crates | audit events | [[Audit Recorder and Event Schema]] |

## CLI surface

The command list is from the report's repository layout and developer-UX section; flags shown are proposals.

| Command | Purpose | Milestone |
|---|---|---|
| `broker run [--profile P] -- <agent> [args]` | Start a session and run the agent in it; agent auto-detected, built-in profile applied | M0 |
| `broker doctor` | Probe backends (Landlock ABI, AppArmor userns gate, VZ availability), print required-layer status and fixes | M0 |
| `broker init` | Write `.broker/broker.toml` and `.broker/policy.cedar` in the repo (narrowing-only, [[I4 Repo Policy Only Narrows]]) | M2 |
| `broker why <request-id>` | Explain a decision from the audit log and determining Cedar policy IDs | M1 |
| `broker audit tail` / `broker audit verify` | Stream events; verify the hash chain | M2 |
| `broker learn -- <agent> -p "fix tests"` | Run in audit mode and record traces ([[Policy Learning Loop]]) | M2 |
| `broker suggest` | Show the mined Cedar diff with evidence and gate results | M2 |
| `broker login` | OIDC device login to Okta or Entra | M3 |
| `broker mcp wrap -- <cmd>` / `broker mcp connect <name>` | Run a stdio MCP server as its own sandboxed principal; stub the agent uses to reach a pinned server by name ([[MCP Guard]]) | M3 |

**Proposal.** There is deliberately no `--no-sandbox`, `--insecure`, `--direct` or `--allow-all` flag, and arguments after `--` are passed to the agent verbatim and never interpreted.

## Control API (ctl.sock)

The control API is JSON-RPC 2.0 over a per-user Unix socket, mode 0600, peer credentials checked. Methods (from the report):

- `session.start {argv, cwd, profile, repo_remote}` → `{session_id, backend, egress_endpoint}`
- `session.stop`
- `grant.request {session_id, action, resource, rationale}` for step-up
- `decision.explain {request_id}`, which backs `broker why`
- `audit.query`
- `learn.start` and `learn.stop`
- `policy.reload`

"The sandbox can never reach this socket. seccomp blocks new `AF_UNIX` sockets and SBPL denies the path." ([[seccomp-bpf]], [[Seatbelt]])

**Example exchange (Proposal; field values illustrative).**

```json
{"jsonrpc":"2.0","id":1,"method":"session.start",
 "params":{"argv":["claude"],"cwd":"/home/dev/web","profile":"default",
           "repo_remote":"https://github.com/acme/web.git"}}

{"jsonrpc":"2.0","id":1,
 "result":{"session_id":"01J9ZK3M5V7X","backend":"linux-native",
           "egress_endpoint":{"uds":"/run/user/1000/broker/s/01J9ZK3M5V7X/data.sock"}}}
```

```json
{"jsonrpc":"2.0","id":7,"method":"grant.request",
 "params":{"session_id":"01J9ZK3M5V7X","action":"git.push",
           "resource":"Broker::Repo::\"github.com/acme/web\"",
           "rationale":"push fix to agent/fix-123"}}

{"jsonrpc":"2.0","id":7,"error":{"code":-32010,"message":"needs_approval",
 "data":{"authority_diff":["+ git.push github.com/acme/web refs/heads/release/*"]}}}
```

Error codes other than JSON-RPC's reserved range are proposals; every error carries a machine-readable reason that the CLI renders.

## Internal design

**Proposal.**

- **Session manager.** A `HashMap<SessionId, Session>` behind an async mutex. `Session` owns: the Task entity and labels, the backend handle, the netguard listener handles, the per-session CA (key in memory only), the sentinel map, the token cache (keyed by scope digest), and the mode (enforce or audit). State machine: `Starting → Running → Stopping → Closed`; any error in `Starting` goes straight to `Closed` with a `launch_refused` audit event.
- **Start sequence** (details in [[Request and Session Lifecycle]]): resolve user from cached OIDC login; hash the agent binary; read the repo remote; load the active bundle plus approved repo policy; build the Task; generate CA and sentinels; start listeners; compile fs grants; `probe()` then `launch()`.
- **Supervisor.** `brokerd` is the parent of the launcher process tree. On `session.stop` or agent exit it kills the tree, destroys the CA, drops cached tokens and flushes the audit log.
- **Bundle sync.** Pull via mTLS with a device certificate; verify the signed manifest; keep last-known-good for offline use up to the bundle's max age; after max age, refuse new sessions (fail closed) with a clear doctor message.
- **Keychain access.** Roots (static API keys, GitHub App private key references, OAuth refresh tokens) are read on demand and zeroised after use; the per-user CA key for laptop mode lives in the OS keychain, never in the system trust store.
- **Approval prompts.** Rare and diff-based: the CLI renders the authority diff produced by the policy crate, not model prose ([[Fatigue-Resistant Approval Interfaces]]).

## State

| State | Where | Lifetime |
|---|---|---|
| Session table, CA keys, sentinels, minted tokens | `brokerd` memory | session |
| Audit log, traces, token metadata (never values) | SQLite WAL in the per-user state dir | retention policy |
| Bundle cache, approval store | per-user state dir | until replaced |
| Credential roots, laptop CA root key | Keychain / libsecret | persistent |

The state dir is outside every sandbox mount on every backend.

## Failure modes and fail-closed behaviour

- `brokerd` not running: `broker run` starts it (or instructs the user); never runs the agent directly.
- `brokerd` crash mid-session: the sandbox's only route is the dead listener, so egress fails closed; on restart, orphaned sandboxes are killed and a `session_aborted` event is written.
- Control socket permission or peer-credential mismatch: reject the connection and log.
- Bundle signature invalid or expired past max age: refuse new sessions.
- Keychain locked: sessions that need that credential fail at mint time with a clear reason; others proceed.

## Security considerations

- Socket in a 0700 directory, file mode 0600; verify peer UID with `SO_PEERCRED` on Linux or `getpeereid` on macOS; reject other UIDs even if the mode is wrong.
- The data-plane channel (UDS, loopback or vsock) is separate from `ctl.sock`; data-plane messages cannot invoke control methods.
- JSON-RPC parsing gets size limits, a strict schema and a fuzz target.
- An exposed agent control plane is an attack surface: OpenClaw's token leak allowed disabling the sandbox ([Adversa](https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/)). `brokerd` never listens on TCP.

## Performance budget

Sandbox start ≤150 ms on native backends and session-start overhead within the ≤5% added wall-clock per task target ([[L4 Product Metrics]]). Agent-binary hashing should be cached by (path, inode, mtime) to stay within budget.

## Invariants upheld

[[I2 Fail-Closed Launch]] (start sequence), [[I5 Config Outside Writable Mounts]] (approval store, state dir), [[I8 No Flag Disables Isolation]] (CLI and API surface), [[I9 Hash-Chained Audit Outside the Sandbox]] (every control action is an audit event).

## Test plan

- Unit: session state machine transitions; bundle verification and max-age handling.
- Property: random sequences of control calls never leave a session `Running` without a backend handle and listener.
- Fuzz: JSON-RPC request parser.
- Integration: from inside a sandbox, try to `connect()` to `ctl.sock` path and to create a new `AF_UNIX` socket: both denied ([[Conformance Probe Matrix]] category 9).
- E2E: `broker run -- claude` and `-- codex` finish a "fix failing test" task ([[M0 Contained Run]]); flag-matrix test for I8.

## Dependencies

`tokio`, `clap`, `serde`/`serde_json`, `nix` (peer credentials), `rusqlite` (via audit), plus a JSON-RPC 2.0 implementation and a keychain/libsecret binding that are **not selected in the record**. Crate maturity beyond `hudsucker` and `landlock` is unverified ([[Tech Stack]]).

## How it connects

- implements:: [[Request and Session Lifecycle]]
- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[Netguard Ingress]]
- depends-on:: [[Control Plane and Policy Bundles]]
- depends-on:: [[seccomp-bpf]]
- depends-on:: [[Seatbelt]]
- part-of:: [[Repository Layout]]
- part-of:: [[Policy Learning Loop]]
- delivered-by:: [[M0 Contained Run]]
- evaluated-by:: [[L4 Product Metrics]]

## Implications for the build

- M0 needs only `run`, `doctor`, `session.start/stop` and a minimal recorder; design the socket protocol for the full method set now so later milestones add handlers, not a new protocol.
- Identity plumbing (`broker login` against Okta or Entra, [[Okta Cross App Access]], [[Entra Agent ID]]) arrives in [[M3 CI Identity and MCP]]; until then the Task owner is the local OS user.
- `broker why` is the main debugging tool for denies; build it in [[M1 Secrets Outside]] because the M1 acceptance requires it.

## Open questions

- Socket and state-dir locations per OS are proposals (for example under `$XDG_RUNTIME_DIR` on Linux); none are specified in the record.
- Whether `brokerd` should be socket-activated or always running; affects cold-start latency.
- Multi-user hosts (shared CI runners) and how peer-credential checks map to sessions.

## Sources

- https://github.com/anthropic-experimental/sandbox-runtime
- https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md
- https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/
- Report: "Interfaces" (control API), component diagram, deployment modes, repository layout, risk "Broker becomes the credential honeypot"; research note 05 sections 3.5 and 3.6.

## Implementation notes

- 2026-09-24: the session record is write-ahead: `session.start` is appended before the sandbox is launched (the agent never starts if the audit log cannot take it), and a new event kind `session.ready` records the layers the shim verified from inside. `session.exited` is sent to the CLI only after teardown and `session.stop` are durable.
- 2026-09-24: brokerd never runs git on the host (repository config can execute code); the repository root is found by walking up to a `.git` entry. The Task owner is `local:<user>` until M3 identity.
- 2026-09-24: `BROKER_HOME` roots config, state and runtime in one directory (tests, CI). It chooses where policy is read from, never whether isolation applies.

## Build log

- 2026-09-24: built `broker` (`run`, `doctor`, `why`, `audit verify|tail`, `daemon status|stop`) and `brokerd` (`code/crates/broker-cli/`, `code/crates/brokerd/`). `ctl.sock` is newline-delimited JSON-RPC 2.0 in a 0700 directory, mode 0600, peer UID checked with `peer_cred`; `session.start` carries the CLI's stdin/stdout/stderr as `SCM_RIGHTS` descriptors so brokerd is the parent of the sandbox while the agent keeps the user's terminal; the CLI forwards INT/TERM/HUP/WINCH/QUIT and exits with the agent's status (125 when the broker refuses). `broker run` starts brokerd on demand; brokerd exits when idle. Methods: `session.start/signal/stop`, `decision.explain`, `audit.verify`, `doctor`, `daemon.status/shutdown`. Tests: `no_flag_disables_isolation` (every clap flag enumerated), `agent_flags_after_dashdash_are_passed_verbatim`, `fds_travel_with_the_line`, `i8_*`, `i9_every_decision_is_chained_and_explainable`.
- 2026-09-24: not built (later milestones): `init`, `learn`, `suggest`, `login`, `mcp`, bundle sync, keychain roots.
- 2026-09-24 (M1): brokerd creates the session CA, trust bundle, sentinels and issuers at session start (`session_l7.rs`) and hands terminated tunnels to `l7_pipeline`; `session.start` records the credential IDs (never values) and the trust bundle. `broker why` prints each adapter verb (for example `git.push github.test:…/acme/web refs/heads/main force=false (fast_forward) => git_ref_not_allowed`) and the credential ID and origin. `session.rs` was split (`session_util.rs`, `session_l7.rs`) to stay under 500 lines.
