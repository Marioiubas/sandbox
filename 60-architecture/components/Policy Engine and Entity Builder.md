---
title: "Policy Engine and Entity Builder"
aliases: ["policy crate", "Entity Builder"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/policy, topic/ifc, control/egress, control/task-tok, boundary/tb4, invariant/i3, invariant/i4, invariant/i6, milestone/m2]
status: built
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The policy crate at request time: builds Cedar entities and context from parsed traffic (Task, Host, PathPrefix, Repo, Credential, McpServer; trifecta labels; sequence-automaton state) and authorizes every derived request in-process with cedar-policy; all must allow."
related: ["[[Cedar]]", "[[Broker Cedar Schema]]", "[[Trifecta Session Labels]]", "[[Hostname Canonicaliser]]", "[[Core Trait Contracts]]", "[[Adaptive Evaluation of Deterministic Monitors]]", "[[broker.toml Human Policy Layer]]", "[[Request and Session Lifecycle]]", "[[I6 Single Canonicaliser]]", "[[I4 Repo Policy Only Narrows]]", "[[I3 Probabilistic Components Only Narrow]]", "[[Example Cedar Policies]]", "[[SymCC CI Gates]]", "[[Credential Injector and Issuers]]", "[[Audit Recorder and Event Schema]]", "[[Control Plane and Policy Bundles]]", "[[GitHub API Adapter]]", "[[Git Smart-HTTP Adapter]]", "[[MCP Guard]]", "[[Policy Learning Loop]]", "[[Red-Team Plan]]", "[[Provenance-Aware Cedar]]", "[[ADR-007 Cedar with a TOML Front-End]]", "[[ADR-008 Grant Representation as Entities and Txn-Token JWT]]", "[[M2 Policy Audit and Learn]]", "[[Conformance Probe Matrix]]", "[[Open Questions and Unverified Claims]]", "[[I2 Fail-Closed Launch]]", "[[Native Config Exporters]]", "[[Repository Layout]]"]
sources: ["https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md", "https://arxiv.org/html/2403.04651", "https://docs.rs/cedar-policy-symcc", "https://goteleport.com/blog/benchmarking-policy-languages/", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/", "https://arxiv.org/abs/2606.26479", "https://github.com/invariantlabs-ai/invariant", "https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/"]
milestone: M2
code: ["code/crates/policy/src/cedar", "code/crates/policy/src/egress.rs", "code/crates/policy/src/egress/authorize.rs", "code/crates/policy/src/egress/mcp.rs"]
---

# Policy Engine and Entity Builder

> The policy crate at request time: builds Cedar entities and context from parsed traffic (Task, Host, PathPrefix, Repo, Credential, McpServer; trifecta labels; sequence-automaton state) and authorizes every derived request in-process with cedar-policy; all must allow.

## Responsibility

The runtime half of `crates/policy` ([[Repository Layout]]: "cedar schema, entity builder, TOML→Cedar compiler, exporters"). The compiler and exporters are specified in [[broker.toml Human Policy Layer]] and [[Native Config Exporters]]; this note covers what happens per request:

1. turn adapter output (`Vec<AuthzRequest>`) plus session state into Cedar entities and context;
2. evaluate each request against the active policy sets with the `cedar-policy` crate, in process;
3. return one `Decision` that allows only if **every** derived request allows, with determining policy IDs for audit and `broker why`;
4. hand an `AllowedBinding` to [[Credential Injector and Issuers]] only when `credential.use` allowed.

**It must never:** accept a host or path string that did not come from the canonicaliser ([[I6 Single Canonicaliser]]); treat an evaluation error, a schema-invalid request or an empty request list as allow; merge repo policy into the base set rather than conjoining ([[I4 Repo Policy Only Narrows]]); take labels, identity or approval state from request content or model output; let a probabilistic component clear a label or add a permit ([[I3 Probabilistic Components Only Narrow]]).

## Why Cedar, and the edge this component sits on

Cedar's semantics are proved in Lean ("If some forbid policy is satisfied, then the request is denied"; "A request is allowed only if it is explicitly permitted"), and its symbolic compilation to SMT is sound and complete ([cedar-lean README](https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md)). Median authorization is 4.0–11.0 µs ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)); Cedar is deterministic and deliberately has no regex ([Teleport](https://goteleport.com/blog/benchmarking-policy-languages/)); AgentCore Policy uses it for agent authorization ([AWS](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)). See [[Cedar]].

The report is explicit about where those guarantees stop, and every stop is in this component:

- "They cover policy semantics, not the enforcement point. How raw traffic is parsed into entities (host, SNI, IP, redirects) must still be tested empirically."
- "They hold only relative to the schema. A schema with non-canonical host strings yields proofs about the wrong thing."
- "`like` patterns are string patterns, not DNS semantics."
- "Information-flow properties are not expressible in stateless request authorization. Cedar can only check the labels the broker gives it."

The 2026 out-of-band study left white-box attacks for future work ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)); the report's red-team human ring therefore includes "a white-box attempt against the Cedar entity builder" ([[Red-Team Plan]], [[Adaptive Evaluation of Deterministic Monitors]]).

## Inputs and outputs

| Input | From |
|---|---|
| `Vec<AuthzRequest>` (action, resource UID, context JSON, verb) | protocol adapters via the L7 pipeline, or netguard for L4 admission |
| `SessionCtx` (Task, labels, mode, approvals) | `brokerd` session |
| Active policy sets, schema, entity data | signed bundle ([[Control Plane and Policy Bundles]]) plus approved repo layer |
| Resolved-address class, SNI, Host header | netguard and tls |

Outputs: `Decision` (to the pipeline), `AllowedBinding` (to `creds`), label and automaton updates (to the session), decision fields for [[Audit Recorder and Event Schema]].

## Interface

**Proposal; not compiled.**

```rust
pub struct PolicyEngine {
    schema: cedar_policy::Schema,
    base: arc_swap::ArcSwap<cedar_policy::PolicySet>,      // org + user, from the bundle
    bundle_version: String,
}

pub struct SessionPolicy {                                   // per session
    repo: Option<cedar_policy::PolicySet>,                  // approved .broker/ layer; conjoined
    entities: cedar_policy::Entities,                       // Task, User, Agent, Credential, McpServer, Repo
    automaton: SequenceAutomaton,                           // sequence rules as context booleans
}

pub enum Verdict { Allow, Deny }
pub struct SubDecision { pub req: AuthzRequest, pub verdict: Verdict, pub determining: Vec<cedar_policy::PolicyId>, pub errors: Vec<String> }

pub struct Decision {
    pub allowed: bool,                                       // AND over sub-decisions, false if empty
    pub subs: Vec<SubDecision>,
    pub mode: Mode,                                          // Enforce | Audit (would-be decision recorded)
    pub binding: Option<AllowedBinding>,                     // only constructible here
    pub bundle_version: String,
}

impl PolicyEngine {
    pub fn authorize_all(&self, s: &SessionCtx, sp: &SessionPolicy, reqs: &[AuthzRequest]) -> Decision;
    pub fn build_resource(&self, host: &CanonicalHost, path: Option<&CanonicalPath>) -> EntityUid; // + ancestors
    pub fn reload(&self, bundle: VerifiedBundle) -> anyhow::Result<()>;                          // atomic swap
}
```

The schema, actions and context types are the report's sketch in [[Broker Cedar Schema]]: principal `Task`; resources `Host`, `PathPrefix in [Host, PathPrefix]`, `Repo`, `Credential`, `McpServer`, `Dir`, `File`; contexts `HttpCtx`, `GitCtx`, `CredCtx`, `McpCtx`, each carrying `session: { id, now, approved, trifecta, mode }`. Default policies are in [[Example Cedar Policies]].

## Internal design

**Proposal.**

### Entity builder

- **Principal.** One `Task` per session, built at `session.start` with `owner`, `agent` (vendor, binary SHA-256), `repo`, `branch_prefix`, `expires_at` (epoch seconds, because Cedar `datetime` availability across SDKs was not verified). "Principal = Task, which carries the user and the agent, so every decision and log line is keyed to both" (research note 03).
- **Grants are entities, not policy text.** Expiry and revocation are data updates with no recompile ([[ADR-008 Grant Representation as Entities and Txn-Token JWT]]).
- **Host and PathPrefix.** `Host::"<canonical name>"` with `registrable` from the canonicaliser; for a path `/repos/acme/web/pulls` the builder emits the chain `PathPrefix::"api.github.com/repos/acme/web/pulls" in PathPrefix::"api.github.com/repos/acme/web" in … in Host::"api.github.com"`, bounded in depth. Policies use `resource in PathPrefix::"…"`; the compiler never emits `like` on hosts, so DNS semantics come from the canonicaliser, not string patterns.
- **Repo.** `Repo` from the canonical remote; `visibility` from GitHub API responses the broker proxies ([[GitHub API Adapter]]); unknown visibility is treated as private for `sensitive_read`.
- **Credential and McpServer.** From the bundle and pinned MCP config (`allowed_hosts`, `risk`; `manifest_sha256`, `pinned`) ([[MCP Guard]]).
- **Context.** `now` from the broker clock; `dest_class` from the resolved address class; `sni` and `host_header` from the canonicalised values; `approved` true only for a request covered by a live approval record.

### Labels and sequences

Trifecta labels are session state set only by the broker from systems of record, sticky once true ([[Trifecta Session Labels]]). Sequence rules such as Invariant's `get_inbox -> send_email` ([Invariant](https://github.com/invariantlabs-ai/invariant)) "become a small automaton in the broker, exposed as context attributes", which "keeps each per-call decision analyzable" (report).

### Evaluation

1. Validate each request against the schema; invalid → sub-deny.
2. Evaluate against `base`; if a repo set exists, evaluate it too and require both to allow.
3. Any Cedar error → sub-deny (the SymCC gate `check_never_errors` should make this unreachable, [[SymCC CI Gates]]).
4. `allowed = !subs.is_empty() && subs.iter().all(allow)`.
5. **Audit mode.** Record the would-be decision; forward non-credential requests that would be denied. Org-ceiling forbids, `credential.use` and foreign-credential rejection are enforced in every mode, so learning never attaches a credential the policy did not allow.

### Reload

`policy.reload` verifies and swaps the base set atomically; entity updates (revocations) apply to the next decision; each decision records `bundle_version`.

## State

Per engine: schema, base set, bundle version. Per session: repo set, entity store, labels, automaton, approval records. No persistent state of its own (bundles and approvals live in `brokerd`'s state dir).

## Failure modes and fail-closed behaviour

- Schema-invalid request, evaluation error, empty request list: deny.
- Entity-builder error (path too deep, unknown repo form): deny with `entity_error`.
- Bundle signature or max-age failure at reload: keep the previous set; at session start refuse launch ([[I2 Fail-Closed Launch]]).
- Composition-bug detector: at session start run `check_implies(P_repo ∧ P_org, P_org)` ([docs.rs](https://docs.rs/cedar-policy-symcc)); failure refuses launch ([[I4 Repo Policy Only Narrows]]).

## Security considerations

- **Parser differentials become entity differentials.** The NUL-byte bypass came from a suffix check and libc resolution disagreeing ([Aonan Guan](https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/)). The builder takes only `CanonicalHost`/`CanonicalPath` types that cannot be constructed elsewhere.
- **Redirects and h2 streams** produce fresh request sets; nothing is cached across them except labels.
- **Label sources** are the soft spot for adaptive attackers; labels only move toward more restrictive.
- **IFC is out of scope for Cedar**; per-value provenance is research ([[Provenance-Aware Cedar]]).

## Performance budget

Cedar evaluation 4.0–11.0 µs median per request ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)); a network request derives one Cedar request per adapter output (for example one `git.push` per ref plus `credential.use`). **Proposal:** entity building plus evaluation ≤100 µs p99 per network request on reference hardware, a small share of the ≤5 ms warm p50 budget.

## Invariants upheld

[[I6 Single Canonicaliser]] (typed canonical inputs), [[I4 Repo Policy Only Narrows]] (conjunction plus implication check), [[I3 Probabilistic Components Only Narrow]] (no widening path from labels or detectors), and the "all derived requests must allow" contract of [[Core Trait Contracts]].

## Test plan

- **Unit:** each entity type from fixture traffic; PathPrefix ancestor chains; context field mapping; audit-mode enforcement of ceiling and `credential.use`.
- **Property:** decision equals the conjunction of sub-decisions; empty list denies; for random repo sets, `allow_effective ⇒ allow_base`; labels never go from true to false within a session.
- **Differential:** a second, deliberately simple reference builder compared on generated traffic; any disagreement fails CI.
- **Fuzz:** raw bytes → canonicaliser → builder → evaluation, asserting no panic and deny on error.
- **Golden:** [[Example Cedar Policies]] against recorded requests (push to `agent/*` allowed; to `main` and with force denied; Rule of Two fires).
- **Conformance:** categories 1, 6, 7 and 8 ([[Conformance Probe Matrix]]).

## Crates

`policy` (runtime), `cedar-policy`, `cedar-policy-symcc` + cvc5 (CI and the start-time check), `arc-swap`, `serde_json`. Versions unverified ([[Open Questions and Unverified Claims]]).

## Delivering milestone

[[M2 Policy Audit and Learn]] (`entities.rs`, `authorize.rs`, schema compiled and validated). M0 and M1 use interim allowlist and method/path tables behind the same `Decision` type; M3 adds trifecta context.

## How it connects

- depends-on:: [[Cedar]]
- depends-on:: [[Broker Cedar Schema]]
- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[broker.toml Human Policy Layer]]
- implements:: [[Core Trait Contracts]]
- implements:: [[I6 Single Canonicaliser]]
- implements:: [[I4 Repo Policy Only Narrows]]
- part-of:: [[Request and Session Lifecycle]]
- evaluated-by:: [[Adaptive Evaluation of Deterministic Monitors]]
- evaluated-by:: [[SymCC CI Gates]]
- evaluated-by:: [[Conformance Probe Matrix]]
- delivered-by:: [[M2 Policy Audit and Learn]]
- decided-by:: [[ADR-007 Cedar with a TOML Front-End]]
- decided-by:: [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]

[[Trifecta Session Labels]] is part-of this component.

## Implications for the build

- The M2 checklist starts by compiling the report's schema (it is "not compiled"); record every change in [[Broker Cedar Schema]].
- Keep the builder small and separate from adapters so the white-box red team has one target.
- Schema extensions proposed elsewhere (`pkg.*` actions, `McpServer` as principal) land together in one ADR.

## Open questions

- Cedar `datetime` support across SDKs; epoch seconds until verified.
- Whether per-tool MCP argument context types are generated per server or carried as a generic record.
- How approval records scope `approved` (one request, one verb, or a time window) without label creep; see [[Trifecta Session Labels]].

## Sources

- https://github.com/cedar-policy/cedar-spec/blob/main/cedar-lean/README.md
- https://arxiv.org/html/2403.04651
- https://docs.rs/cedar-policy-symcc
- https://goteleport.com/blog/benchmarking-policy-languages/
- https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/
- https://arxiv.org/abs/2606.26479
- https://github.com/invariantlabs-ai/invariant
- https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/
- Report: component "policy: entity builder + Cedar authorize (all derived requests must allow)", request-life step 3, "Why Cedar, and where its guarantees stop", schema sketch, sequence rules, red-team human ring; research notes 02 Q4 and 03 Q5.

## Build log

- 2026-09-24: built (M2 step 1): `policy::cedar` (`Engine` with base and optional repo `PolicySet`, strict validation, `authorize` → `Verdict` with determining policy IDs; errors and invalid requests deny), `entities.rs` (Task/User/Agent principal, Host with Domain and category parents, Repo, Credential, Path record), `compile.rs` (grants → permits), `categories.rs` (DoH, paste, tunnel). `EgressPolicy::{admit_host, admit_addrs, authorize_l7}` now decide through Cedar; the M1 tables only explain denies. Record mode (`broker learn`) records the enforce-mode verdict as `would_deny`. Trifecta labels and the sequence automaton are M3 (labels are always false today).
- 2026-09-24: tests: `cedar::tests::{golden_worked_decisions, admission_semantics_match_m0, record_mode_relaxes_task_permits_but_not_the_ceiling, repo_layer_only_narrows, credential_ceiling_confines_credentials, malformed_requests_deny, cedar_agrees_with_the_reference}`; all M0/M1 conformance and invariant suites unchanged.
- 2026-09-24: grants stay policy text rather than entities so the formal gates prove them ([[ADR-028 M2 Plan Items Built Differently or Deferred]]); plain grants carry no L7 authority ([[ADR-027 Plain Host Grants Carry No L7 Authority]]).
- 2026-09-25: `code/crates/policy/src/egress.rs` split to stay under 500 lines, no behaviour change: L7 authorization (`authorize_l7`, per-action requests, `credential.use`) moved to `egress/authorize.rs`, MCP call decisions to `egress/mcp.rs`, tests to `egress/tests.rs`; compilation and admission stay in `egress.rs`.
