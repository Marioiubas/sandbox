---
title: "Control Plane and Policy Bundles"
aliases: ["Control Plane", "Policy Bundle Format", "ee"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/policy, topic/identity, topic/audit, topic/approval, topic/supply-chain, platform/cloud, control/audit, control/pin, invariant/i3, invariant/i4, invariant/i5, invariant/i9, milestone/m2, milestone/phase2]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The commercial ee/ control plane (policy repo -> compiler + SymCC gates -> signed bundles; OIDC/SCIM; issuer config; audit ingest to SIEM; review UI; fleet inventory) and the bundle format (schema.cedarschema, policies/*.cedar, entities.json, broker.toml, manifest signed with Ed25519 or cosign, max age offline)."
related: ["[[SymCC CI Gates]]", "[[Broker CLI and Daemon]]", "[[Okta Cross App Access]]", "[[Entra Agent ID]]", "[[Audit Recorder and Event Schema]]", "[[Policy Learning Loop]]", "[[ADR-014 Apache-2.0 Endpoint with Commercial ee]]", "[[MVP Plan]]", "[[Native Config Exporters]]", "[[Policy Engine and Entity Builder]]", "[[broker.toml Human Policy Layer]]", "[[Broker Cedar Schema]]", "[[Credential Injector and Issuers]]", "[[I2 Fail-Closed Launch]]", "[[I3 Probabilistic Components Only Narrow]]", "[[I4 Repo Policy Only Narrows]]", "[[I5 Config Outside Writable Mounts]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[Local Credential Proxies]]", "[[Tech Stack]]", "[[Repository Layout]]", "[[Architecture Overview]]", "[[M2 Policy Audit and Learn]]", "[[Risk Register]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://docs.rs/cedar-policy-symcc", "https://workos.com/blog/id-jag-cross-app-access", "https://developer.okta.com/blog/2026/08/24/xaa-oidc-resource", "https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow", "https://startwithidentity.com/blog/agent-identity-gets-a-protocol/", "https://github.com/Infisical/agent-vault", "https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk", "https://code.claude.com/docs/en/sandboxing", "https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/"]
milestone: phase2
---

# Control Plane and Policy Bundles

> The commercial ee/ control plane (policy repo -> compiler + SymCC gates -> signed bundles; OIDC/SCIM; issuer config; audit ingest to SIEM; review UI; fleet inventory) and the bundle format (schema.cedarschema, policies/*.cedar, entities.json, broker.toml, manifest signed with Ed25519 or cosign, max age offline).

## Responsibility

Two things with different licences and milestones:

1. **The bundle format and its verification on the endpoint** (Apache-2.0, in `policy` and `brokerd`): the only way org policy reaches a broker. Needed from [[M2 Policy Audit and Learn]], when policy becomes Cedar and CI runs the SymCC gates.
2. **The control plane** (commercial `ee/`, phase 2): the report's box "Policy repo (git) → compiler + SymCC gates → signed bundles │ OIDC/SCIM (Okta, Entra) │ Issuer config (GitHub App keys, AWS roles, OAuth clients) │ Audit ingest → SIEM │ Review UI (learned diffs, approvals) │ Fleet inventory". Phase 2 adds "signed fleet bundles, device enrolment, SCIM, SIEM connectors, Slack or Teams step-up approvals, the diff-review UI and agent inventory" ([[MVP Plan]]).

The split follows [[ADR-014 Apache-2.0 Endpoint with Commercial ee]]: everything that enforces runs on the endpoint and is auditable; the fleet conveniences are paid. Precedents: Infisical Agent Vault ships MIT with an `ee` directory under a separate licence ([GitHub](https://github.com/Infisical/agent-vault); [[Local Credential Proxies]]); Daytona went closed-source in June 2026 ([bex.co](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk)), which favours an auditable Apache-2.0 data plane.

**It must never:** be required for enforcement (endpoints enforce from the last-known-good bundle and refuse new sessions past max age); ship a bundle that has not passed the SymCC gates; put secret material in a bundle; forward a user's IdP token as-is to any upstream; let an LLM merge a policy change ([[I3 Probabilistic Components Only Narrow]]); accept repo-scope policy as anything but a narrowing ([[I4 Repo Policy Only Narrows]]).

## Inputs and outputs

| Input | From | Output | To |
|---|---|---|---|
| Policy source (`policies/`, `broker.toml`, entity data) | customer's git repo | signed bundle | endpoints over mTLS |
| Learned diffs | [[Policy Learning Loop]] | PRs with evidence, gate results, replay stats | reviewers |
| IdP groups and users | Okta or Entra via OIDC and SCIM | `User`/`Group` entity data | bundles |
| Audit batches (OTLP/OCSF, chain anchor) | endpoints ([[Audit Recorder and Event Schema]]) | SIEM delivery; retention; compliance evidence | Splunk HEC, Microsoft Sentinel, Datadog, S3, webhooks (research note 05) |
| Step-up requests (`requires_approval`) | endpoints | approval records | endpoints |
| Device enrolment | endpoints | device certificates | endpoints |

## Bundle format

The report's list (**Proposal**): a tarball containing `schema.cedarschema`, `policies/*.cedar`, `entities.json`, the human-layer `broker.toml`, and "a manifest signed with an org Ed25519 key or cosign, with a maximum age for offline operation".

Manifest (**Proposal; not compiled**; field names are design defaults):

```json
{
  "format": 1,
  "tenant": "acme",
  "version": 1842,
  "issued_at": 1790000000,
  "max_age_s": 259200,
  "files": {
    "schema.cedarschema": "sha256:…",
    "policies/org.cedar": "sha256:…",
    "policies/ceiling.cedar": "sha256:…",
    "entities.json": "sha256:…",
    "broker.toml": "sha256:…"
  },
  "gates": { "report_sha256": "…", "passed": ["narrowing", "ceiling", "credential_confinement",
                                             "never_errors", "deny_rules_live", "tenant_isolation"] },
  "source": { "repo": "github.com/acme/broker-policy", "commit": "…" }
}
```

Signature: `manifest.json.sig` (Ed25519 over the manifest bytes) or a cosign bundle. The endpoint pins the org public key at enrolment or in user config.

Endpoint verification (**Proposal; not compiled**):

```rust
pub struct VerifiedBundle { pub tenant: String, pub version: u64, pub issued_at: u64,
                            pub schema: cedar_policy::Schema, pub policies: cedar_policy::PolicySet,
                            pub entities: cedar_policy::Entities, pub human: BrokerToml }

pub fn verify_bundle(tar: &[u8], trust: &OrgTrust, last: Option<&BundleMeta>, now: u64)
    -> Result<VerifiedBundle, BundleError>;
// 1 signature over manifest; 2 every file hash; 3 tenant == trust.tenant;
// 4 version > last.version (anti-rollback); 5 now <= issued_at + max_age_s;
// 6 schema parses; policies validate against schema; entities conform; broker.toml compiles.
```

Control-plane endpoints (**Proposal**; paths illustrative):

```text
GET  /v1/bundles/latest            mTLS device cert → bundle tarball + signature
POST /v1/audit/batches             OTLP or OCSF JSON, last chain hash as anchor
POST /v1/approvals                 {tenant, session, action, resource, authority_diff} → pending id
GET  /v1/approvals/{id}            → approved | denied | expired
POST /v1/devices/enrol             OIDC-authenticated CSR → device certificate
```

## Internal design

### Compiler pipeline

Research note 05 §3.3 lists the compiler's outputs (**Proposal**): "(a) proxy decision tables and entity store; (b) Seatbelt SBPL and Landlock rulesets; (c) exporters to Claude Code managed settings JSON, Codex `requirements.toml`, Cursor `sandbox.json` and OpenShell YAML ... ; (d) Cedar analysis checks (no wildcard push, no `*` egress with injection, and so on)." The exporters are specified in [[Native Config Exporters]]; Codex's managed `requirements.toml` via MDM ([Codex KB](https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/)) and Claude Code managed settings, where repository settings cannot enable injection ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)), are the targets.

Every bundle passes the six gates of [[SymCC CI Gates]] using `cedar-policy-symcc` queries (`check_implies`, `check_never_errors`, `check_disjoint` and others) ([docs.rs](https://docs.rs/cedar-policy-symcc)); the gate report hash goes into the manifest. The same open-source compiler and gates run as a CI job in the customer's policy repo, so the MVP needs no server.

### Identity

**Proposal**, per deployment mode (research note 05): laptops use OIDC device-code login to Okta or Entra, with groups via SCIM feeding Cedar principals; CI exchanges GitHub Actions or GitLab OIDC JWTs; Kubernetes uses projected service-account tokens. Later, agents are registered as Okta Agent SSO or Entra Agent ID identities, and ID-JAG is used for SaaS. The shipping flows: Okta's ID-JAG, where "the resource's authorization server redeems it for a short-lived token after admin policy checks" ([WorkOS](https://workos.com/blog/id-jag-cross-app-access); [Okta](https://developer.okta.com/blog/2026/08/24/xaa-oidc-resource); [[Okta Cross App Access]]), and Entra Agent ID on-behalf-of, where agent identities cannot run interactive `/authorize` and consent comes only from admin pre-authorization ([Microsoft Learn](https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow); [[Entra Agent ID]]). The control plane's job is narrowing, because "delegation chains inherit the broadest permission unless actively narrowed" ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)).

### Approvals and review

Step-up to Slack, Teams or the CLI for actions tagged `requires_approval` (for example `pr.merge`, `pkg.publish`), rendering the authority diff, not model prose ([[Fatigue-Resistant Approval Interfaces]]). The diff-review UI shows learned Cedar diffs with evidence counts, gate results and "would have blocked N" replay statistics; an LLM may explain, never merge.

### Fleet inventory

Which agents (by binary hash) and MCP servers (by manifest hash) run where, from `session.start` and `mcp.launch` events.

## State

Control plane (axum + Postgres, TypeScript/React UI per [[Tech Stack]]): tenants, devices and certificates, bundle history, approvals, audit copies with anchors, inventory. Endpoint: bundle cache, last-known-good metadata and the pinned org key in `brokerd`'s state dir, outside every mount ([[I5 Config Outside Writable Mounts]]).

## Failure modes and fail-closed behaviour

- Signature, hash, tenant or schema failure: reject; keep last-known-good; alert via `broker doctor`.
- Older version than the cached one: reject as rollback.
- Past `max_age_s` with no fresh bundle: refuse new sessions ([[I2 Fail-Closed Launch]]); running sessions end at their task expiry.
- Control plane down: enforcement unaffected; audit export backs up locally; approvals unavailable, so approval-gated actions stay denied.

## Security considerations

- **Fleet-wide blast radius.** A compromised control plane could widen every endpoint. Mitigations (**Proposal**): signing key held outside the server (in the customer's CI or an HSM); ceiling gates re-run by the endpoint on the entity data it can check; anti-rollback; no secrets in bundles.
- **Issuer config versus issuer secrets.** The report's box lists "Issuer config (GitHub App keys, AWS roles, OAuth clients)". Bundles carry identifiers (app IDs, role ARNs, client IDs) only; where private keys live for a fleet is open (below).
- **Audit ingest** verifies chain continuity per device against anchors ([[I9 Hash-Chained Audit Outside the Sandbox]]).

## Performance budget

Off the request path. Bundle verification plus Cedar validation at reload should complete well under a second for typical policy sizes (**Proposal**, measure); reload swaps atomically in [[Policy Engine and Entity Builder]].

## Invariants upheld

[[I3 Probabilistic Components Only Narrow]] (no auto-merge; gates), [[I4 Repo Policy Only Narrows]] (repo layer composed and gated), [[I5 Config Outside Writable Mounts]] (bundles and keys outside mounts, hash-verified), [[I9 Hash-Chained Audit Outside the Sandbox]] (anchored ingest), I2 (max age).

## Test plan

- **Unit:** `verify_bundle` rejects bad signature, one-byte file tamper, extra or missing file, wrong tenant, rollback, expired; accepts a valid bundle.
- **Property:** any single-byte mutation of a signed bundle is rejected.
- **Fuzz:** tar reader and manifest parser.
- **CI:** gates on fixture policy repos, including a deliberately widening change that must fail with counterexamples ([[SymCC CI Gates]]).
- **E2E:** offline endpoint runs until max age, then refuses new sessions; exporter golden files; audit batches reach a test SIEM sink ([[M2 Policy Audit and Learn]]).

## Crates

Endpoint: `policy` (bundle verify), `brokerd` (sync), `ed25519-dalek` or cosign verification, `tar`, `sha2`. Control plane (`ee/`): axum, Postgres, TypeScript/React. Versions unverified ([[Open Questions and Unverified Claims]]).

## Delivering milestone

Bundle format, verification and CI gates: [[M2 Policy Audit and Learn]]. Control plane v1: phase 2 (months 3–6). Registration with Okta Agent SSO and Entra Agent ID and ID-JAG for SaaS: phase 3.

## How it connects

- depends-on:: [[SymCC CI Gates]]
- depends-on:: [[Native Config Exporters]]
- depends-on:: [[Okta Cross App Access]]
- depends-on:: [[Entra Agent ID]]
- depends-on:: [[Audit Recorder and Event Schema]]
- part-of:: [[Policy Learning Loop]]
- part-of:: [[Architecture Overview]]
- delivered-by:: [[MVP Plan]]
- delivered-by:: [[M2 Policy Audit and Learn]]
- decided-by:: [[ADR-014 Apache-2.0 Endpoint with Commercial ee]]
- motivated-by:: [[Local Credential Proxies]]

Bundles are pulled and verified by [[Broker CLI and Daemon]].

## Implications for the build

- Define `verify_bundle` and the manifest in M2 even with no server: a CI job in the policy repo produces signed bundles with the open-source compiler.
- Keep bundle semantics identical whether produced by CI or by the `ee/` server, so the server adds convenience, not authority.
- The approval protocol must work without the control plane (CLI prompts over `ctl.sock`).

## Open questions

- Where GitHub App private keys and similar roots live for a fleet: enrolment-time provisioning into each keychain, or a control-plane minting service that returns short-lived tokens; needs an ADR ([[Risk Register]]: credential honeypot).
- Default `max_age_s` for offline operation is not in the record.
- Device attestation for enrolment is not in the record.

## Sources

- https://docs.rs/cedar-policy-symcc
- https://workos.com/blog/id-jag-cross-app-access
- https://developer.okta.com/blog/2026/08/24/xaa-oidc-resource
- https://learn.microsoft.com/en-us/entra/agent-id/agent-on-behalf-of-oauth-flow
- https://startwithidentity.com/blog/agent-identity-gets-a-protocol/
- https://github.com/Infisical/agent-vault
- https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk
- https://code.claude.com/docs/en/sandboxing
- https://codex.danielvaughan.com/2026/03/31/codex-cli-network-security-requirements-toml/
- Report: control-plane box of the component diagram, bundle list, "Later phases", licence decision, tech stack; research note 05 §3.3, §5.3 and §5.4.
