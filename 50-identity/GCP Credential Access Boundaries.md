---
title: "GCP Credential Access Boundaries"
aliases: ["GCP Downscoped Tokens", "Credential Access Boundary"]
type: "standard"
section: "identity"
summary: "GCP downscoped tokens: at most 10 rules of availableResource, inRole permission ceilings and CEL prefix conditions, Cloud Storage only; every other GCP service falls back to proxy enforcement."
tags: [sandbox/identity, standard, topic/credentials, platform/cloud, control/task-tok, control/cred-out, boundary/tb4, milestone/phase2]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
related: ["[[Just-in-Time Credential Minting]]", "[[Credential Injector and Issuers]]", "[[AWS STS Session Policies]]", "[[Risk Register]]", "[[MVP Plan]]", "[[GitHub App Installation Tokens]]"]
---

# GCP Credential Access Boundaries

A GCP Credential Access Boundary (CAB) produces a downscoped short-lived token from an existing OAuth access token by attaching at most ten rules, each naming a Cloud Storage bucket, an upper bound on permissions expressed as `inRole:` roles, and an optional CEL condition such as an object-name prefix. It works **only for Cloud Storage**, and a credential carries one boundary. For every other GCP service the broker's method and path rules are the only scope, as they are for static SaaS API keys.

## What a boundary contains

From the GCP downscoping documentation ([GCP docs](https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials)):

| Element | Meaning |
|---|---|
| `availableResource` | the bucket the rule applies to |
| `availablePermissions` | upper bound, as `inRole:` role references |
| `availabilityCondition` | optional CEL expression, for example `resource.name.startsWith(...)` |
| `objectListPrefix` | used in conditions to allow listing only under a prefix |
| limits | **Cloud Storage only**; at most **10** rules; **one boundary per credential** |

Illustrative boundary (field names from the docs; the exact resource-name string formats and the role name are background knowledge, confirm before coding):

```json
{
  "accessBoundary": {
    "accessBoundaryRules": [
      {
        "availableResource": "//storage.googleapis.com/projects/_/buckets/acme-data",
        "availablePermissions": ["inRole:roles/storage.objectViewer"],
        "availabilityCondition": {
          "expression": "resource.name.startsWith('projects/_/buckets/acme-data/objects/tasks/123/')"
        }
      }
    ]
  }
}
```

The downscoped token is obtained by exchanging the source token together with the boundary at Google's token service (an RFC 8693-style exchange; the endpoint and parameter names are not captured in the record, so read them from the cited page).

## How it compares

| Target | Finest native scope | Lifetime | Who enforces the rest |
|---|---|---|---|
| [[GitHub App Installation Tokens]] | ≤500 repos, per-category read/write | 1 h | broker: branch, path, verb |
| [[AWS STS Session Policies]] | session policy ∩ role, tags, `SourceIdentity` | 900 s–43,200 s | mostly native |
| GCP CAB | Cloud Storage only, ≤10 rules, CEL prefix | short-lived | broker for every other service |
| Static SaaS API keys | none | long-lived | the broker's method/path allowlist *is* the scope |

Table condensed from the report's native-downscoping section ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app); [AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html); [GCP docs](https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials)).

The asymmetry is the point of [[Risk Register]]'s "Upstream scoping limits" row: GitHub has no branch or path scope and GCP CAB covers Cloud Storage only, so the mitigation is proxy enforcement for everything native tokens cannot express.

## Fallback for other GCP services

Research-note inference: for BigQuery, Pub/Sub, Compute and the rest, the broker holds a short-lived GCP token (from workload-identity federation or a service account held outside the sandbox) and enforces scope by method, path and, where needed, request-body inspection at L7. Because the upstream token is broader than the task, that token must never leave the broker, and the Cedar grant must be the tighter bound. GCP and Azure workload-identity federation are listed as later issuers in research note 05 §3.2 (a design proposal); no milestone in [[MVP Plan]] delivers them.

## Verdict for the broker

**Proposal.**

- **Use it for:** Cloud Storage access from agents: one boundary per task, bucket plus object-prefix condition, `inRole` ceiling at the smallest role that covers observed operations.
- **Don't use it for:** any non-Storage GCP service; tasks needing more than 10 bucket rules (split the task); substituting for broker-side authorization (the CEL condition covers object names, not HTTP verbs on other APIs).
- **How we integrate it.** A future `gcp_cab` issuer in `crates/creds/issuers/` implementing `CredentialIssuer`, compiling Cedar Storage grants into a boundary, exchanging for a downscoped token, caching by scope digest. Not in the MVP: M0–M4 cover GitHub App and AWS STS minting only ([[MVP Plan]]). Until then, GCP traffic goes through the `static` issuer with L7 rules, marked `risk: high`.

## How it connects

- implements:: [[Just-in-Time Credential Minting]] (Storage only)
- delivered-by:: [[Credential Injector and Issuers]] (future `gcp_cab` issuer)
- contrasts-with:: [[AWS STS Session Policies]] (native scoping across services)
- mitigated-by:: [[Risk Register]] ("Upstream scoping limits")
- depends-on:: [[MVP Plan]] (not scheduled in M0–M4)

## Implications for the build

- Do not advertise GCP minting in MVP docs.
- When added, the conformance suite needs a probe that reads outside the prefix (native denial) and one that calls a non-Storage API (broker denial).

## Open questions

- Exact token-exchange endpoint, parameters and resource-name formats are not in the record.
- Whether GCP extended CAB beyond Cloud Storage by 2026 was not checked.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
