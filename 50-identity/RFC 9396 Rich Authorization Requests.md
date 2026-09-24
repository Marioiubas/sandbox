---
title: "RFC 9396 Rich Authorization Requests"
aliases: ["RAR", "authorization_details"]
type: "standard"
section: "identity"
summary: "authorization_details arrays of typed objects (locations, actions, datatypes, identifier, privileges): the only standard OAuth structure that can say actions=[GET] on a path, with per-type semantics the broker must interpret."
tags: [sandbox/identity, standard, topic/credentials, topic/policy, control/task-tok, boundary/tb4, milestone/phase2]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
related: ["[[RFC 8693 Token Exchange]]", "[[Internal Grant JWT]]", "[[Transaction Tokens and Agent Auth Drafts]]", "[[Broker Cedar Schema]]", "[[Just-in-Time Credential Minting]]", "[[I6 Single Canonicaliser]]", "[[ADR-008 Grant Representation as Entities and Txn-Token JWT]]"]
---

# RFC 9396 Rich Authorization Requests

RFC 9396 (2023) adds an `authorization_details` parameter to OAuth: a JSON array of typed objects, each with a `type` and optional common fields `locations`, `actions`, `datatypes`, `identifier` and `privileges`. It is the only standard OAuth structure that can say "`actions=[GET]` on `locations=[…/contents/docs/*]`", but the meaning of every field is defined per `type`, so a resource server (or the broker) must interpret it. The broker uses it as vocabulary for grant shapes, not as something upstreams will enforce.

## Structure

From [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396):

| Field | Required | Meaning |
|---|---|---|
| `type` | yes | identifier that defines the semantics of the whole object |
| `locations` | no | array of URIs or strings naming where the resource lives |
| `actions` | no | array of action strings |
| `datatypes` | no | kinds of data requested |
| `identifier` | no | a specific resource instance |
| `privileges` | no | privilege levels |

`authorization_details` can appear in authorization requests, token requests and (echoed) in token responses and introspection, so a client can request fine-grained authority and a resource server can see what was granted (RFC mechanics; the record extracted the object structure only).

## What it can express that scopes cannot

A scope string like `repo` or `contents:write` cannot say which path or method. A RAR object can (illustrative, using the field names above; the `type` URI is invented for the example and would be defined by the broker):

```json
"authorization_details": [
  { "type": "https://broker.example/http-access",
    "locations": ["https://api.github.com/repos/acme/web/contents/docs/*"],
    "actions": ["GET"] },
  { "type": "https://broker.example/http-access",
    "locations": ["https://api.github.com/repos/acme/web/pulls"],
    "actions": ["POST"],
    "identifier": "pr.create" },
  { "type": "https://broker.example/git",
    "locations": ["https://github.com/acme/web.git"],
    "actions": ["push"],
    "privileges": ["refs/heads/agent/*", "no-force"] }
]
```

This is the same information the broker's internal grant carries in `tctx.allowed` ([[Internal Grant JWT]]), expressed in a standard envelope.

## The catch: semantics are per type

- The RFC standardises the container, not the meaning of `locations` patterns, wildcards or action names; "semantics are per-`type`, so a resource server (or the broker) must interpret them" ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396); research note 03).
- No upstream in the record (GitHub, AWS, GCP) accepts RAR for the scopes the broker needs; GitHub's finest scope is repo plus permission category ([GitHub REST](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app)).
- Consequence: RAR is useful *between the broker's own components* (CI sidecar, gateway mode, control plane) and possibly toward future RAR-aware authorization servers, not as an upstream enforcement mechanism today.

## Mapping to the broker's model

| RAR field | Broker concept | Cedar |
|---|---|---|
| `type` | adapter family (`http-access`, `git`, `mcp`) | action namespace |
| `locations` | canonical host plus path prefix, or repo | `Host` / `PathPrefix` / `Repo` resource |
| `actions` | HTTP method or adapter verb | `http.GET`, `git.push`, `mcp.call_tool` |
| `identifier` | a single operation ID | resource entity UID |
| `privileges` | constraints such as ref patterns, `no-force` | context conditions |

**Proposal.** If the grant is ever expressed as RAR, the `locations` strings must pass through the same canonicaliser as live traffic before becoming Cedar entities; a RAR grant with non-canonical hostnames would make every proof about the wrong thing ([[I6 Single Canonicaliser]]; the Cedar guarantees hold only relative to the schema, per the report). The record explicitly offers "RAR-shaped `authorization_details`" as an alternative to the Txn-Token-shaped grant (research note 03 inference).

## Relationship to the other standards

- Carried in RFC 8693 token exchange or authorization requests ([[RFC 8693 Token Exchange]]).
- A Transaction Token's `tctx` can hold an equivalent structure ([[Transaction Tokens and Agent Auth Drafts]]).
- Audience pinning comes from RFC 8707 `resource`, not from RAR `locations` ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)).

## Verdict for the broker

**Proposal.**

- **Use it for:** a standards-aligned serialisation of task grants when they cross process or host boundaries, and for talking to any future RAR-aware authorization server; documentation vocabulary in [[Broker Cedar Schema]].
- **Don't use it for:** expecting GitHub, AWS or GCP to enforce path or method scope; replacing Cedar evaluation.
- **How we integrate it.** A `serde` model of `authorization_details` in `crates/grant` with a converter to and from Cedar entities and the `tctx.allowed` array; round-trip property tests (RAR → entities → RAR is identity for canonical inputs; non-canonical inputs are rejected). Not needed for single-host MVP sessions, where the grant lives only as Cedar entity data.

## How it connects

- depends-on:: [[RFC 8693 Token Exchange]] (transport)
- contrasts-with:: [[Internal Grant JWT]] (Txn-Token-shaped `tctx.allowed` chosen instead)
- contrasts-with:: [[Transaction Tokens and Agent Auth Drafts]]
- depends-on:: [[Broker Cedar Schema]] (entities it must map onto)
- part-of:: [[Just-in-Time Credential Minting]] (vocabulary for the task scope)
- decided-by:: [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]

## Implications for the build

- No MVP milestone requires RAR; keep the converter behind a feature flag until gateway mode (phase 2).
- If implemented, add a fuzz target for the RAR parser like every other parser.

## Open questions

- Whether any target authorization server in the fleet accepts RAR is not in the record.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
