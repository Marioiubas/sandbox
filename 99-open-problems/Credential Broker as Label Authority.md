---
title: "Credential Broker as Label Authority"
aliases: []
type: problem
section: open
tags: [sandbox/open, problem, topic/ifc, topic/credentials, topic/policy]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Credential Broker as Label Authority

> Derive confidentiality labels from the OAuth scope, tenant or repo visibility that produced each datum, closing FIDES's annotation gap from a source the model cannot influence (FlowSeal's principle).

## The problem

Information-flow control for agents needs labels on data, and the literature has no good answer to who assigns them. FIDES lists as a limitation that labels must be annotated or inferred ([arXiv](https://arxiv.org/html/2505.23643)). RTBAS decides which labels propagate with an LM judge and attention saliency, which is probabilistic ([arXiv](https://arxiv.org/abs/2502.08966)). When label assignment depends on a model reading adversary-controlled content, "the attack surface and defense mechanism coincide" ([FlowSeal](https://arxiv.org/html/2609.14003)).

The research problem: make the credential broker the **label authority**. It knows which tenant, repo, OAuth scope and credential produced each datum, because it minted the credential and proxied the request. It can therefore assign confidentiality (and integrity) labels deterministically, from a source the model cannot influence.

## Why it matters

- The report's conclusion: the broker "is the only component that sees every system of record, so it is the natural source of information-flow labels." That turns the lethal trifecta from advice into an enforced, analyzable rule, and no current paper or product does it.
- Labels from systems of record are principle 3 of the report's ten design principles ("Source labels from systems of record"), supported by FlowSeal and FIDES's limitations (research note 02 Q6).
- Without deterministic labels, [[Provenance-Aware Cedar]] would only move the probabilistic step from the policy to the labeller.

## State of the art

- **FlowSeal**: provenance labels from underlying systems, not model inference; a mandatory interceptor outside the LLM; 0-3.3% leakage at 72.4% benign utility; residual risk in the LLM-based declassification oracle ([arXiv](https://arxiv.org/html/2609.14003)). Its date is uncertain (the fetched page showed 12 Sep 2024, conflicting with the 2609 arXiv ID) ([[Information Flow Control]]).
- **FIDES**: confidentiality × integrity lattice; selective hiding keeps high-label results in variables; a quarantined LLM may inspect them only through schema-constrained outputs ([arXiv](https://arxiv.org/html/2505.23643)). See [[FIDES]].
- **The MVP's session labels**: `sensitive_read` flips when the session reads a private repo (visibility is known from the API the broker proxies) or uses a high-risk credential; this is already broker-derived, at session granularity ([[Trifecta Session Labels]]).
- The [[GitHub API Adapter]] classifies requests into verbs and can see repo visibility; the [[Credential Injector and Issuers]] knows each credential's scope and audience.

## Research approach (Proposal)

1. **Label derivation table.** For each issuer and adapter, define the label of a response as a function of request metadata the broker controls: GitHub (repo visibility, org, installation), AWS (account, role, S3 prefix), OAuth SaaS (tenant, scope). Example: a response from a private repo in org `acme` gets readers `{org:acme}`; a public issue body gets integrity `untrusted`.
2. **Label store.** Keep a per-session map from response fingerprints (hashes of values or normalised fragments) to labels, in broker memory, with metadata (never values) in the audit stream.
3. **Outbound check.** On every write-class request, look up labels for argument fields (see [[Provenance-Aware Cedar]]) and pass them as Cedar context; policy forbids flows where readers of the destination are not a subset of the data's readers (for example a public PR body containing `{org:acme}` data).
4. **Declassification as a capability.** Model downgrading as an explicit, audited grant (FIDES leaves declassification informal); never let an LLM declassify.
5. **Evaluate.** Replay the GitHub MCP toxic flow and GitLost-style scenarios ([[GitHub MCP Toxic Flow]]) and AgentDyn's GitHub suite; measure leakage blocked, false blocks and label-match coverage (how often a leaked value was recognised).

## How it would change the product

- The trifecta rule becomes per-datum instead of per-session, so a session that read a private README could still post an unrelated public comment.
- The audit stream gains a "which data went where" record for incident response.
- It is the concrete answer to "who annotates labels", and a publishable contribution.

## Hooks in the MVP

- Keep repo visibility, credential ID, issuer and scope digest on every audit event (already specified in [[Audit Recorder and Event Schema]]).
- Design the `CredentialIssuer` `Issued` record so its scope metadata can be attached to responses.

## How it connects

- motivated-by:: [[Information Flow Control]]
- motivated-by:: [[FIDES]]
- depends-on:: [[Credential Injector and Issuers]]
- depends-on:: [[GitHub API Adapter]]
- depends-on:: [[Trifecta Session Labels]]
- part-of:: [[Provenance-Aware Cedar]]
- mitigates:: [[GitHub MCP Toxic Flow]]

## Implications for the build

- Response-side metadata must be captured on the L7 path even when the MVP does not use it yet.
- Never store response values in the audit log; fingerprints only, and only in memory for the session.

## Open questions

- How robust value matching is to paraphrase or re-encoding by the model (an attack surface for [[Adaptive Evaluation of Deterministic Monitors]]).
- How to label data from hosts on the L4 splice path, which the broker does not decrypt.

## Sources

- Report: problem 2; "Three gaps no paper fills" bullet 2; Conclusion; audit-table row for FlowSeal.
- Research note 02 Q2 (FIDES, FlowSeal, RTBAS), Q5 and Q6 (principle 3, open problem 2).
