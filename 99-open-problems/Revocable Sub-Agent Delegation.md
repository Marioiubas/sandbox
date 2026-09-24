---
title: "Revocable Sub-Agent Delegation"
aliases: []
type: problem
section: open
tags: [sandbox/open, problem, topic/credentials, topic/identity, topic/policy, milestone/phase3, evidence/conflict, evidence/unverified]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: AUTO
related: AUTO
sources: AUTO
---

# Revocable Sub-Agent Delegation

> Membrane-style revocable delegation to sub-agents and map-reduce workers; no agent paper evaluates revocation or sub-agent attenuation.

## The problem

Agents increasingly spawn sub-agents and parallel workers. Each needs some of the parent's authority, never more, and the parent (or the human) must be able to revoke it, including everything the sub-agent derived from it. No agent paper in the record evaluates revocation or sub-agent attenuation, although Miller's caretakers and membranes give the model ([erights.org](http://www.erights.org/talks/thesis/)) (report).

The research problem: represent delegated grants so that (a) a sub-agent's authority is provably a subset of its parent's, (b) the parent or broker can revoke a sub-agent's authority and everything derived from it at once, and (c) this works when sub-agents run in separate sandboxes or on separate hosts.

## Why it matters

- "Delegation chains inherit the broadest permission unless actively narrowed" ([Start With Identity](https://startwithidentity.com/blog/agent-identity-gets-a-protocol/)); narrowing is precisely the broker's job.
- The CSA's agentic IAM proposal calls for delegation chains from the human principal to the agent to sub-agents, and a global session authority for immediate revocation ([CSA](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)).
- The design-patterns paper's Map-Reduce pattern gives natural per-item sandboxes; research note 02 proposes that Map-Reduce workers get read-only, single-item, no-egress grants ([arXiv](https://arxiv.org/html/2506.08837)). Without attenuation and revocation, that profile cannot be enforced.

## State of the art

- **Object capabilities**: authority only via held references; attenuation through forwarders, caretakers and membranes. The record summarises Miller's thesis from background knowledge; it was not re-read ([[Object Capabilities]]).
- **Macaroons**: chained-HMAC bearer credentials; any holder can append caveats but never remove them; third-party caveats need discharge macaroons ([NDSS](https://www.ndss-symposium.org/ndss2014/ndss-2014-programme/macaroons-cookies-contextual-caveats-decentralized-authorization-cloud/)).
- **Biscuit**: public-key-signed tokens with offline attenuation and Datalog authorization policies ([Biscuit](https://doc.biscuitsec.org/getting-started/introduction.html)). No evaluated use of Macaroons or Biscuit for LLM agent tool calls exists in the record ([[Macaroons and Biscuit]]).
- **Token exchange**: RFC 8693 carries `subject_token`, `actor_token` and a nested `act` claim for delegation ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)); Transaction Tokens carry an immutable `tctx` context across workloads in one trust domain ([draft-08](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens-08)).
- **Products**: Keycard advertises delegation chaining that stops sub-agents exceeding their parent, and credentials revoked at session end ([Keycard](https://www.keycard.ai/blog/announcing-keycard-for-coding-agents/)); see [[Agent Identity Brokers]]. No evaluation is published.
- **The MVP's grant**: Cedar entities in the broker on one laptop; a Txn-Token-shaped, DPoP-bound JWT with a nested `act` chain across hosts ([[Internal Grant JWT]], [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]).

> [!warning] Conflict
> Biscuit timing: the report's internal-grant section defers Biscuit "to phase 2", while its later-phases paragraph puts Biscuit-based sub-agent delegation in phase 3. [[MVP Plan]] follows phase 3.

## Research approach (Proposal)

1. **Membrane in the broker.** Model each sub-agent as a child `Task` entity whose grants are a subset of the parent's, with a `parent` attribute. Revocation is a data update: mark the parent or child revoked, and a Cedar forbid denies every request from any descendant (`principal in` a revoked ancestor). This is a membrane implemented as entity hierarchy, with no token recall needed on one host.
2. **Proof of attenuation.** At delegation time, run `check_implies(P_child, P_parent)` in [[SymCC CI Gates]] style online; reject any delegation that is not a narrowing.
3. **Cross-host delegation.** For sub-agents on other hosts, issue attenuated grants (Biscuit with Datalog caveats, or a nested-`act` Txn-Token) sender-constrained with DPoP ([[DPoP and mTLS-Bound Tokens]]); short TTLs plus a revocation list checked by the broker bound the window.
4. **Execution-mode profiles.** Define default child profiles for the design-pattern modes (Map-Reduce worker: read-only, single-item, no egress).
5. **Evaluate.** Multi-agent scenarios where a compromised worker tries to use authority beyond its item, or keeps acting after revocation; measure attempted-vs-blocked actions, time-to-revoke, and overhead. Compare entity-based membranes, nested-`act` JWTs and Biscuit.

## How it would change the product

- Multi-agent coding workflows (planner plus workers) could run under the broker with provably attenuated worker grants.
- Revocation would become a first-class operation in the control API and audit stream.
- It would resolve the phase-2/phase-3 Biscuit question with evidence.

## Hooks in the MVP

- The grant JWT's nested `act` chain already records agent and sandbox identity under the user ([[Internal Grant JWT]]).
- Grants as entities make revocation a data update with no policy recompile ([[Broker Cedar Schema]]).

## How it connects

- motivated-by:: [[Object Capabilities]]
- depends-on:: [[Macaroons and Biscuit]]
- motivated-by:: [[Design Patterns for Securing LLM Agents]]
- contrasts-with:: [[Agent Identity Brokers]]
- decided-by:: [[ADR-008 Grant Representation as Entities and Txn-Token JWT]]
- depends-on:: [[Internal Grant JWT]]
- depends-on:: [[SymCC CI Gates]]

## Implications for the build

- Keep the `Task` entity able to carry a parent reference even if the MVP never sets it.
- Do not bake single-level delegation assumptions into `grant` crate APIs.

## Open questions

- How the broker detects that an agent spawned a sub-agent at all when both run inside one sandbox (process tree vs logical agent).
- Whether online SymCC checks are fast enough at delegation time.

## Sources

- Report: problem 6; "Three gaps no paper fills" bullet 3; internal grant section; later phases.
- Research note 02 Q1 inference and Q6 problem 6.
- Research note 04b Q3 (CSA delegation chains and global session authority); research note 03 Q3 (Keycard delegation chaining).
