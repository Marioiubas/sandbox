---
title: "MOC Problem"
aliases: []
type: moc
section: problem
tags: [sandbox/problem, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Why this product exists: the engineering requirement, the thesis and the market context."
related: ["[[Problem Statement]]", "[[Product Thesis]]", "[[MOC Threat Model]]", "[[MOC Research]]", "[[MOC Landscape]]", "[[00 Home]]"]
sources: []
---

# MOC Problem

> Why this product exists: the engineering requirement, the thesis and the market context.

This section answers *why build anything at all*. Coding agents run with the developer's ambient authority while reading content anyone can write, and no model-side defense survives adaptive attack. The product therefore does not try to make the model trustworthy; it shrinks and audits what a hijacked agent can do. Read [[Problem Statement]] first, then [[Product Thesis]] for what the team should own and why the market will pay for it.

Reading convention inherited from the report: a sentence with an inline citation is a verified fact; anything marked **Proposal** is a design recommendation. See [[Vault Conventions]].

## Core notes

- [[Problem Statement]] — Assume the agent's intent can be hijacked; remove ambient authority (SSH keys, gh/npm tokens, cloud profiles, model keys, DB roles) and hand back only task-scoped, short-lived, audited capabilities through a policy point the agent cannot reconfigure.
- [[Product Thesis]] — Own the broker, borrow the sandbox: a vendor-neutral Apache-2.0 Rust broker that owns one policy and audit stream, per-task credential minting, developer-protocol semantics and verified policy learning, while reusing OS sandboxes; includes market context from the scoreboard.

## How this section connects

- The requirement is made concrete by the [[MOC Threat Model]] (assets, adversaries, the seven trust boundaries and 24 incidents).
- The evidence that in-band defenses fail lives in [[MOC Research]], starting at [[The Attacker Moves Second]].
- Why the value sits in the broker rather than a new sandbox is argued in [[MOC Landscape]] ([[Gap Analysis]]) and recorded as [[ADR-001 Value Lives in the Broker]].
- What gets built, in what order, is in [[MOC Architecture]] and [[MOC Build]].
