---
title: "00 Home"
aliases: ["Home", "Index"]
type: moc
section: meta
tags: [sandbox/meta, moc]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Top index: one-paragraph orientation, the Start-here path and links to every section MOC and meta note."
related: ["[[CLAUDE]]", "[[MOC Problem]]", "[[MOC Threat Model]]", "[[MOC Research]]", "[[MOC Primitives]]", "[[MOC Identity]]", "[[MOC Architecture]]", "[[MOC Policy]]", "[[MOC Landscape]]", "[[MOC Build]]", "[[MOC Decisions]]", "[[MOC Open Problems]]", "[[Vault Conventions]]", "[[Glossary]]", "[[Bibliography]]", "[[Dashboard]]", "[[Open Questions and Unverified Claims]]", "[[Build Log]]"]
sources: []
---

# Home: capability-based sandboxing for autonomous agents

> **Own the broker, borrow the sandbox.** Build a vendor-neutral, Apache-2.0 Rust broker that wraps any coding agent or local MCP server in the OS sandbox vendors already ship, makes its own egress proxy the only way out, authorizes every request with Cedar against task-scoped grants, and mints short-lived upstream credentials just before forwarding, so no secret ever enters the sandbox.

## Orientation

Autonomous coding agents run with the developer's ambient authority (SSH keys, `gh` and npm tokens, cloud profiles, model keys) while reading content anyone can write. Every in-band prompt-injection defense tested adaptively was broken; nearly every 2025-2026 incident combined untrusted input, a broad standing credential and an open or "allowed" outbound channel; and the isolation primitives are mature and cheap. Proxy-side secret injection is already commodity. What nobody offers neutrally, and what this product owns, is one policy and one audit stream across all agents, credential **minting** bound to user, agent, repo and task, semantic rules for developer protocols (git push per branch, GitHub API verbs, read-only registries), and a record-then-restrict loop that proves each policy change is a narrowing. The plan is a 10-week, fail-closed MVP for 2-3 engineers. It will not stop an injected agent from misusing authority it legitimately holds; it shrinks that authority to the task and makes its use auditable.

## Start here

1. [[CLAUDE]]: the build contract (invariants, rules, definition of done). **Claude Code: read this first.**
2. [[MOC Problem]]: why the product exists.
3. [[MOC Threat Model]]: what we defend against, and what we do not.
4. [[MOC Architecture]]: the nine invariants, components, interfaces and data flow.
5. [[MOC Build]]: the plan, milestones and evaluation harness; then the current milestone, starting with [[M0 Contained Run]].

## Sections

| Section | MOC | What it holds |
|---|---|---|
| 10 Problem | [[MOC Problem]] | engineering requirement, thesis, market context |
| 20 Threat model | [[MOC Threat Model]] | assets, adversaries A1-A6, trust boundaries TB1-TB7, non-goals, 24 incidents |
| 30 Research | [[MOC Research]] | foundations, adaptive-attack record, audited defenses, benchmarks, ten design principles |
| 40 Primitives | [[MOC Primitives]] | Seatbelt, bubblewrap, Landlock, seccomp, microVMs, gVisor, WASI, egress topology, filesystem control |
| 50 Identity | [[MOC Identity]] | provider downscoping, IETF token standards, Okta/Entra flows, MCP authorization, sentinels vs minting |
| 60 Architecture | [[MOC Architecture]] | invariants, components, interfaces, request lifecycle, deployment modes |
| 70 Policy | [[MOC Policy]] | Cedar, schema, example policies, trifecta labels, SymCC gates, policy learning |
| 80 Landscape | [[MOC Landscape]] | competitor teardowns and the gap to own |
| 90 Build | [[MOC Build]] | tech stack, repo layout, MVP plan, milestones M0-M4, evaluation L1-L6, red team, risks |
| 95 Decisions | [[MOC Decisions]] | ADR-001 to ADR-015 |
| 99 Open problems | [[MOC Open Problems]] | eight research problems and the measurement gaps |

## Meta

- [[Vault Conventions]]: frontmatter schema, types, tags, status and confidence values, link semantics.
- [[Glossary]]: every term of art, linked to its note.
- [[Bibliography]]: every source URL, grouped by topic, with the notes that use it.
- [[Dashboard]]: Dataview views of status, proposals, open problems, ADRs and milestones.
- [[Open Questions and Unverified Claims]]: what must be checked before code depends on it.
- [[Build Log]]: Claude Code's running log of the build.
- `_manifest.json`: machine-readable index of every note. `templates/`: note templates.
