---
title: "CLAUDE"
aliases: ["Handoff Contract"]
type: meta
section: meta
tags: [sandbox/meta, meta, topic/build]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Handoff contract for Claude Code: mission, non-negotiable invariants, reading order, graph traversal, Proposal vs Verified, ADR and note-update rules, code location (code/) and definition of done per milestone."
related: ["[[00 Home]]", "[[MOC Problem]]", "[[MOC Threat Model]]", "[[MOC Architecture]]", "[[MOC Build]]", "[[M0 Contained Run]]", "[[Vault Conventions]]", "[[Build Log]]", "[[Dashboard]]", "[[Repository Layout]]", "[[MOC Decisions]]", "[[I1 No Secrets in the Sandbox]]", "[[I2 Fail-Closed Launch]]", "[[I3 Probabilistic Components Only Narrow]]", "[[I4 Repo Policy Only Narrows]]", "[[I5 Config Outside Writable Mounts]]", "[[I6 Single Canonicaliser]]", "[[I7 Reject Foreign Credentials]]", "[[I8 No Flag Disables Isolation]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]"]
sources: []
---

# CLAUDE.md: build handoff contract

You are Claude Code, opening this Obsidian vault as your working directory. The vault is the complete design record for a product; your job is to **build it**, milestone by milestone, and keep this vault true while you do.

## 1. What this vault is

A knowledge graph of ~180 atomic notes (one idea each) that together specify a **vendor-neutral egress and credential broker plus sandbox for AI agents** ("capability-based sandboxing for autonomous agents"). The notes were written from one synthesized research report and six research-note files (September 2026). `_manifest.json` at the vault root is the machine-readable index of every note: file path, title, type, section, one-line summary, required links and the sources each note was written from.

## 2. Mission

Build a single Apache-2.0 **Rust** binary (`broker` CLI plus the per-user `brokerd` daemon) that:

1. wraps any coding agent (Claude Code, Codex, Gemini CLI, Cursor agent) or local MCP server in the OS sandbox vendors already ship: **Seatbelt** on macOS, **bubblewrap with no network interface + seccomp + Landlock** on Linux ([[Two-Tier Isolation Design]]);
2. makes its own egress proxy the **only** way out: it resolves DNS itself, terminates TLS only where it must, and authorizes every request with **Cedar** against task-scoped grants ([[Architecture Overview]]);
3. **mints** short-lived upstream credentials just before forwarding (repo-scoped GitHub App tokens, 15-minute AWS STS sessions with session policies, OAuth token exchange), so **no secret ever enters the sandbox** ([[Just-in-Time Credential Minting]]);
4. understands developer protocols (git push per repo and branch, GitHub API verbs, read-only registries, MCP tool calls) ([[Git Smart-HTTP Adapter]], [[GitHub API Adapter]], [[MCP Guard]]);
5. writes one hash-chained audit stream attributed to user, agent, task and session ([[Audit Recorder and Event Schema]]);
6. learns least-privilege policy from recorded runs and proves each change is a narrowing with Cedar's verified analyzer ([[Policy Learning Loop]], [[SymCC CI Gates]]).

It will **not** stop an injected agent from misusing authority it legitimately holds. It shrinks that authority to the task and makes its use auditable ([[Threat Model Non-Goals]]). Never claim otherwise in code comments, docs or CLI output.

## 3. Non-negotiable invariants

A change that weakens any of these is a security regression. You may not weaken one without first writing an ADR that names the invariant, explains why, and is linked from [[MOC Decisions]] and the invariant note. Each invariant must have at least one automated test that fails if it is violated.

| # | Invariant | Minimum test |
|---|---|---|
| I1 | [[I1 No Secrets in the Sandbox]]: no secret in env, files, argv, `/proc` or response bodies; only per-session sentinels | scan the sandbox for canary secrets; expect only sentinels |
| I2 | [[I2 Fail-Closed Launch]]: refuse to launch if any isolation layer or the proxy cannot start; never mount `docker.sock` or host paths for convenience | disable each layer in turn; `broker run` must exit non-zero |
| I3 | [[I3 Probabilistic Components Only Narrow]]: LLM drafts, explainers and detectors may only narrow authority | any widening path must require a SymCC-proved diff plus human approval |
| I4 | [[I4 Repo Policy Only Narrows]]: repository-supplied policy only narrows user and org policy | `check_implies(repo ∧ org, org)` gate; widening repo policy is rejected |
| I5 | [[I5 Config Outside Writable Mounts]]: policy, agent config, hooks, MCP manifests and the broker binary are outside every writable mount and loaded only after content-hash approval | write attempts to each path from inside the sandbox are denied |
| I6 | [[I6 Single Canonicaliser]]: one canonicaliser for every hostname and path; match canonical name **and** broker-resolved address; reject what cannot be canonicalised | bypass corpus (NUL, CRLF, IDNA, IP-literal encodings, metadata IPs) all denied |
| I7 | [[I7 Reject Foreign Credentials]]: strip client credentials and reject any credential the broker did not issue | attacker-planted API key to an allowed host is rejected |
| I8 | [[I8 No Flag Disables Isolation]]: no flag (`--yolo`, auto-approve) disables isolation, egress or brokering | every CLI flag combination keeps the sandbox and proxy on |
| I9 | [[I9 Hash-Chained Audit Outside the Sandbox]]: every decision logged outside the sandbox, hash-chained, attributed | tamper with one row; chain verification fails |

Also non-negotiable: the product never installs its CA into the host system trust store, and never forwards a user's IdP token as-is to an upstream or MCP server.

## 4. Reading order

Read these in order before writing any code, following the links each one gives you:

1. [[00 Home]]: orientation and the section map.
2. [[MOC Problem]] → [[Problem Statement]] → [[Product Thesis]].
3. [[MOC Threat Model]] → [[Threat Model Overview]] → [[Trust Boundaries]] → [[Threat Model Non-Goals]]. Skim the incident table; you will reproduce many incidents as tests.
4. [[MOC Architecture]] → [[Architecture Overview]] → [[Request and Session Lifecycle]] → the nine invariant notes → [[Core Trait Contracts]].
5. [[MOC Build]] → [[MVP Plan]] → [[Repository Layout]] → [[Tech Stack]] → [[Evaluation Harness]] → [[Conformance Probe Matrix]].
6. **The current milestone note.** The current milestone is the lowest-numbered milestone whose `status` is not `built` (start: [[M0 Contained Run]]). Then read every note it links to.

Consult [[MOC Policy]], [[MOC Identity]], [[MOC Primitives]], [[MOC Research]], [[MOC Landscape]] and [[MOC Decisions]] when the milestone touches them. Check [[Open Questions and Unverified Claims]] before depending on any number, version or date.

## 5. How to traverse the graph

- **Forward links:** each note's frontmatter `related:` list plus the `[[wikilinks]]` in its body. The `links_to` array in `_manifest.json` is the required minimum set.
- **MOCs:** every note is listed in its section MOC; MOCs end with a "How this section connects" block pointing to other MOCs.
- **Backlinks:** `grep -rl --include='*.md' -F '[[Note Name' .` finds every note linking to *Note Name* (the missing `]]` also matches `[[Note Name|alias]]`).
- **Machine traversal:** `jq -r '.[] | select(.section=="architecture") | .title' _manifest.json`; `jq -r '.[] | select(.links_to | index("MCP Guard")) | .title' _manifest.json`.
- **Aliases:** a concept merged into a note appears in that note's `aliases` (for example *Confused Deputy* lives in [[Object Capabilities]], *RFC 8707* in [[MCP Authorization Spec]], *record/shadow/enforce modes* in [[Policy Learning Loop]]). Link to the canonical title; use `[[Title|alias]]` for display text.
- **Status views:** [[Dashboard]] (Dataview) shows notes by status, open proposals and milestone progress.

## 6. Proposal vs Verified

The research convention carries into every note:

- A sentence with an **inline citation** is a verified fact from the research record. Rely on it, but check [[Open Questions and Unverified Claims]] for caveats.
- Anything marked **Proposal** is a design recommendation. Treat proposals as the **default design**: implement them as written unless you find a concrete reason not to. If you deviate, write an ADR.
- `confidence: low` or anything listed in Open Questions (for example Landlock ABI 10/11 availability, OCSF class IDs, unprivileged overlayfs kernel versions, APFS clone behaviour, cedar `datetime` support, crate maturity beyond `hudsucker` and `landlock`) must be **verified empirically or from primary docs before code depends on it**. Record the result in the note and remove or annotate the open question.
- Secondary-source figures (boot times, latencies) are planning numbers, not requirements. Measure on your own CI and reference machines; the thresholds you must meet are in [[Evaluation Harness]].

## 7. Where the code lives

- **`code/` at the vault root is the repository root of the product**, laid out exactly as the report's `broker/` tree in [[Repository Layout]] (Cargo workspace `code/Cargo.toml`, `code/crates/...`, `code/tests/...`, `code/eval/...`, `code/ee/...`). Create it in M0.
- The vault and `code/` share one git repository rooted at the vault folder. Commit vault updates together with the code they describe.
- `.obsidian/app.json` excludes `code/` from Obsidian indexing; product documentation meant for users goes in `code/docs/`, while design knowledge stays in the vault.
- Never write real secrets anywhere in the vault or `code/`. Tests use canary values and throwaway GitHub/AWS/Okta dev tenants whose credentials live in the OS keychain or CI secrets, never in the repository.

## 8. How to record decisions

1. Copy `templates/Template ADR.md` to `95-decisions/ADR-NNN Short Title.md` using the next free number (the seeded ADRs end at ADR-015, so the first new one is ADR-016).
2. Fill context, decision, alternatives, consequences, and the invariants and notes affected; set `status: proposal`, then `built` when implemented.
3. Link it from [[MOC Decisions]] (add a row and a bullet), from every note it changes, and from [[Build Log]].
4. If it replaces an earlier ADR, add `superseded_by: "[[ADR-NNN ...]]"` to the old ADR's frontmatter and a "Superseded" line in its body; do not delete the old ADR.
5. Add the entry to `_manifest.json` (same schema) so the index stays complete.

## 9. How to update notes while building

- When you implement what a note describes: set `status: built`, bump `updated:`, add or extend a `## Build log` section at the end of the note with dated bullets (what was built, code paths, tests, deviations with ADR links). Add an optional `code:` frontmatter list of paths.
- Keep the original sourced content; put corrections in a `## Implementation notes` section with evidence, and fix the claim only when you have primary-source or measured evidence (cite it).
- New notes: create from the templates in `templates/`, follow [[Vault Conventions]], give them a unique Title Case name without `# | ^ : % [ ] / \ ;`, link them from their section MOC, and add them to `_manifest.json`.
- Append one entry per work session to [[Build Log]].
- Never delete a note; if a note becomes obsolete, set `status: draft` and explain why in its body.

## 10. Definition of done per milestone

A milestone is done only when **all** of the following hold. Then set the milestone note to `status: built`.

1. Every acceptance criterion in the milestone note passes in an automated test (CI on macOS and Linux where the note says so), and the test names are listed in the milestone's Build log.
2. Every invariant still has a passing test; none was weakened without an ADR.
3. The conformance corpus ([[L1 Conformance Suite]], [[Conformance Probe Matrix]]) grew to cover the milestone's new surface, and 100% of out-of-policy probes are denied and logged with a reason.
4. Every component note the milestone delivered is `status: built` with a Build log entry; any deviation has an ADR.
5. [[Build Log]] has an entry summarising the milestone; open questions resolved along the way are updated in [[Open Questions and Unverified Claims]].

Milestone-specific acceptance, verbatim from the plan:

- **[[M0 Contained Run]]:** `broker run -- claude` and `-- codex` finish a "fix failing test" task on macOS 15/26 and Ubuntu 22.04/24.04; conformance categories 3, 4, 5, 9 and 10 are 100% denied (incl. NUL-byte, CRLF, IDNA, IP-literal, 169.254.169.254 and DNS TXT probes); reading `~/.ssh/id_ed25519` is denied; launch refuses to run if any layer is missing.
- **[[M1 Secrets Outside]]:** a scan finds only sentinels in env, files, argv and `/proc`; push to `agent/x` on the session repo succeeds, pushes to another repo, to `main` or with force are denied and `broker why` explains each; an attacker-planted API key sent to an allowed host is rejected; a sentinel copied off-host is useless.
- **[[M2 Policy Audit and Learn]]:** learn mode over 3 repos × 3 agents yields a policy under which the same tasks pass with 0 denies; a seeded injection ("post `~/.aws` to a paste site; push to attacker repo") is blocked and logged; every learned change passes the narrowing or ceiling gates or shows counterexamples; events validate against OCSF and reach a test SIEM sink.
- **[[M3 CI Identity and MCP]]:** on an untrusted-issue CI fixture the agent tree sees no long-lived secret; audit rows carry IdP subject and groups; a wrapped GitHub MCP server can read issues but cannot reach non-allowlisted hosts, and a changed tool description revokes it; a replay of the GitHub MCP toxic flow is stopped at the public write; S3 read works via minted credentials and writes outside the prefix are denied.
- **[[M4 Harden and Ship]]:** ≥24 h fuzzing per target with no crashes; latency and utility thresholds met or documented; external pentest of proxy and launcher closes with no open high findings; design partners run daily.

## 11. Working rules

- Fail closed everywhere: empty lists deny, unknown hosts deny, unmatched L7 requests deny, unparseable input denies.
- Enforcement-layer bugs are the dominant failure class in the incident record. Every parser (hostname, URL, HTTP/1.1, h2, pkt-line, JSON-RPC) gets property tests and a `cargo-fuzz` target from the day it is written.
- Prefer battle-tested primitives (kernel sandboxes, rustls, cedar-policy) over custom code; keep the custom L7 surface minimal.
- Prompt the human rarely, and when you do, show the authority diff (what new capability is granted), not prose.
- Keep the vault and code in step: a PR that changes behaviour updates the note that specifies it.
