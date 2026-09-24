---
title: "ADR-019 Mandatory Deny-Write List Additions"
aliases: ["ADR-019"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/isolation, control/fs, boundary/tb2, boundary/tb5, invariant/i5, milestone/m0]
status: built
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Extend the mandatory deny-write list with the .git entry itself (a rename-and-replant escape found while building M0), .mcp.json, .envrc, .gemini, .broker and PATH directories inside writable roots, and give missing protected names read-only placeholders on Linux."
related: ["[[I5 Config Outside Writable Mounts]]", "[[Filesystem Control and Rollback]]", "[[Sandbox Launcher]]", "[[Seatbelt]]", "[[bubblewrap]]", "[[Conformance Probe Matrix]]", "[[MOC Decisions]]"]
sources: []
superseded_by:
code: ["code/crates/launcher/src/fs_compile.rs", "code/crates/launcher/src/backends/linux/bwrap.rs", "code/crates/launcher/src/backends/seatbelt/sbpl.rs"]
---

# ADR-019 Mandatory Deny-Write List Additions

> Protect the `.git` entry itself and more authority-bearing names, and cover missing names on Linux with placeholders.

## Status

Built (2026-09-24). [[I5 Config Outside Writable Mounts]] requires an ADR for any change to the mandatory list.

## Context

The report protects `.git/hooks` and `.git/config` rather than all of `.git`, so the agent can still commit ([[Filesystem Control and Rollback]]). Testing that rule on macOS 26.5 found an escape: with only those two paths protected, `mv .git .gitx` succeeds, and writing a `.git` **file** containing `gitdir: .gitx` makes the renamed directory the repository, whose `hooks/` and `config` are no longer protected. The user's next unsandboxed `git` would run attacker hooks. Separately:

- Claude Code loads project MCP servers from `.mcp.json`; direnv executes `.envrc` on `cd`; Gemini CLI reads `.gemini/`; repository broker policy lives in `.broker/` (I4, I5). None were on the list.
- A PATH directory inside the repository (for example `./bin` on PATH) lets the agent plant a binary the user's shell runs later.
- On Linux, bwrap can only re-bind paths that exist, so a protected name that does not exist yet could be created by the agent (found by conformance category 10 on Linux: `.mcp.json` was writable).

## Decision

1. Deny writes to the **entry** `${root}/.git` (rename, unlink, replace) while its contents stay writable: SBPL `(deny file-write* (literal …/.git))`; on Linux `.git` is bound onto itself, and a mountpoint cannot be renamed or removed.
2. Add `.mcp.json`, `.envrc`, `.gemini` and `.broker` to the per-root list, next to `.git/hooks`, `.git/config`, `.claude`, `.codex`, `.cursor`, `.vscode` and `.idea`.
3. Add every PATH directory that lies inside a writable root.
4. For worktrees and submodules (`.git` is a file), protect the file, the resolved gitdir's `hooks` and `config`, and the common dir's.
5. On Linux, every protected name missing from the repository gets an empty read-only placeholder directory for the session (including `.git` in a directory that is not a repository), removed at teardown.

**Testable as:** `cat10_filesystem` (writes to every protected name denied; `rename .git`, rename over `.git/config`, hardlink and symlink tricks denied; no placeholder left behind), `cat10_non_repo_directory_cannot_grow_git_hooks`, `fs_compile::tests::*` including the property test `mandatory_never_writable`.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Protect all of `.git` (Codex) | Breaks local commits, which the broker's push design relies on |
| Only check hooks at push time | Hooks run on the user's next local git command, not only on push |
| Create empty placeholder *files* on Linux | An empty `.mcp.json` left behind by a crash is invalid JSON for the agent; an empty directory is ignored |

## Consequences

`git init` inside the sandbox fails in a directory that is not already a repository. On Linux a crash can leave empty placeholder directories in the repository.

## Invariants affected

Strengthens [[I5 Config Outside Writable Mounts]].

## Relationships

- motivated-by:: [[I5 Config Outside Writable Mounts]]

## Build log

- 2026-09-24: created and built with M0; the rename-and-replant escape is reproduced (and blocked) in `cat10_filesystem`.
