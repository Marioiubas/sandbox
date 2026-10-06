---
title: "ADR-046 Git Redirection and Shared Agent State Are Not Writable"
aliases: ["ADR-046"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/sandbox, invariant/i5, milestone/m4]
status: built
confidence: medium
created: 2026-10-06
updated: 2026-10-06
summary: "A session can no longer write anything that makes the user's git or another agent session run its code: `.git/commondir`, `config.worktree`, `.git/modules`, `.git/worktrees` and every nested `.git` below the repository are protected (Linux: read-only placeholders that git reads as harmless; nested repositories created during a session are renamed aside at teardown); protected names that are symlinks protect their targets; Claude Code's shared shell snapshots are add-only (macOS) or private per session (Linux), and its project state is scoped to the session's project."
related: ["[[I5 Config Outside Writable Mounts]]", "[[ADR-019 Mandatory Deny-Write List Additions]]", "[[ADR-016 macOS M0 Compatibility Exceptions]]", "[[Sandbox Launcher]]", "[[Filesystem Control and Rollback]]", "[[Claude Code and sandbox-runtime]]", "[[MOC Decisions]]"]
sources: ["https://git-scm.com/docs/gitrepository-layout", "https://git-scm.com/docs/git-config#Documentation/git-config.txt-corefsmonitor"]
superseded_by: 
---

# ADR-046 Git Redirection and Shared Agent State Are Not Writable

> The repository's git configuration and hooks are protected wherever git can be told to read them from, and agent state that other sessions execute is never changed by a session.

## Status

built (2026-10-06, M4). Found by an adversarial review of the configuration-trust paths (three High findings, verified with Apple Git 2.50.1 and Claude Code 2.1.288 on the build machine).

## Context

[[ADR-019 Mandatory Deny-Write List Additions]] protects `.git/config`, `.git/hooks` and the `.git` entry at each writable root, because repository git configuration becomes code execution outside the sandbox (`core.fsmonitor` runs on the user's next `git status`; hooks run on commit). The review showed four other ways to get git to read config and hooks the agent wrote, and one agent-state path:

1. `.git/commondir` repoints git's common directory (config, hooks) to a directory the agent creates inside `.git` ([gitrepository-layout](https://git-scm.com/docs/gitrepository-layout)).
2. `.git/modules/<name>/` (submodule git directories) and `.git/worktrees/<name>/` hold other repositories' config; the superproject's `git status` runs a child git in each submodule.
3. A nested repository (`git init sub`, or a `sub/.git` file naming a gitdir) added as a gitlink is descended into by the superproject's `git status`; ADR-019's statement that `git init` fails in the sandbox held only at the root. A planted nested repository also chose the task repository of a later session started inside it.
4. A protected name that is a symlink (`.claude -> config/claude`) protected the link, not its target, which Seatbelt and bind mounts act on.
5. Claude Code runs every Bash command as `source ~/.claude/shell-snapshots/snapshot-…sh && eval …`; the claude-code profile made that directory writable, so a sandboxed session could append to the snapshot of a concurrently running unsandboxed Claude Code session. It also made every project's `~/.claude/projects/<slug>/memory/MEMORY.md` (standing instructions) writable.

## Decision

- **Protected git paths:** `.git/commondir`, `.git/config.worktree`, `.git/modules`, `.git/worktrees` join the per-root list, and are protected inside a gitdir reached through a `.git` file too. On Linux, where bind mounts protect only what exists, missing ones get placeholders: read-only empty directories for `modules`/`worktrees`, an empty `config.worktree`, and a `commondir` containing `.`, which git resolves to the git directory itself (verified: status, commit, branch, gc, config and worktree listing behave as without it). Placeholders are removed at teardown.
- **Nested repositories:** no `.git` may be written below the repository root (`CompiledFsPolicy::nested_git`): enforced by an SBPL pattern on macOS. On Linux, nested repositories that exist at launch are protected; one created during the session cannot be refused (no pattern rules in bind mounts or Landlock), so at teardown every `.git` below the root that was not there at launch is renamed `.git.broker-quarantine-<id>` (never deleted) and named in the session's `session.stop` row (`quarantined_git`).
- **Symlinked protected names** add their resolved targets.
- **Shared agent state (`[agent] state_private`):** directories every session of an agent shares and executes from. On macOS files may be added but not changed, renamed or removed (`deny file-write-data file-write-unlink file-write-mode file-write-flags file-write-xattr`; verified with `sandbox-exec`: creating a new file with content succeeds, appending to, truncating, renaming over or deleting an existing one fails). On Linux the session gets its own empty tmpfs there. The claude-code profile uses it for `~/.claude/shell-snapshots`, and its `~/.claude/projects` grant becomes `~/.claude/projects/${cwd_slug}` (this project only).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Make all of `.git` read-only except objects, refs and logs | Git renames lock files into `.git` itself (index, HEAD, packed-refs), which needs `.git` writable. |
| Refuse new files under `.git` by default | Git creates its own working state there (`rebase-merge/`, `sequencer/`, `*.lock`). |
| `shell-snapshots` read-only | Claude Code then fails to create its snapshot, and its `source … && eval` command line fails: every Bash command breaks. Add-only keeps it working (its own snapshot is cut to the first write on macOS: no aliases or functions) and changes no other session's file. |
| Point Claude Code at a per-session config directory (`CLAUDE_CONFIG_DIR`) | Hides the user's settings, agents and memory from the session. |

## Consequences

- Inside a session: `git submodule update`, `git worktree add` and `git init` below the repository root fail; the sandboxed Claude Code's Bash tool runs without the user's aliases and shell functions on macOS.
- **Residual (Linux):** a nested repository created during a session exists until teardown, so a concurrent unsandboxed git process in the superproject (an IDE's background `git status`) could read it during the session. macOS refuses its creation.
- **Residual:** a session can still write its own project's Claude Code memory (`~/.claude/projects/<this project>/memory`), which a later unsandboxed session of the same project would load; this is the agent's own state, not another project's.

## Invariants affected

Strengthens I5. Weakens none.

## Tests

`launcher::fs_compile::tests::{review_git_commondir_cannot_redirect_config_and_hooks, review_submodule_git_directories_are_protected, review_nested_repositories_cannot_grow_hooks_or_config, review_a_symlinked_protected_name_protects_its_target, new_nested_repositories_are_quarantined_at_teardown}`, `sbpl::tests::nested_repositories_are_denied_by_pattern`, `brokerd::profiles::tests::{review_claude_code_cannot_write_other_sessions_shell_snapshots, review_claude_code_cannot_write_other_projects_memory}`, `brokerd::session_util::tests::review_a_gitdir_planted_below_the_root_does_not_choose_the_task_repository`, end to end `m0_categories::cat10_git_cannot_be_pointed_at_agent_written_config` (macOS and Linux).

## Relationships

- decided-by:: adversarial review (2026-10-06)
- extends:: [[ADR-019 Mandatory Deny-Write List Additions]]
