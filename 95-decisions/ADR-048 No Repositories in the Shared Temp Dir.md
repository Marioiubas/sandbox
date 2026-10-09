---
title: "ADR-048 No Repositories in the Shared Temp Dir"
aliases: ["ADR-048"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/sandbox, invariant/i5, invariant/i4, milestone/m4]
status: built
confidence: medium
created: 2026-10-09
updated: 2026-10-09
summary: "On macOS a session may not create a `.git` anywhere in the per-user temp dir (`DARWIN_USER_TEMP_DIR`, writable to every session under ADR-016) outside its own roots there. Otherwise a later session the user starts in a scratch directory takes its task repository, and with it push rules, GitHub verbs and App token scope, from a file an earlier agent wrote. `repo_root` also ignores a `.git` another user owns."
related: ["[[ADR-046 Git Redirection and Shared Agent State Are Not Writable]]", "[[ADR-016 macOS M0 Compatibility Exceptions]]", "[[I5 Config Outside Writable Mounts]]", "[[I4 Repo Policy Only Narrows]]", "[[Sandbox Launcher]]", "[[Seatbelt]]", "[[Broker CLI and Daemon]]", "[[Risk Register]]", "[[MOC Decisions]]"]
sources: ["https://github.blog/2022-04-12-git-security-vulnerability-announced/"]
superseded_by: 
---

# ADR-048 No Repositories in the Shared Temp Dir

> No session can plant a repository where a later session would take it for its task repository.

## Status

built (2026-10-09, M4). Found by the host-side review of 2026-10-09; its test failed before the change and passes after it.

## Context

The daemon chooses a session's task repository by walking up from the working directory to the nearest `.git` (`brokerd::session_util::repo_root`). The repository's `origin` remote fills `${repo_remote}`: push rules, GitHub API verbs and the repositories a GitHub App token is minted for. [[ADR-046 Git Redirection and Shared Agent State Are Not Writable]] stopped a session planting a `.git` below its own repository root. On macOS, though, every session may write the per-user temp dir (the `$TMPDIR` that `mktemp -d` uses), because Apple toolchain shims reset `TMPDIR` to it ([[ADR-016 macOS M0 Compatibility Exceptions]], R16). A session could write `<T>/tmp.Qx81/.git/config` naming any repository the user's App installation covers. A later session the user starts in `<T>/tmp.Qx81` would then be scoped to that repository. The walk also took a `.git` without asking who owns it, although git itself refuses a repository another user owns ([CVE-2022-24765](https://github.blog/2022-04-12-git-security-vulnerability-announced/)).

## Decision

- **Rule (`CompiledFsPolicy::scratch_git`):** no path with a `.git` component anywhere under the per-user temp dir, top level included, except inside the session's own writable roots there. Those roots are its `TMPDIR` (`broker-<id>`) and the repository, when the user started the session in the temp dir; the repository keeps ADR-046's own rule. The SBPL rule order is:
  1. deny `<T>/(.+/)?\.git(/|$)`;
  2. allow the session's own roots in `<T>`;
  3. the repository's nested-repository deny (ADR-046);
  4. the add-only deny for shared agent state, moved after the allow so that the allow cannot undo it.
- **Ownership:** `repo_root` treats a `.git` owned by another user as no repository (the session runs without a task repository).
- **Linux:** unchanged. A Linux session has no shared writable temp dir (`platform_tmp` is macOS-only).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Stop `repo_root` at the temp dir | The planted `.git` is below the temp dir's top level, so the walk still finds it before stopping. |
| Accept a repository only if `.git` is owned by the user | Every session runs as the user, so the planted file is the user's too. Kept only as a second check, for files of other users. |
| Deny `.git` in the whole temp dir, own `TMPDIR` included | Test suites and build tools `git init` in temporary directories, and `mktemp` puts those in the session's own `TMPDIR`. |

## Consequences

- Inside a macOS session, a tool that ignores `TMPDIR` and creates a repository directly in the per-user temp dir gets EPERM. The denial is on the audit record (kernel denial, [[ADR-041 Kernel Denials on the Audit Record]]).
- **Residual:** other directories that several sessions may write (agent state granted by a profile, for example `~/.claude`) can still hold a planted repository. A session the user starts inside one of them would take its task repository from it. These are not places users start sessions; this is noted in the [[Risk Register]] (R16).
- **Residual:** a repository planted before this change stays in place.

## Invariants affected

Strengthens I5 (no file a session writes configures a later session) and I4 (the task repository, which scopes repository policy, comes from the user). Weakens none.

## Tests

- `launcher::fs_compile::tests::no_repository_in_the_shared_temp_dir_outside_own_roots`
- `launcher::backends::seatbelt::sbpl::tests::shared_scratch_repositories_are_denied_before_the_repository_rule`
- the reviewer's `brokerd::session_util::tests::review_a_gitdir_planted_in_the_shared_temp_dir_does_not_choose_the_task_repository` (failed before)
- end to end on macOS: `m0_categories::cat10_no_repository_in_the_shared_temp_dir`. A scratch repository and a `.git` file are refused, and `git init` in the session's `TMPDIR` works.

## Relationships

- decided-by:: host-side review (2026-10-09)
- extends:: [[ADR-046 Git Redirection and Shared Agent State Are Not Writable]]
- motivated-by:: [[ADR-016 macOS M0 Compatibility Exceptions]]

## Build log

- 2026-10-09: built. Code: `code/crates/launcher/src/fs_compile.rs` (`scratch_git`), `code/crates/launcher/src/backends/seatbelt/sbpl.rs` (rule order), `code/crates/brokerd/src/session_util.rs` (`repo_root` ownership check). Tests as above.
