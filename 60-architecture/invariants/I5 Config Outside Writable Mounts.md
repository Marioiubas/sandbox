---
title: "I5 Config Outside Writable Mounts"
aliases: ["Config Out of Reach"]
type: concept
section: architecture
tags: [sandbox/architecture, concept, invariant/i5, topic/filesystem, control/fs, control/pin, boundary/tb5, boundary/tb6, milestone/m0]
status: proposal
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Policy, agent config, hooks, MCP manifests and the broker binary sit outside every writable mount and are loaded only after content-hash approval."
related: ["[[MCP Guard]]", "[[Filesystem Control and Rollback]]", "[[Copilot Auto-Approve Settings Write]]", "[[Cursor CurXecute and MCPoison]]", "[[Cursor DuneSlide Sandbox Escape]]", "[[Control Plane and Policy Bundles]]", "[[Sandbox Launcher]]", "[[Codex CLI Project Config Autoload]]", "[[Claude Code Pre-Trust Config Execution]]", "[[I4 Repo Policy Only Narrows]]", "[[Broker CLI and Daemon]]", "[[Conformance Probe Matrix]]", "[[M0 Contained Run]]", "[[ADR-012 MCP Servers as Pinned Sandboxed Principals]]"]
sources: ["https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/", "https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison", "https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html", "https://github.com/advisories/GHSA-xrxf-jgv3-qmrm", "https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md", "https://github.com/anthropic-experimental/sandbox-runtime", "https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of"]
milestone: M0
---

# I5 Config Outside Writable Mounts

> Policy, agent config, hooks, MCP manifests and the broker binary sit outside every writable mount and are loaded only after content-hash approval.

## Statement

**Proposal.** Define the *authority-bearing file set* as:

- broker policy (bundles, `broker.toml`, `.cedar` files, entity data) and the approval store;
- agent configuration and permission settings (`.claude/`, `.cursor/`, `.codex/`, `.vscode/settings.json`, Gemini settings, and equivalents in built-in [[Broker CLI and Daemon|profiles]]);
- git hooks and `.git/config` (hooks, `core.fsmonitor`, `core.sshCommand` and filter drivers execute in the user's next unsandboxed git command);
- MCP server manifests and configuration;
- shell rc files and PATH directories;
- the broker binary, `brokerd`, and every helper binary the launcher executes (seccomp helper, stub `broker mcp connect`).

Two properties must hold for every session:

1. **Not writable.** No path in the set is inside any writable mount of any sandbox, and kernel-enforced rules deny writes (including via rename, symlink, hardlink and `..` traversal).
2. **Hash-approved before use.** `brokerd` reads workspace-supplied items in the set only after the user or org approved that exact content hash; a changed hash is treated as unapproved and ignored until re-approved.

## Rationale

The agent changing its own policy is a recurring class; research note 04b lists writes to `.vscode/settings.json`, `.cursor/mcp.json`, `.claude/settings.json`, shell rc files and the sandbox helper.

- Copilot CVE-2025-53773: the agent wrote `"chat.tools.autoApprove": true` into `.vscode/settings.json`, enabling "YOLO mode" ([Embrace The Red](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/)); see [[Copilot Auto-Approve Settings Write]].
- Cursor CurXecute and MCPoison: the agent could write `.cursor/mcp.json`, and approval was "bound by the MCP name not its contents" ([Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)); see [[Cursor CurXecute and MCPoison]].
- Cursor DuneSlide: `working_directory` and symlink fallback allowed writes to `~/.zshrc` and the sandbox helper ([The Hacker News](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)); see [[Cursor DuneSlide Sandbox Escape]].
- Codex CVE-2025-61260: project-local config auto-loaded without confirmation ([GHSA](https://github.com/advisories/GHSA-xrxf-jgv3-qmrm)); see [[Codex CLI Project Config Autoload]].
- MITRE ATLAS added AML.T0081 Modify AI Agent Configuration and AML.T0083 Credentials from AI Agent Configuration ([Zenity Labs](https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of)).

Precedents: Codex re-binds `.git`, the resolved gitdir and `.codex` read-only ([codex linux-sandbox](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)); srt always write-denies `.bashrc`, `.zshrc`, `.gitconfig`, `.vscode/`, `.idea/`, `.claude/` ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).

## How it is enforced

**Proposal.**

- [[Sandbox Launcher]] compiles a mandatory deny-write list that no policy layer can remove: shell rc files, `.git/hooks`, `.git/config`, agent settings directories, and the broker install and state directories. The report protects `.git/hooks` and `.git/config` rather than all of `.git`, because the agent still needs to commit locally; the broker performs the push. On Linux these are re-bound read-only (bwrap) and covered by Landlock; on macOS they are SBPL deny rules.
- The broker binary and helpers live in the install prefix, which is never mounted writable; `brokerd` state (bundles, approval store, audit DB, CA keys) lives in a per-user directory that is not mounted into any sandbox at all.
- [[MCP Guard]]: MCP servers are defined only in user or org config; the agent's MCP config points at `broker mcp connect <name>`, so rewriting `mcp.json` "buys an attacker nothing". Tool manifests are hashed; any change revokes grants.
- Content-hash approval: `brokerd` keeps `approvals.db` rows `(scope, path, sha256, approved_by, approved_at)`. At `session.start` it hashes `.broker/*` and profile-relevant agent config; unapproved content is ignored and reported. Approval UI shows the full content diff, not a name.
- Linux deny-globs are literal at start ([srt](https://github.com/anthropic-experimental/sandbox-runtime)), so the deny list is expressed as parent-directory rules plus Landlock rather than expanded globs ([[Filesystem Control and Rollback]]).

## Minimal test

**Proposal.** Probe category 10 of the [[Conformance Probe Matrix]], `tests/conformance/fs_config`: from inside the sandbox attempt, for each path in the set, direct write, `rename` over it, create a symlink in a writable dir pointing at it and write through it, hardlink, `..` traversal, and a rename TOCTOU race. Every attempt must be denied by the kernel and appear in the audit log. Then modify `.broker/broker.toml` from outside and start a session: the modified policy must not load until re-approved.

## What would violate it

- Binding `$HOME` writable, or placing the broker helper in `${tmp}` or the repo.
- Approving MCP servers or repo config by name or path rather than by hash.
- Letting the agent run `broker` subcommands that modify policy (the control socket is unreachable from the sandbox; see [[Broker CLI and Daemon]]).
- Reading agent config from inside the sandbox on behalf of the broker.

## How it connects

- motivated-by:: [[Copilot Auto-Approve Settings Write]]
- motivated-by:: [[Cursor CurXecute and MCPoison]]
- motivated-by:: [[Cursor DuneSlide Sandbox Escape]]
- motivated-by:: [[Codex CLI Project Config Autoload]]
- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[Filesystem Control and Rollback]]
- depends-on:: [[MCP Guard]]
- depends-on:: [[Control Plane and Policy Bundles]]
- evaluated-by:: [[Conformance Probe Matrix]]
- delivered-by:: [[M0 Contained Run]]
- decided-by:: [[ADR-012 MCP Servers as Pinned Sandboxed Principals]]

## Implications for the build

- The mandatory deny-write list is code, not configuration; changing it needs an ADR.
- The approval store and bundle cache must be outside every mount on every backend, including future VM backends where virtiofs shares are configured.
- [[I4 Repo Policy Only Narrows]] relies on this: repo policy that is not hash-approved is simply absent.

## Open questions

- Files created after sandbox start that match a deny pattern are not covered by literal Linux bind rules; Landlock plus fanotify or a FUSE layer is suggested in research note 01 but not designed.
- Which agent-config paths each vendor reads is version-dependent; profiles must be maintained per agent release.

## Sources

- https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/
- https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison
- https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html
- https://github.com/advisories/GHSA-xrxf-jgv3-qmrm
- https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md
- https://github.com/anthropic-experimental/sandbox-runtime
- https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of
- Report: invariant I5, `.git/hooks` Proposal, MCP guard section; research notes 04b Q1-Q3 and 01 Q6.

## Build log

- 2026-09-24: tests `cat10_filesystem` (writes to `.git/hooks`, `.git/config`, `.claude/`, `.mcp.json`, `.vscode/`, `.envrc`, `.codex/`, `.broker/`, `.cursor/`, rename of `.git`, rename over `.git/config`, hardlink and symlink tricks all denied), `cat10_non_repo_directory_cannot_grow_git_hooks`, `i5_repository_policy_is_never_loaded_in_m0`. The mandatory list was extended by [[ADR-019 Mandatory Deny-Write List Additions]]. Broker state, config, runtime and binaries are outside every writable root and masked; the content-hash approval store arrives with repo policy in M2.
