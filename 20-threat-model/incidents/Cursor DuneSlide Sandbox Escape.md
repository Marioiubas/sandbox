---
title: "Cursor DuneSlide Sandbox Escape"
aliases: ["DuneSlide", "CVE-2026-50548", "CVE-2026-50549"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/filesystem, topic/isolation, control/iso, control/fs, control/audit, adversary/a1, boundary/tb2, invariant/i5, milestone/m0, evidence/secondary, evidence/single-source]
status: verified
confidence: low
created: 2026-09-24
updated: 2026-09-24
summary: "A working_directory pointing at ~/.zshrc or the sandbox helper, and a symlink-check fallback, let writes escape Cursor's sandbox (CVE-2026-50548/50549, fixed Apr 2026)."
related: [AUTO]
sources: [AUTO]
---

# Cursor DuneSlide Sandbox Escape

"DuneSlide" is a pair of Cursor sandbox escapes. One set a command's `working_directory` to a sensitive location, such as the sandbox helper binary or `~/.zshrc`, which the sandbox then allowed writes to; the other used a fallback taken when a symlink check failed to write outside the project. Either could be triggered by injected instructions from MCP or web content ([The Hacker News](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)). The lesson: the sandbox's own helper and the user's shell startup files must sit outside every writable mount, and filesystem rules must be enforced by the kernel on resolved objects, not by path strings with fallbacks.

## Timeline

Per The Hacker News only ([The Hacker News](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)):

- **19 Feb 2026**: reported by Cato AI Labs.
- **2 Apr 2026**: fixed in Cursor 3.0.
- **1 Jul 2026**: disclosed. Both CVEs rated CVSS 9.8.

> [!question] Unverified
> CVE numbers and dates come from a single secondary source; the Cursor security advisory was not fetched.

## What happened

- **`working_directory` escape.** A command could be launched with its working directory set to a sensitive path. The sandbox derived its writable set from that directory, so writes to the sandbox helper or to `~/.zshrc` were permitted.
- **Symlink fallback.** When a symlink check failed, the implementation fell back to behaviour that allowed writing outside the project.

Either primitive gives persistence (a modified `~/.zshrc` runs in the user's next unsandboxed shell) or control over the sandbox itself (a modified helper binary) ([The Hacker News](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)).

## Root cause

- **(f) enforcement-layer flaw** (writable set derived from an attacker-influenced parameter; unsafe fallback on check failure) plus **(d) missing filesystem boundary** around the helper and rc files.
- Adversary **A1** (injected instructions choose the working directory or plant the symlink). Boundary TB2.
- One of the "at least seven in 13 months" enforcement-layer bugs across four vendors ([[Threat Model Overview]]).

## Impact

Sandbox escape and persistence on developer machines, triggerable by prompt injection. Fixed in Cursor 3.0.

## Stopping control in this design

- **Would have prevented: helper outside every writable mount ([[I5 Config Outside Writable Mounts]]).** The broker binary, sandbox helpers, policy and agent config are never inside a writable mount, whatever working directory a command asks for.
- **Would have prevented: kernel FS rules fixed at launch.** The writable set is compiled once from the Cedar `fs.*` grants into SBPL, or bwrap mounts plus [[Landlock]] rules, before the agent starts ([[Sandbox Launcher]]). A later command's `working_directory` cannot widen it, because the kernel enforces the mounts and Landlock rules on the whole process tree.
- **Would have prevented: fail closed on check failure.** **Proposal.** Any path that cannot be canonicalised or resolved is denied, never passed through a fallback ([[I2 Fail-Closed Launch]] applied to per-operation checks).
- **Rc files and git hooks** are outside the default writable set; `.git/hooks` and `.git/config` are mounted read-only ([[Filesystem Control and Rollback]]).
- **AUDIT** records denied writes where the backend reports them.

## Regression test

[[Conformance Probe Matrix]] **category 10 (filesystem)**, required for [[M0 Contained Run]]:

- attempt writes to `~/.zshrc`, `~/.bashrc`, `~/.profile`, git hooks, agent config and the broker/helper binaries, directly, via `..`, via symlinks and hardlinks created inside the workspace, and via rename races: all denied at the kernel;
- start subprocesses with a working directory set to each of those locations: the writable set is unchanged;
- simulate a failing symlink resolution: the operation is denied, not retried with a weaker check.

## How it connects

- mitigated-by:: [[Filesystem Control and Rollback]]
- mitigated-by:: [[I5 Config Outside Writable Mounts]]
- mitigated-by:: [[Landlock]]
- mitigated-by:: [[Sandbox Launcher]]
- example-of:: [[Cursor and Gemini CLI]]
- evaluated-by:: [[Risk Register]]

## Implications for the build

- Never derive sandbox permissions from per-command parameters supplied by the agent; the policy is per session.
- Install the broker and helpers in locations outside `$HOME` write grants, and verify their hash at launch.
- Fuzz and property-test the path canonicaliser used by the policy compiler ([[I6 Single Canonicaliser]]).

## Open questions

- Single secondary source for CVE numbers and dates ([[Open Questions and Unverified Claims]]).
- Unprivileged overlayfs and APFS clone behaviour, relevant to rollback modes that would further limit damage, are unverified.

## Sources

- [The Hacker News, Jul 2026](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)
