---
title: "Claude Code Path and Command Injection CVEs"
aliases: ["CVE-2025-54794", "CVE-2025-54795", "InversePrompt"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/filesystem, topic/isolation, control/fs, control/iso, control/audit, adversary/a1, boundary/tb2, milestone/m0, platform/macos, platform/linux]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "A naive path-prefix working-directory check (CVE-2025-54794) and command injection through an allowlisted echo (CVE-2025-54795) bypassed Claude Code's string-based controls."
related: [AUTO]
sources: [AUTO]
---

# Claude Code Path and Command Injection CVEs

Two 2025 Claude Code vulnerabilities, reported together by Cymulate as "InversePrompt", showed that string-based controls in the agent are not a boundary. The working-directory restriction used a naive prefix check, so a sibling directory with the same prefix passed; and command injection through an allowlisted command such as `echo` bypassed the approval prompt ([Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/)). The design answer is to enforce the filesystem boundary in the kernel, so the agent's own path and command logic is never load-bearing.

## Timeline

- **2025**: both reported by Elad Beber (Cymulate) ([Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/)).
- **CVE-2025-54794**: CVSS 7.7, fixed in v0.2.111.
- **CVE-2025-54795**: CVSS 8.7, fixed in v1.0.20.

## What happened

- **CVE-2025-54794, path prefix.** The restriction to the working directory compared path strings by prefix. Illustratively, a directory `/work/project-evil` passes a check for `/work/project` because the string starts the same way ([Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/)).
- **CVE-2025-54795, command injection.** An allowlisted, auto-approved command (for example `echo`) could be given input that injected additional commands, which then ran without the approval prompt ([Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/)).

Both are instances of the third recurring shape, bugs in the enforcement layer itself, which appeared at least seven times in 13 months across four vendors ([[Threat Model Overview]]).

## Root cause

- **(f) parser flaw in the enforcement layer**: path strings compared without canonicalisation; command strings approved by name.
- Adversary **A1** (the injected instruction chooses the path or the command).
- Boundary TB2 was implemented in user space by string matching rather than by the kernel.

## Impact

Reads or writes outside the intended directory and command execution without approval, reachable by prompt injection. Fixed; no in-the-wild exploitation reported in the record.

## Stopping control in this design

- **Would have prevented: kernel-enforced FS.** On macOS a generated Seatbelt profile denies writes except to the repo and tmp and denies reads of secret directories ([[Seatbelt]]); on Linux bubblewrap mounts only the granted paths writable and [[Landlock]] enforces path rules on file descriptors, not strings ([[Sandbox Launcher]], [[Filesystem Control and Rollback]]). A sibling directory with a matching prefix is simply not mounted writable.
- **Would have made the command allowlist non-load-bearing: ISO.** Whatever command runs, it runs inside the sandbox with no secrets and no network except the broker. Command approval becomes a UX feature, not a security control.
- **AUDIT** logs denied filesystem operations where the backend reports them.

**Proposal.** The broker never implements its own path-prefix authorisation for filesystem access. Where the broker must reason about paths (policy compilation, `fs.*` Cedar actions), it canonicalises through the single canonicaliser and compiles to kernel rules; the kernel decides.

## Regression test

[[Conformance Probe Matrix]] **category 10 (filesystem)**, required for [[M0 Contained Run]]:

- sibling-prefix directories (`<repo>-x`, `<repo>..`), `..` traversal, symlinks and hardlinks pointing outside the grant, and rename TOCTOU: all writes fail at the kernel;
- reading `~/.ssh/id_ed25519` is denied;
- shell metacharacters in arguments to commands the agent considers safe do not change what the sandbox permits (the probe asserts the side effect is still confined).

## How it connects

- mitigated-by:: [[Filesystem Control and Rollback]]
- mitigated-by:: [[Sandbox Launcher]]
- mitigated-by:: [[Landlock]]
- mitigated-by:: [[Seatbelt]]
- example-of:: [[Claude Code and sandbox-runtime]]
- part-of:: [[Threat Model Overview]]
- evaluated-by:: [[Risk Register]]

## Implications for the build

- Linux path rules are literal, so deny-globs miss files created after start; prefer allow-lists of writable roots over deny-lists.
- Unit-test the SBPL and bwrap/Landlock compilers against sibling-prefix and symlink cases, not only the runtime.
- Treat any user-space path check in the broker as defense in depth only.

## Open questions

- None specific to this incident.

## Sources

- [Cymulate, CVE-2025-54794 / CVE-2025-54795](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/)
