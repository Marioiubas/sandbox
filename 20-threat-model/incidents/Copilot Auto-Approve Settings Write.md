---
title: "Copilot Auto-Approve Settings Write"
aliases: ["CVE-2025-53773", "Copilot YOLO Mode"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/filesystem, topic/approval, control/fs, control/hitl, control/audit, adversary/a1, boundary/tb5, boundary/tb1, invariant/i5, invariant/i8, milestone/m0]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Agent mode could write chat.tools.autoApprove into .vscode/settings.json without approval, enabling YOLO mode and arbitrary command execution after an injection (CVE-2025-53773)."
related: [AUTO]
sources: [AUTO]
---

# Copilot Auto-Approve Settings Write

GitHub Copilot's agent mode in VS Code could write `"chat.tools.autoApprove": true` into the workspace's `.vscode/settings.json` without asking, which switched on "YOLO mode" and let every subsequent command run without approval. A prompt injection could therefore first disable the approval gate and then execute arbitrary commands ([Embrace The Red](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/)). It is the canonical case of an agent editing its own policy, the reason [[I5 Config Outside Writable Mounts]] exists.

## Timeline

- **29 Jun 2025**: reported by Johann Rehberger (Embrace The Red) ([Embrace The Red](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/)).
- **Aug 2025**: patched in the August Patch Tuesday release ([CVE record](https://www.cve.org/CVERecord?id=CVE-2025-53773)).

## What happened

1. Injected content (in a file, web page or tool output) reached Copilot agent mode.
2. The agent edited `.vscode/settings.json`, a file inside the writable workspace, adding the auto-approve setting. File edits in the workspace did not require approval.
3. With auto-approve on, the agent could run terminal commands without prompts, giving arbitrary code execution on the developer's machine ([Embrace The Red](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/)).

MITRE ATLAS added AML.T0081 Modify AI Agent Configuration for exactly this technique ([Zenity Labs](https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of)).

## Root cause

- **(d) missing filesystem boundary**: the agent could write its own permission configuration.
- **(g) approval-gate design**: the gate could be switched off from inside the thing it gates.
- Adversary **A1**. Boundaries TB5 (workspace config) and TB1 (approval).

## Impact

Remote code execution on developer machines via prompt injection. Patched.

## Stopping control in this design

- **Would have prevented: FS ([[I5 Config Outside Writable Mounts]]).** Agent configuration paths (`.vscode/`, `.claude/`, `.cursor/`, `.codex/`), hooks and MCP manifests are read-only inside the sandbox, and the configuration the agent obeys is supplied by the broker from outside every writable mount after content-hash approval ([[Filesystem Control and Rollback]]).
- **Would have made the gate irrelevant: [[I8 No Flag Disables Isolation]].** Even if an agent's in-sandbox approval setting were flipped, it relaxes only in-sandbox prompts; isolation, egress and credential brokering are unaffected. Commands still run with no secrets and only brokered egress.
- **HITL cannot be switched off from inside.** **Proposal.** Approvals that matter (widenings, irreversible verbs) are broker approvals rendered as authority diffs ([[Fatigue-Resistant Approval Interfaces]]), and no file in the sandbox can pre-approve them.
- **AUDIT** logs the denied write attempt.

## Regression test

- **Category 10 (filesystem)**, required for [[M0 Contained Run]]: from inside the sandbox, attempts to create or modify each known agent-config path, git hooks and `.git/config` fail at the kernel and are logged.
- **Flag and setting matrix**: with every agent's auto-approve setting forced on, the sandbox and proxy remain on and a probe to a non-allowlisted host is still denied.

## How it connects

- mitigated-by:: [[I5 Config Outside Writable Mounts]]
- mitigated-by:: [[I8 No Flag Disables Isolation]]
- mitigated-by:: [[Filesystem Control and Rollback]]
- mitigated-by:: [[Fatigue-Resistant Approval Interfaces]]
- part-of:: [[Threat Model Overview]]

Siblings where the agent rewrote its own tool config: [[Cursor CurXecute and MCPoison]].

## Implications for the build

- VS Code-hosted agents are not in the MVP profile list, but the read-only config set must be extensible per agent profile and include `.vscode/settings.json` when an IDE agent is wrapped.
- Protecting only `.git/hooks` and `.git/config` (not all of `.git`) keeps local commits working while blocking hook-based execution in the user's next unsandboxed git command.

## Open questions

- None specific to this incident.

## Sources

- [Embrace The Red, CVE-2025-53773](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/)
- [CVE record](https://www.cve.org/CVERecord?id=CVE-2025-53773)
- [Zenity Labs / MITRE ATLAS](https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of)
