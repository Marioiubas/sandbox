---
title: "Gemini CLI Prefix Allowlist Bypass"
aliases: ["Gemini CLI Incident"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/isolation, topic/approval, control/iso, control/egress, control/audit, control/hitl, adversary/a1, boundary/tb1, boundary/tb2, boundary/tb5, invariant/i2, milestone/m0]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Gemini CLI's command allowlist matched only the prefix, whitespace hid the payload in the UI, context files were an injection vector and the OS sandbox was off by default (Jul 2025)."
related: [AUTO]
sources: [AUTO]
---

# Gemini CLI Prefix Allowlist Bypass

Tracebit showed that Gemini CLI's command allowlist matched only the prefix of a command line, so a malicious command chained after an allowlisted one ran silently; whitespace could push the malicious part out of view in the approval UI; README.md and GEMINI.md context files delivered the injection; and Gemini CLI's OS sandboxing options were off by default ([Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)). Three root causes stacked. The design answer is that isolation is on by default and the launch fails closed, which makes any command allowlist non-load-bearing.

## Timeline

- **27 Jun 2025**: reported by Tracebit.
- **25 Jul 2025**: fixed in Gemini CLI v0.1.14. Google rated it P1/S1 ([Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)).

## What happened

1. A repository contained a context file (README.md or GEMINI.md) with injected instructions, which Gemini CLI loads into context.
2. The injection made the agent run a command beginning with an allowlisted command, followed by a chained malicious command.
3. The allowlist check matched only the prefix, so the whole line ran without a prompt.
4. Padding with whitespace hid the malicious tail from the user in the UI.
5. Google noted that its sandboxing options (Docker/Podman/Seatbelt) were off by default, so nothing contained the result ([Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)).

## Root cause

- **(f) parser flaw in the enforcement layer** (prefix matching of command strings);
- **(a) untrusted input** (context files);
- **(g) approval-gate design** (the UI did not render ground truth);
- plus an insecure default: OS isolation off.
- Adversary **A1**. Boundaries TB1, TB2, TB5.

## Impact

Silent arbitrary command execution on opening and working in a malicious repository. Fixed.

## Stopping control in this design

- **Would have prevented the damage: ISO on by default ([[Two-Tier Isolation Design]]).** Under the broker every agent runs in the OS sandbox; there is no "off" setting. Whatever command line runs, it has no secrets, only kernel-limited filesystem access and only brokered egress. The command allowlist becomes a UX convenience, not a boundary.
- **Would have prevented a degraded launch: [[I2 Fail-Closed Launch]].** If any isolation layer or the proxy cannot start, `broker run` exits non-zero. Contrast Claude Code, which by default warns and runs unsandboxed unless `sandbox.failIfUnavailable` is set ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)).
- **Would have contained: EGRESS and AUDIT.** Exfiltration from the chained command hits the deny-by-default proxy and is logged.
- **TB1: render ground truth.** **Proposal.** Where the broker prompts at all, it renders the exact action or authority diff with control characters and excess whitespace made visible, never a model summary ([[Fatigue-Resistant Approval Interfaces]]).

## Regression test

- **I2 test**: disable each isolation layer in turn (Seatbelt unavailable, bwrap missing, Landlock unsupported, proxy port busy); `broker run` must exit non-zero every time.
- **Containment probe**: inside the sandbox, a scripted "allowlisted command; malicious command" chain attempts a secret read and an outbound request; both are denied at the kernel and the proxy.
- **Approval rendering unit test**: an approval string containing long whitespace runs, ANSI escapes or Unicode bidi characters is rendered with them visible.

## How it connects

- mitigated-by:: [[I2 Fail-Closed Launch]]
- mitigated-by:: [[Two-Tier Isolation Design]]
- mitigated-by:: [[Fatigue-Resistant Approval Interfaces]]
- example-of:: [[Cursor and Gemini CLI]]
- part-of:: [[Threat Model Overview]]
- evaluated-by:: [[Risk Register]]

## Implications for the build

- The Gemini CLI profile must launch it under the broker's sandbox regardless of Gemini's own sandbox setting.
- `broker doctor` reports which layers are available; `broker run` never offers a "continue without sandbox" option.
- Context files (README, AGENTS.md, GEMINI.md, CLAUDE.md) are untrusted input; reading one of a public repo flips `untrusted_input` ([[Trifecta Session Labels]]).

## Open questions

- None specific to this incident.

## Sources

- [Tracebit](https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack)
- [Claude Code sandboxing docs](https://code.claude.com/docs/en/sandboxing)
