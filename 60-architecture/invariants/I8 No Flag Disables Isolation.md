---
title: "I8 No Flag Disables Isolation"
aliases: ["No Bypass Flags"]
type: concept
section: architecture
tags: [sandbox/architecture, concept, invariant/i8, topic/isolation, topic/approval, control/iso, control/hitl, adversary/a5, boundary/tb1, milestone/m0]
status: proposal
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "No flag (--yolo, auto-approve, dangerously-skip-permissions) can disable isolation, egress or brokering; flags only relax in-sandbox prompts."
related: ["[[Nx s1ngularity Supply-Chain Attack]]", "[[Copilot Auto-Approve Settings Write]]", "[[Adversary Classes]]", "[[Fatigue-Resistant Approval Interfaces]]", "[[Broker CLI and Daemon]]", "[[Sandbox Launcher]]", "[[OpenClaw Exposure and Token Theft]]", "[[I2 Fail-Closed Launch]]", "[[I5 Config Outside Writable Mounts]]", "[[Threat Model Overview]]", "[[M0 Contained Run]]"]
sources: ["https://www.wiz.io/blog/s1ngularity-supply-chain-attack", "https://metr.org/blog/2026-05-19-frontier-risk-report/", "https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/", "https://anthropic.com/engineering/claude-code-auto-mode", "https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/", "https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/"]
milestone: M0
---

# I8 No Flag Disables Isolation

> No flag (--yolo, auto-approve, dangerously-skip-permissions) can disable isolation, egress or brokering; flags only relax in-sandbox prompts.

## Statement

**Proposal.** For every combination of:

- `broker` CLI flags and subcommand options,
- environment variables read by `broker` or `brokerd`,
- flags passed to the wrapped agent after `--` (for example `--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`),
- agent settings files (for example an `autoApprove` key),
- user-scope and repo-scope policy,

the resulting session still has: the backend's required isolation layers ([[I2 Fail-Closed Launch]]), the broker as the only egress, broker-owned DNS, credential brokering with sentinels only, and audit. Agent flags and settings may change how often the *agent* asks its user for approval inside the sandbox; they never change what the sandbox can reach. The only way to loosen containment is an org-signed or user-scope policy change that is itself a narrowing-or-approved diff, and even that cannot turn a required layer off.

## Rationale

- **s1ngularity weaponised bypass flags.** The Nx post-install malware ran installed AI CLIs with `--dangerously-skip-permissions`, `--yolo` and `--trust-all-tools`, and "succeed[ed] in hundreds of cases" ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)). See [[Nx s1ngularity Supply-Chain Attack]].
- **Users turn controls off.** About 40% of surveyed developers gave agents unrestricted command permissions on low-stakes projects ([METR](https://metr.org/blog/2026-05-19-frontier-risk-report/)); users approve 93% of Claude Code permission prompts ([Anthropic](https://anthropic.com/engineering/claude-code-auto-mode)); OWASP lists "Overwhelming HITL" as threat T10 ([OWASP](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)). This is adversary A5 in [[Adversary Classes]].
- **Agents flip their own switches.** Copilot's agent wrote `chat.tools.autoApprove` into `.vscode/settings.json` ([Embrace The Red](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/)); see [[Copilot Auto-Approve Settings Write]].
- **A reachable sandbox toggle is an escape.** OpenClaw CVE-2026-25253 leaked a gateway token that allowed disabling the sandbox and host RCE ([Adversa](https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/)); see [[OpenClaw Exposure and Token Theft]].

The report: "never let a prompt-disabling flag weaken isolation, egress or brokering".

## How it is enforced

**Proposal.**

- [[Broker CLI and Daemon]]: the `broker run` argument parser has no option that selects "no sandbox", "no proxy", "direct network" or "pass-through credentials". Everything after `--` is passed verbatim to the agent and never interpreted by the broker.
- `SandboxSpec` construction in [[Sandbox Launcher]] takes the required-layer set from the backend, not from options; a `debug_assert!` and a release-mode check verify the invariant set before `launch()`.
- The control API has no method that disables isolation for a running session; `grant.request` can only request a specific capability, which goes through Cedar and, if widening, approval. `ctl.sock` is unreachable from sandboxes (seccomp blocks new `AF_UNIX`, SBPL denies the path), so an agent cannot call it even if it learned the protocol.
- Agent settings files are write-protected ([[I5 Config Outside Writable Mounts]]); even if an agent enables its own auto-approve by another route, that only affects in-sandbox prompts.
- Environment variables like `BROKER_*` that could alter policy are ignored; configuration comes from files outside the sandbox.

## Minimal test

**Proposal.** `tests/e2e/flag_matrix`: generate every CLI flag combination from the `clap` command definition (plus each known agent bypass flag after `--`, plus agent settings with auto-approve enabled), start a session, and assert in each case that (a) a probe `connect()` to a non-allowlisted host fails, (b) a DNS query from the sandbox fails, (c) the env contains only sentinels, and (d) the audit log has a session-start event with the full required-layer list. Any combination that loosens one of these fails CI.

## What would violate it

- A `--no-proxy`, `--insecure`, `--allow-all-network` or `--direct` option, even "for debugging".
- Honouring `HTTP_PROXY=""` as "turn off the broker".
- Detecting `--yolo` in the agent argv and switching to a "trusted" profile.
- A control-API method such as `session.set_mode("off")`.

## How it connects

- motivated-by:: [[Nx s1ngularity Supply-Chain Attack]]
- motivated-by:: [[Copilot Auto-Approve Settings Write]]
- motivated-by:: [[OpenClaw Exposure and Token Theft]]
- mitigates:: [[Adversary Classes]]
- depends-on:: [[Broker CLI and Daemon]]
- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[I2 Fail-Closed Launch]]
- part-of:: [[Fatigue-Resistant Approval Interfaces]]
- delivered-by:: [[M0 Contained Run]]

## Implications for the build

- Debugging features must be additive (more logging, `broker why`, trace capture) rather than subtractive.
- Documentation and CLI help must state that agent bypass flags do not bypass the broker, so users are not misled in either direction.
- Audit mode (`enforcement: audit` in the learning plane) still runs the sandbox and brokering; it only changes Cedar denies into logged would-denies on L7 decisions, never removes isolation or DNS control.

## Open questions

- Whether audit mode should be allowed to skip L7 denies for hosts that would otherwise be blocked entirely; the report's learning stage records "with L7 visibility on the hosts that will need credentials" but does not say whether unknown hosts are reachable in audit mode. Default: unknown hosts stay denied at L4 and are logged.

## Sources

- https://www.wiz.io/blog/s1ngularity-supply-chain-attack
- https://metr.org/blog/2026-05-19-frontier-risk-report/
- https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/
- https://anthropic.com/engineering/claude-code-auto-mode
- https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- https://adversa.ai/blog/openclaw-security-101-vulnerabilities-hardening-2026/
- Report: invariant I8, approval-fatigue paragraph, Interfaces (control socket unreachable); research note 04b Q2 design requirement.

## Build log

- 2026-09-24: tests `no_flag_disables_isolation` (every clap flag enumerated; `run` accepts only `--profile`), `i8_no_profile_flag_or_env_disables_isolation` (6 profiles × 5 agent bypass flags, plus cleared or hostile client proxy variables: direct egress and DNS still denied, every session has all required layers), `i8_unknown_profile_is_refused_not_ignored`, `i8_invalid_user_policy_refuses_launch`. Fault injection can only cause refusals.
