---
title: "Nx s1ngularity Supply-Chain Attack"
aliases: ["s1ngularity", "Nx Attack"]
type: incident
section: threat
tags: [sandbox/threat, incident, topic/supply-chain, topic/credentials, topic/egress, topic/isolation, control/iso, control/egress, control/cred-out, adversary/a2, adversary/a5, boundary/tb6, boundary/tb7, platform/ci, invariant/i1, invariant/i8, milestone/m0, milestone/m3]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Malicious nx packages drove locally installed AI CLIs with --yolo-style flags to hunt secrets, leaked 1,000+ GitHub tokens and ~20,000 files, then made 5,500+ private repos public (Aug 2025)."
related: [AUTO]
sources: [AUTO]
---

# Nx s1ngularity Supply-Chain Attack

Malicious versions of the `nx` build system were published to npm through a stolen publish token, and their post-install script ran the victim's locally installed AI coding CLIs with permission prompts disabled by flag, using them as "living-off-the-land" reconnaissance tools to find secrets. The results were uploaded to public GitHub repositories created with the victim's own `gh` credentials. It is the clearest case for why no flag may disable isolation, why package installs must run sandboxed without credentials, and why standing tokens on disk are the crown jewels.

## Timeline

- **26 Aug 2025**: malicious versions of 8 packages (for example `nx` 21.5.0–21.8.0 and 20.9.0–20.12.0) published to npm; live for about 4 hours ([Nx postmortem](https://nx.dev/blog/s1ngularity-postmortem)).
- **28–29 Aug 2025**: phase 2 made 5,500+ private repositories public across 400+ users and organisations ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)).

## What happened

1. **Entry via CI.** A GitHub Actions `pull_request_target` workflow echoed unsanitised PR titles (injection), ran with read/write default permissions and allowed workflow dispatch; the attacker obtained the npm publish token this way ([Nx postmortem](https://nx.dev/blog/s1ngularity-postmortem)).
2. **Publish.** Malicious package versions went to npm.
3. **Post-install.** The malware scanned for secrets and "attempted to use local AI tools (like Claude and Gemini)" ([Nx postmortem](https://nx.dev/blog/s1ngularity-postmortem)). It ran installed AI CLIs (Claude, Gemini, Q) with `--dangerously-skip-permissions`, `--yolo` and `--trust-all-tools`, and "succeed[ed] in hundreds of cases, although AI provider guardrails at times interceded" ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)).
4. **Exfiltration.** Results were uploaded to public GitHub repos the malware created using the victim's `gh` credentials.
5. **Phase 2.** Stolen tokens were used to make private repos public.

Nx remediated with npm Trusted Publishers (OIDC), manual 2FA approval for releases, no pipeline runs for external contributors, and provenance checks ([Nx postmortem](https://nx.dev/blog/s1ngularity-postmortem)).

## Root cause

- **(e) supply chain** + **(b) standing credentials** (`gh`, npm and cloud credentials on disk) + **(c) unrestricted egress** to github.com.
- Adversary **A2** (malicious publisher), exploiting **A5** behaviour: prompt-disabling flags exist and are honoured.
- Two boundaries failed: TB7 (PR title next to publish credentials) and TB6 (package install hook).

## Impact

Over 1,000 valid GitHub tokens, dozens of cloud credentials and npm tokens, and about 20,000 files leaked; 5,500+ private repositories made public ([Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)).

## Stopping control in this design

- **Would have prevented the harvest: ISO for installs.** `npm install` and its hooks run inside the sandbox, where `~/.config/gh`, `~/.aws`, `~/.ssh` and wallet files are unreadable ([[Sandbox Launcher]], [[Two-Tier Isolation Design]]).
- **Would have prevented the AI-CLI abuse: [[I8 No Flag Disables Isolation]].** When an agent CLI runs under the broker, `--yolo` and equivalents may relax in-sandbox prompts only; they cannot disable isolation, egress or brokering. The agent finds no secrets because none are in the sandbox ([[I1 No Secrets in the Sandbox]]).
- **Would have prevented exfiltration: EGRESS.** Deny-by-default brokered egress: no repository creation on api.github.com unless granted, and pushes only to the task repo ([[Topology-Forced Egress]]).
- **Would have prevented the entry: CI mode.** **Proposal.** The broker holds runner OIDC in CI and the job never holds a long-lived publish token ([[M3 CI Identity and MCP]]).

A caveat: the design only covers AI CLIs launched through the broker. Malware that runs outside the broker on an unprotected host can still read files on that host; the protection comes from the credentials not being on disk in the clear (keychain-held roots) and from installs being sandboxed.

## Regression test

- **Flag matrix**: for each supported agent, every combination of prompt-disabling flags (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`, auto-approve settings) still yields a sandboxed process with the proxy on (I8's minimum test).
- **Category 2 / 10**: a scripted "post-install" inside the sandbox searches common credential paths and env vars; it finds only sentinels.
- **Category 1**: creating a new repository or pushing to a non-task repo on github.com is denied.
- **M3 fixture**: an untrusted-PR CI job shows no long-lived secret in the agent tree.

## How it connects

- mitigated-by:: [[I8 No Flag Disables Isolation]]
- mitigated-by:: [[I1 No Secrets in the Sandbox]]
- mitigated-by:: [[Sandbox Launcher]]
- mitigated-by:: [[Topology-Forced Egress]]
- mitigated-by:: [[Two-Tier Isolation Design]]
- evaluated-by:: [[M3 CI Identity and MCP]]
- example-of:: [[Adversary Classes]]
- part-of:: [[Threat Model Overview]]

## Implications for the build

- Agent profiles must parse and neutralise each vendor's prompt-disabling flags only at the prompt layer; the launcher ignores them.
- Provide a `broker run -- npm install` path (or equivalent) so dependency installs are sandboxed like agents.
- Registries are read-only by default; `publish` requires an explicit grant ([[Registry and LLM API Adapters]]).

## Open questions

- No post-mortem confirms whether any s1ngularity victim had an OS sandbox enabled; the effect of sandboxing is inferred ([[Open Questions and Unverified Claims]]).

## Sources

- [Nx postmortem](https://nx.dev/blog/s1ngularity-postmortem)
- [Wiz, s1ngularity](https://www.wiz.io/blog/s1ngularity-supply-chain-attack)
