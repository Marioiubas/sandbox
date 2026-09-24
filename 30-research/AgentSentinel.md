---
title: "AgentSentinel"
aliases: ["eBPF Backstop"]
type: paper
section: research
tags: [sandbox/research, paper, topic/isolation, topic/audit, platform/linux, control/iso, control/audit, invariant/i9, milestone/phase2]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "CCS 2025 eBPF and LSM tracing with hybrid rule and LLM audit: 79.6% defense success at 10.8% FPR; adopt a kernel-level backstop for telemetry, never the primary decision point."
related: ["[[Two-Tier Isolation Design]]", "[[Claude Code DNS Exfiltration CVE-2025-55284]]", "[[The Attacker Moves Second]]", "[[Local Credential Proxies]]", "[[Sandbox Launcher]]", "[[Audit Recorder and Event Schema]]", "[[I3 Probabilistic Components Only Narrow]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[seccomp-bpf]]", "[[Landlock]]", "[[bubblewrap]]", "[[Broker DNS Resolver]]"]
sources: ["https://dl.acm.org/doi/10.1145/3719027.3765064", "https://arxiv.org/html/2509.07764v1", "https://zenodo.org/records/16688500", "https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/", "https://github.com/strongdm/leash", "https://github.com/anthropic-experimental/sandbox-runtime"]
---

# AgentSentinel

AgentSentinel watches a computer-use agent from the kernel. It traces process, filesystem and network events with eBPF and LSM hooks, suspends sensitive events, and has them audited by a mix of rules and an LLM. It defended 79.6% of attacks on its new BadComputerUse benchmark, but with a **10.8% false-positive rate**, far too high for a decision point in daily use. The broker adopts the idea as a **backstop**: kernel-level telemetry under tool- and network-level mediation, catching what the primary layer misses, never the layer that decides.

## Citation

- Hu, Chen, Zhao, Chen. "AgentSentinel". ACM CCS 2025; arXiv 2509.07764 ([ACM DL](https://dl.acm.org/doi/10.1145/3719027.3765064); [arXiv HTML](https://arxiv.org/html/2509.07764v1)).
- Code and results: [Zenodo](https://zenodo.org/records/16688500).

## Mechanism

From the paper ([arXiv HTML](https://arxiv.org/html/2509.07764v1)):

1. **Tracing.** eBPF plus LSM hooks on **16 system probes** covering process, filesystem and network activity of the agent's process tree.
2. **Suspension.** Sensitive events are held pending an audit decision instead of being allowed or denied immediately.
3. **Hybrid audit.** Rule-based checks decide the clear cases; an LLM auditor handles the rest, with a security query cache to avoid re-asking.

```text
kernel event (exec | open | connect | ...) from agent tree
   └─ eBPF/LSM probe → sensitive?  no → allow
                                   yes → suspend → rules decide?  yes → allow/deny
                                                                 no  → LLM auditor (cached) → allow/deny
```

(Illustrative of the pipeline above.)

## Threat model and assumptions

- **Attacker:** manipulates a computer-use agent (for example through injected content) into harmful system operations: reading or exfiltrating sensitive files, running malicious processes, opening network connections ([arXiv HTML](https://arxiv.org/html/2509.07764v1)).
- **Trusted:** the kernel and the eBPF/LSM instrumentation, the rule set, and the audit service, all outside the agent's control.
- **Assumed:** the sensitive events that matter are visible as syscall-level events on the 16 probes, and the agent's process tree is fully traced (the authors note nested child processes may escape).
- **Not addressed:** semantic intent above the syscall (which repo, which API verb) and data flow through allowed channels.
- **Adaptive attacks:** 17 of 20 defended, reported by the authors.

## Evidence

- New benchmark **BadComputerUse**: 60 scenarios in 7 categories, with an 87% average baseline attack success rate ([arXiv HTML](https://arxiv.org/html/2509.07764v1)).
- AgentSentinel: **79.6%** defense success, **10.8%** false-positive rate, **4.2%** false-negative rate ([arXiv HTML](https://arxiv.org/html/2509.07764v1)).
- **17 of 20** adaptive attacks defended ([arXiv HTML](https://arxiv.org/html/2509.07764v1)).

## Counter-evidence and weaknesses

Stated limitations ([arXiv HTML](https://arxiv.org/html/2509.07764v1)):

- False positives on legitimate privileged package installs (exactly what coding agents do all day).
- Audit latency from suspending events.
- Nested child processes may escape tracing.

From the research audit: a 10.8% FPR is too high for production; the LLM auditor is probabilistic, and [[The Attacker Moves Second]] shows such components fall to adaptive attackers; eBPF and LSM give *visibility* but not semantic intent (a `connect()` to `api.github.com:443` says nothing about which repo is being pushed to).

## Where the probabilistic part lives

The LLM auditor, for events the rules do not decide. In this design an LLM judge may only narrow (deny, flag) and never allow what policy denies ([[I3 Probabilistic Components Only Narrow]]).

## Why a backstop still matters

The primary layer in this product is the broker: topology forces all traffic through it and Cedar decides each request. Tool-level mediation has historically missed channels. In Claude Code CVE-2025-55284, auto-approved `ping`, `nslookup`, `dig` and `host` commands encoded secrets in DNS queries; the fix removed them from the allowlist ([Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)). The research inference is that the DNS CVE is exactly the kind of gap a kernel-level backstop catches ([[Claude Code DNS Exfiltration CVE-2025-55284]]). The design closes that particular channel structurally (no UDP/53 in the sandbox; [[Broker DNS Resolver]]), but the lesson generalises: keep an independent layer that sees syscalls, not just requests.

The field already has one precedent. StrongDM Leash combines a container with an eBPF monitor and Cedar policy over file, process and network events, although it forwards API keys into the agent ([Leash](https://github.com/strongdm/leash); [[Local Credential Proxies]]). Separately, Linux bubblewrap has no built-in violation reporting; sandbox-runtime suggests `strace` ([sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)), which leaves an observability gap on Linux that eBPF could fill.

## Adopt / Improve / Add

- **Adopt:** **Proposal:** a kernel-level (eBPF/LSM) backstop layer under the capability layer, for **telemetry and detection**, not as the primary decision point. Principle 9 in the report: keep a kernel backstop under tool-level mediation.
- **Improve:** **Proposal:** make the backstop deterministic and deny-only: rules derived from the same session grants (allowed paths, the single egress socket), so any `connect()` other than to the broker bridge, or any write outside granted paths, is a high-signal alert with near-zero false positives, rather than an LLM judgement. Kernel enforcement itself stays with seccomp and Landlock ([[seccomp-bpf]], [[Landlock]], [[bubblewrap]]) launched by the [[Sandbox Launcher]].
- **Add:** **Proposal:** feed backstop events into the same hash-chained audit stream as broker decisions, attributed to user, agent, task and session ([[Audit Recorder and Event Schema]], [[I9 Hash-Chained Audit Outside the Sandbox]]), so a "sandbox attempted X, broker never saw it" row is visible to the SIEM.

## How it connects

- contrasts-with:: [[Local Credential Proxies]]
- part-of:: [[Two-Tier Isolation Design]]
- depends-on:: [[Audit Recorder and Event Schema]]

[[The Attacker Moves Second]] classifies AgentSentinel as hybrid (LLM auditor). The DNS incident it would have caught is [[Claude Code DNS Exfiltration CVE-2025-55284]].

## Implications for the build

- MVP: not in M0–M4 scope; the MVP relies on seccomp, Landlock, bwrap and Seatbelt for enforcement. Keep an event type for kernel-level observations in the audit schema so a backstop can be added without a schema break.
- Never let a backstop's LLM (if one is ever added) override a Cedar deny or grant anything.
- The Linux violation-reporting gap (no bwrap reporting) is worth an explicit design note when the audit recorder is built.

## Open questions

- eBPF requires privileges that an unprivileged per-user daemon does not have; how a laptop deployment would load probes is not in the record.
- Measured overhead and false-positive rate of a grant-derived, deny-only backstop on coding workloads: no data.

## Sources

- [AgentSentinel, ACM DL](https://dl.acm.org/doi/10.1145/3719027.3765064); [arXiv HTML](https://arxiv.org/html/2509.07764v1); [Zenodo](https://zenodo.org/records/16688500)
- [Embrace The Red, CVE-2025-55284](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)
- [StrongDM Leash](https://github.com/strongdm/leash); [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
