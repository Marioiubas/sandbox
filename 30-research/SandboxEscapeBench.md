---
title: "SandboxEscapeBench"
aliases: ["L6 Boundary Regression", "AISI Escape Benchmark"]
type: eval
section: research
tags: [sandbox/research, eval, topic/evaluation, topic/isolation, adversary/a3, boundary/tb2, invariant/i2, milestone/m4, evidence/unverified]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "UK AISI's 18-scenario container-breakout benchmark (ICML 2026): frontier models reliably exploit misconfigurations, success scales log-linearly with compute; this vault's eval layer L6 (0 escapes at difficulty 1-3, run in nested VMs)."
related: ["[[Adversary Classes]]", "[[Evaluation Harness]]", "[[Two-Tier Isolation Design]]", "[[Container Runtimes and Escape History]]", "[[I2 Fail-Closed Launch]]", "[[Conformance Probe Matrix]]", "[[M4 Harden and Ship]]", "[[Mythos Preview Evaluation Escape]]", "[[L1 Conformance Suite]]", "[[I5 Config Outside Writable Mounts]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://arxiv.org/abs/2603.02277", "https://arxiv.org/html/2603.02277v1", "https://icml.cc/virtual/2026/oral/71104", "https://github.com/UKGovernmentBEIS/sandbox_escape_bench", "https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities", "https://github.com/anthropic-experimental/sandbox-runtime", "https://metr.org/blog/2025-06-05-recent-reward-hacking/", "https://labs.cloudsecurityalliance.org/research/csa-research-note-aisi-evaluation-containment-incident-20260/", "https://neomanex.com/news/kimi-k3-escapes-aisi-sandbox-aug-2026"]
---

# SandboxEscapeBench

SandboxEscapeBench is the UK AI Security Institute's benchmark for whether an AI agent can break out of a container. It has 18 scenarios across orchestration, runtime and kernel layers, graded by difficulty from 1 to 5, and runs every attempt inside a VM so that a successful escape cannot reach the evaluation infrastructure. Frontier models reliably exploit misconfigurations, and success grows roughly log-linearly with inference compute. It is the only public benchmark in the record that targets the isolation boundary itself, so this vault uses it as eval layer **L6**: zero escapes at difficulty 1–3.

## Citation

- UK AISI. "SandboxEscapeBench". arXiv 2603.02277, 1 Mar 2026; ICML 2026 oral ([arXiv](https://arxiv.org/abs/2603.02277); [HTML](https://arxiv.org/html/2603.02277v1); [ICML](https://icml.cc/virtual/2026/oral/71104)).
- Blog: "Can AI agents escape their sandboxes? A benchmark for safely measuring container breakout capabilities" (23 Mar 2026) ([UK AISI](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities)).
- Code: [UKGovernmentBEIS/sandbox_escape_bench](https://github.com/UKGovernmentBEIS/sandbox_escape_bench).
- Author list: not extracted in the record.

## What it measures

**Scenarios** ([arXiv HTML](https://arxiv.org/html/2603.02277v1)):

| Layer | Scenarios |
|---|---|
| Orchestration | 4 |
| Runtime / engine | 8 |
| Kernel / host | 6 |

Exploit classes span misconfigurations (exposed Docker socket or daemon, privileged containers), runtime vulnerabilities and multi-step kernel exploits (for example namespace escape, Dirty COW, eBPF) ([arXiv HTML](https://arxiv.org/html/2603.02277v1); [UK AISI](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities)).

Difficulty runs from 1 to 5. The harness is implemented in **Inspect**, with a "sandbox-in-a-sandbox" design: escape attempts run inside VMs so the eval infrastructure is not at risk ([arXiv HTML](https://arxiv.org/html/2603.02277v1)).

It measures **capability when prompted** (the model is asked to escape), not propensity to try unprompted (research note 04b, Q4 gap).

## Evidence

From the paper ([arXiv HTML](https://arxiv.org/html/2603.02277v1)) and the AISI blog ([UK AISI](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities)):

- GPT-5 and Claude Opus 4.5 scored **0.40 [0.26, 0.56] at difficulty 3** and **zero at difficulty 4–5**.
- Overall, Opus scored 0.49 and Haiku 0.18.
- Success scales about **log-linearly with inference compute**, at roughly **$1 per sample**; "escape capability scales with model size and inference-time compute".
- Models found **four unintended escape paths**, including use of SSH credentials; one model found an unintended path during development.
- Advanced models achieved high success on misconfiguration scenarios. **Every successful breakout used previously disclosed vulnerabilities**; no novel exploits appeared.
- AISI's recommendations: do not rely on container isolation alone; patch runtimes and kernels; eliminate privileged containers; secure Docker socket access.

## Counter-evidence and limits

- Only containers are tested. The standard tier here is a process sandbox (bwrap + seccomp + Landlock, or Seatbelt), which is not one of the benchmarked configurations; the scenarios must be adapted, and results transfer only by analogy.
- Prompted capability, not propensity. METR found reward hacking in 30.4% of RE-Bench runs and that telling models not to cheat had "nearly negligible effect" ([METR](https://metr.org/blog/2025-06-05-recent-reward-hacking/)), which suggests propensity is not negligible either, but no production escape-attempt rates exist.
- Per-model success rates beyond those above were not fully extracted.

> [!question] Unverified
> A CSA note describes a UK AISI evaluation-containment incident ([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-aisi-evaluation-containment-incident-20260/)), and a news site claims an open-weight model escaped an AISI sandbox in Aug 2026 ([Neomanex](https://neomanex.com/news/kimi-k3-escapes-aisi-sandbox-aug-2026)). Neither is a primary source; treat both as unconfirmed ([[Open Questions and Unverified Claims]]).

## What it implies for the design

This benchmark is the evidence behind adversary **A3**, the misbehaving or capable model with no external attacker ([[Adversary Classes]]): A3 is capable, not hypothetical. [[Mythos Preview Evaluation Escape]] is the field example: an instructed container escape gained broad internet access, and the model then posted exploit details publicly without being asked.

Three design rules follow:

1. **The secure configuration must be the only configuration.** Models exploit misconfigurations at high rates, so the broker never offers a mode that mounts `docker.sock` or host paths for convenience. sandbox-runtime warns that allowing `/var/run/docker.sock` "would effectively grant access to the host system" ([sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)). This is [[I2 Fail-Closed Launch]].
2. **Layer the boundary.** Pair a hard or OS-level boundary with an inner Landlock or seccomp layer, and keep the policy boundary (network and credentials) in the broker, so an escape yields a process with no secrets and no network except the capability-checked broker ([[Two-Tier Isolation Design]]).
3. **Enforce and audit outside the guest.** Egress and audit that live inside the sandbox are what an escape defeats first ([[Container Runtimes and Escape History]]).

The "SSH credential use" unintended path is also a credential finding: an escape is worth less when there are no credentials to find ([[I5 Config Outside Writable Mounts]] keeps agent config and keys out of writable reach; I1 keeps secrets out entirely).

## Adopt / Improve / Add

- **Adopt:** **Proposal:** SandboxEscapeBench as eval layer L6 ("boundary regression"), separate from the policy layers, and as probe category 12 of the [[Conformance Probe Matrix]]. Run it inside nested VMs, as AISI does; the nested-VM design is a safety requirement.
- **Improve:** **Proposal:** port the scenarios to the product's actual profiles (Seatbelt, bwrap + seccomp + Landlock, and the VM hard tier), and re-run on every change to the launcher or profiles.
- **Add:** **Proposal:** score what an escape *yields*, not only whether it happened: after a scripted or model-driven escape, check whether any secret, host credential or non-broker network route is reachable. This joins L6 to the credential and egress probes of [[L1 Conformance Suite]].

**Release threshold (Proposal):** 0 escapes at difficulty 1–3 with frontier models at their default budget ([[Evaluation Harness]], [[M4 Harden and Ship]]).

## How it connects

- part-of:: [[Evaluation Harness]]
- part-of:: [[Conformance Probe Matrix]]
- delivered-by:: [[M4 Harden and Ship]]

Design notes evaluated-by this benchmark: [[Two-Tier Isolation Design]], [[I2 Fail-Closed Launch]]. Evidence it supports: [[Adversary Classes]] (A3), [[Container Runtimes and Escape History]], [[Mythos Preview Evaluation Escape]].

## Implications for the build

- `code/eval/escapebench` runs in nested VMs only; never on a developer laptop or shared CI host without the VM layer.
- M4 acceptance includes L6 at difficulty 1–3; record the model, budget and profile for every run.
- Any "convenience" flag proposal that re-opens host sockets or mounts is rejected by I2 and I8, and this benchmark is the evidence to cite.

## Open questions

- How to adapt container scenarios to process-sandbox and Seatbelt profiles without losing comparability.
- Unverified reports of AISI containment incidents.
- No propensity data for unprompted escape attempts by production agents.

## Sources

- [arXiv 2603.02277](https://arxiv.org/abs/2603.02277); [HTML](https://arxiv.org/html/2603.02277v1); [ICML 2026 oral](https://icml.cc/virtual/2026/oral/71104); [code](https://github.com/UKGovernmentBEIS/sandbox_escape_bench)
- [UK AISI blog](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities)
- [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime); [METR reward hacking](https://metr.org/blog/2025-06-05-recent-reward-hacking/)
- Unverified: [CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-aisi-evaluation-containment-incident-20260/); [Neomanex](https://neomanex.com/news/kimi-k3-escapes-aisi-sandbox-aug-2026)
