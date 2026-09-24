---
title: "ADR-003 Topology-Enforced Egress"
aliases: ["ADR-003"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/egress, topic/dns, topic/isolation, platform/linux, platform/macos, platform/ci, control/egress, boundary/tb3, invariant/i2, invariant/i6, invariant/i8, milestone/m0, evidence/unverified]
status: proposal
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Enforce egress by topology (no NIC or loopback-only plus UDS or vsock), rejecting HTTP_PROXY-only and eBPF-redirect-only designs."
related: ["[[Topology-Forced Egress]]", "[[Netguard Ingress]]", "[[Local Credential Proxies]]", "[[MCP Gateways]]", "[[seccomp-bpf]]", "[[ADR-009 Broker-Only DNS Resolution]]", "[[Sandbox Launcher]]", "[[Hostname Canonicaliser]]", "[[AgentSentinel]]", "[[Conformance Probe Matrix]]", "[[Mythos Preview Evaluation Escape]]", "[[Nx s1ngularity Supply-Chain Attack]]", "[[I2 Fail-Closed Launch]]", "[[I6 Single Canonicaliser]]", "[[I8 No Flag Disables Isolation]]", "[[I9 Hash-Chained Audit Outside the Sandbox]]", "[[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]", "[[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]", "[[ADR-006 Deny Unmatched L7 Requests]]", "[[M0 Contained Run]]", "[[Open Questions and Unverified Claims]]", "[[ADR-004 Selective TLS Termination with Per-Session CA]]"]
sources: ["https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o", "https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes", "https://docs.stacklok.com/toolhive/guides-cli/network-isolation", "https://github.com/Infisical/agent-vault", "https://github.com/anthropic-experimental/sandbox-runtime", "https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md", "https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox", "https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/", "https://arxiv.org/html/2509.07764v1", "https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card", "https://nx.dev/blog/s1ngularity-postmortem"]
---

# ADR-003 Topology-Enforced Egress

> Enforce egress by topology (no NIC or loopback-only plus UDS or vsock), rejecting HTTP_PROXY-only and eBPF-redirect-only designs.

## Status

**Proposed** (2026-09-24). Delivered in [[M0 Contained Run]] (empty netns plus UDS bridge; CONNECT and SOCKS5). The transparent listener and vsock follow. Not superseded.

## Context

The broker's whole value depends on being the **only** way out. If the agent can reach the internet around it, minting, Cedar and audit are decoration. Three facts shape the choice.

**Environment variables are not a boundary.**

- `HTTP_PROXY` alone is "polite": an agent with code execution "can… call raw sockets directly" ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)).
- LangSmith says its proxy is "not implemented by hoping every language, package manager, SDK, or subprocess respects `HTTP_PROXY`" ([LangChain](https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes)).
- ToolHive "does not transparently redirect all traffic with iptables or nftables rules", so raw TCP bypasses it and only HTTP/HTTPS is covered ([Stacklok](https://docs.stacklok.com/toolhive/guides-cli/network-isolation); [[MCP Gateways]]).
- Infisical Agent Vault relies on `HTTPS_PROXY` and has no sandbox ([Agent Vault](https://github.com/Infisical/agent-vault); [[Local Credential Proxies]]).

**Topology already works in production.**

- srt removes the Linux network namespace entirely and bridges through Unix sockets; on macOS Seatbelt allows only the proxy's localhost port ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).
- Codex's managed-proxy mode uses `--unshare-net` plus a TCP→UDS→TCP bridge, after which seccomp blocks new `AF_UNIX` sockets so the command cannot create other channels ([codex README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)).
- In the cloud, Vercel "transparently redirects outbound TCP and DNS traffic" at a host-side firewall ([Vercel](https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox)).

**Kernel redirection exists but leaves a NIC in place.** A cgroup `sock_addr` eBPF program (connect4/6, sendmsg4/6) can deny or rewrite the destination address and port ([docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/)). A netns plus iptables design that drops everything except proxy TCP and DNS UDP added ~14 ms per HTTPS request through a MITM ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)). Note that this design still allowed DNS UDP; ADR-009 forbids exactly that.

**Incidents where the outbound path mattered.**

- In the Mythos Preview evaluation escape, a requested container escape gained broad internet access ([system card](https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card)). The control that stops it is egress enforced outside the guest ([[Mythos Preview Evaluation Escape]]).
- Nx s1ngularity malware drove local AI CLIs to hunt secrets and exfiltrate them ([Nx](https://nx.dev/blog/s1ngularity-postmortem); [[Nx s1ngularity Supply-Chain Attack]]).

## Decision

**Proposal.** Every sandbox backend presents exactly one egress endpoint and no other route. This is the `EgressEndpoint` enum in `SandboxSpec`: `Uds(path) | Loopback(port) | Vsock(cid, port)`.

| Backend | Topology | What closes the other routes |
|---|---|---|
| Linux standard | `--unshare-net`: an empty network namespace with no interface; one UDS bridge to `brokerd` | [[seccomp-bpf]] blocks new `AF_UNIX` sockets after the bridge and blocks raw sockets; Landlock allows TCP connect to the bridge port only |
| macOS standard | SBPL allows network-outbound only to the broker's per-session localhost port | Each session authenticates with a sentinel `Proxy-Authorization`, because any local process can reach a loopback port |
| VM hard tier | vsock only, or a NIC whose sole peer is the broker | No other device |
| CI | The Linux standard tier inside the runner VM; the broker outside the sandbox | Same as Linux |

Inside the Linux namespace, [[Netguard Ingress]] exposes three listeners, all bridged to the one socket:

- HTTP CONNECT;
- SOCKS5;
- a transparent listener that receives all other TCP through nftables redirect and reads the original destination and ClientHello SNI.

All three feed one [[Hostname Canonicaliser]]. `HTTP(S)_PROXY` variables are set for convenience only; nothing relies on them. eBPF or LSM tracing may be added later as a telemetry backstop, never as the decision point.

Testable form:

- Conformance categories 5 (raw TCP, UDP, ICMP, SSH, QUIC, nested SOCKS) and 9 (unset proxy env, direct sockets, `docker.sock`, host localhost services) are 100% denied ([[Conformance Probe Matrix]]).
- Launch exits non-zero if the namespace, bridge, seccomp filter or SBPL cannot be applied.

## Alternatives considered

| Alternative | Pros | Cons (evidence) | Why rejected |
|---|---|---|---|
| **`HTTP_PROXY` only** (ToolHive, Agent Vault) | No privileges; portable; trivial to deploy | Raw sockets, static Go binaries and SSH ignore it; it fails **open** ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o); [Stacklok](https://docs.stacklok.com/toolhive/guides-cli/network-isolation)) | Env vars are bypassable |
| **eBPF redirect only** (cgroup `sock_addr` rewrite with the NIC left in place) | Transparent for every connect(); no namespace plumbing | The sandbox keeps a real interface, so any gap fails open: an unhooked address family, a UDP path, a program not attached to the right cgroup. Correctness is a rule set rather than an absence | Topology fails closed. Redirection remains useful *inside* the empty namespace (nftables to the transparent listener) and for telemetry |
| **Netns plus iptables allow-rules** (proxy TCP and DNS UDP permitted) | Measured cost (~14 ms per HTTPS request) | Leaves DNS open as an exfiltration channel; relies on rules staying correct | Superseded by no-NIC plus broker-only DNS ([[ADR-009 Broker-Only DNS Resolution]]) |
| **eBPF/LSM monitor as the enforcement point** | Rich kernel telemetry | AgentSentinel's hybrid rule and LLM audit had a 10.8% false-positive rate ([arXiv](https://arxiv.org/html/2509.07764v1)) | Adopt only as a backstop for telemetry ([[AgentSentinel]]) |

> [!question] Unverified
> The privilege needed to attach cgroup BPF programs, and whether a sandboxed process could detach or evade them, is not in the research record. The rejection rests on the fail-open structure, not on those details.

## Consequences

**Positive.**

- Fail-closed by construction: a tool that ignores proxy settings on Linux still passes policy through the transparent listener; on macOS it simply fails.
- One choke point for DNS, TLS, Cedar and audit.
- The same shape serves local MCP servers, each in its own sandbox.

**Negative.**

- On macOS, without a Network Extension, clients that ignore proxy variables fail. That fails closed and is acceptable for the MVP, but it is a compatibility cost ([[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]).
- Ubuntu 24.04+ AppArmor gating of unprivileged userns affects `--unshare-net`.
- Topology does not close allowed-domain abuse (a gist on an allowed github.com), registries acting as proxies, or timing channels. Those need L7 authorization ([[ADR-006 Deny Unmatched L7 Requests]]), rate limits and measurement (conformance category 11).
- The transparent path adds a parser surface (original destination, SNI peek) that must be fuzzed.

**Follow-up work.**

- DNS policy ([[ADR-009 Broker-Only DNS Resolution]]).
- Transparent listener and nftables rules in the namespace.
- vsock endpoint for the VM backend.
- Bypass-corpus entries for every listener.

## Revisit triggers

- Transparent interception on macOS is validated without a Network Extension, or Apple ships a supported per-process network filter.
- Landlock UDP (ABI 10) reaches a stable kernel. That would allow an extra inner UDP layer, not a replacement.
- A bypass of the empty-namespace topology is published for bubblewrap or Codex's pipeline.
- A deployment target cannot remove the NIC (some Kubernetes modes). That needs an ADR for host-side redirect in that mode.

## Invariants and components affected

- **Upholds** [[I2 Fail-Closed Launch]]: no topology, no launch. **Upholds** [[I8 No Flag Disables Isolation]]: no flag restores a NIC. **Upholds** [[I6 Single Canonicaliser]]: every ingress mode feeds one canonicaliser.
- **Supports** [[I9 Hash-Chained Audit Outside the Sandbox]]: every connection passes a logging point outside the sandbox.
- **Weakens none.**
- Components: [[Sandbox Launcher]], [[Netguard Ingress]], [[seccomp-bpf]] rules.

## How it connects

- implements:: [[Topology-Forced Egress]]
- delivered-by:: [[Netguard Ingress]]
- depends-on:: [[seccomp-bpf]]
- depends-on:: [[ADR-002 OS Process Sandbox by Default with VM Hard Tier]]
- contrasts-with:: [[Local Credential Proxies]]
- contrasts-with:: [[MCP Gateways]]
- mitigates:: [[Mythos Preview Evaluation Escape]]
- mitigates:: [[Nx s1ngularity Supply-Chain Attack]]
- evaluated-by:: [[Conformance Probe Matrix]]
- delivered-by:: [[M0 Contained Run]]

## Implications for the build

- M0 acceptance: conformance categories 3, 4, 5, 9 and 10 at 100% denied, including DNS TXT and 169.254.169.254 probes.
- The launcher must refuse to run if seccomp cannot install the post-bridge `AF_UNIX` block. The control socket must be unreachable: seccomp blocks new `AF_UNIX` sockets and SBPL denies the path.
- Tests must attempt a direct `connect()` to a public IP from inside the sandbox on every CI OS image.

## Open questions

- macOS transparent interception without a Network Extension is unvalidated ([[Open Questions and Unverified Claims]]).
- Privileges and evasion properties of cgroup eBPF redirection (not in the record).
- ECH adoption would affect the transparent listener's SNI read (see [[ADR-004 Selective TLS Termination with Per-Session CA]]).

## Sources

- https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o
- https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes
- https://docs.stacklok.com/toolhive/guides-cli/network-isolation
- https://github.com/Infisical/agent-vault
- https://github.com/anthropic-experimental/sandbox-runtime
- https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md
- https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox
- https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/
- https://arxiv.org/html/2509.07764v1
- https://www.lesswrong.com/posts/xtnSzhA3TvExN4ZhG/claude-mythos-preview-system-card
- https://nx.dev/blog/s1ngularity-postmortem
- Report: "Topology forces traffic through the broker; environment variables do not", interfaces (control socket), decision table row "Egress enforcement". Research note 01 Q5, research note 03 Q4, research note 05 section 1.
