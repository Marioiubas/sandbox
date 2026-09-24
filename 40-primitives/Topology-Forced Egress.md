---
title: "Topology-Forced Egress"
aliases: ["Egress Enforcement Mechanics", "Transparent Redirection"]
type: "concept"
section: "primitives"
summary: "Only topology forces traffic through the broker: no NIC plus UDS on Linux, Seatbelt loopback-only on macOS, vsock in VMs, host-side redirect in cloud; HTTP_PROXY alone is 'polite' and bypassable (ToolHive, Agent Vault)."
tags: [sandbox/primitives, concept, topic/egress, topic/dns, topic/isolation, platform/linux, platform/macos, platform/ci, platform/cloud, control/egress, boundary/tb3, invariant/i2, invariant/i8, milestone/m0]
status: verified
confidence: high
milestone: M0
created: 2026-09-24
updated: 2026-09-24
related: ["[[ADR-003 Topology-Enforced Egress]]", "[[Netguard Ingress]]", "[[bubblewrap]]", "[[Seatbelt]]", "[[seccomp-bpf]]", "[[Broker DNS Resolver]]", "[[Local Credential Proxies]]", "[[MCP Gateways]]", "[[Vercel Sandbox]]", "[[I6 Single Canonicaliser]]", "[[Open Questions and Unverified Claims]]", "[[I7 Reject Foreign Credentials]]", "[[Core Trait Contracts]]", "[[Landlock]]", "[[I2 Fail-Closed Launch]]", "[[I8 No Flag Disables Isolation]]", "[[Claude Code DNS Exfiltration CVE-2025-55284]]", "[[Conformance Probe Matrix]]", "[[M0 Contained Run]]", "[[L4 Product Metrics]]"]
---

# Topology-Forced Egress

Only network topology forces an agent's traffic through the broker; `HTTP_PROXY` environment variables do not, because any process with code execution can open a raw socket. The sandbox must have no route anywhere except the broker: no network interface plus a Unix socket on Linux, loopback-only to one port under Seatbelt on macOS, vsock in a VM, and host-side transparent redirection in cloud runtimes. Products that rely on proxy variables alone (ToolHive, Infisical Agent Vault) are bypassable by design.

## Why environment variables are not a boundary

- Cooperative (`HTTP_PROXY`) mode is "polite": agents with code execution "can… call raw sockets directly" ([dev.to GVM write-up](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)).
- LangSmith states its proxy is "not implemented by hoping every language, package manager, SDK, or subprocess respects `HTTP_PROXY`" ([LangChain](https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes)).
- ToolHive "does not transparently redirect all traffic with iptables or nftables rules", so raw TCP bypasses it and only HTTP/HTTPS is covered ([Stacklok](https://docs.stacklok.com/toolhive/guides-cli/network-isolation)).
- Infisical Agent Vault relies on `HTTPS_PROXY` and has no sandbox ([Agent Vault](https://github.com/Infisical/agent-vault)); see [[Local Credential Proxies]].
- srt documents that on Linux, programs that ignore proxy variables could bypass filtering, which is why it removes the network namespace entirely ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).

## The four topologies that do force it

| Environment | Topology | Evidence |
|---|---|---|
| Linux process sandbox | network namespace with **no interface**; only exit is a Unix socket to the broker | srt: netns "removed entirely", traffic via "Unix domain sockets" and socat ([srt](https://github.com/anthropic-experimental/sandbox-runtime)); Codex: `--unshare-net` plus TCP→UDS→TCP bridge, then seccomp blocks new `AF_UNIX` ([Codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)) |
| macOS process sandbox | Seatbelt permits outbound only to the broker's localhost port | srt ([srt](https://github.com/anthropic-experimental/sandbox-runtime)) |
| VM | only device is vsock, or a NIC whose sole peer is the broker | Docker Sandboxes: "All outbound TCP traffic routes through a host-side proxy" ([Docker architecture](https://docs.docker.com/ai/sandboxes/architecture/)); libkrun TSI makes the VMM the network proxy ([libkrun](https://github.com/containers/libkrun)) |
| Cloud sandbox | host-side transparent redirection of TCP **and DNS** | Vercel "transparently redirects outbound TCP and DNS traffic… while preserving original destination" ([Vercel blog](https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox)); Cloudflare uses a nftables `proxy-everything` sidecar in local dev ([Cloudflare](https://blog.cloudflare.com/sandbox-auth/)) |

gVisor adds a fifth variant: the Sentry's seccomp filter forbids host `connect(2)`, so `--network=none` plus a UDS is topology too ([gVisor intro](https://gvisor.dev/docs/architecture_guide/intro/)).

## Kernel redirection mechanisms (when a NIC must exist)

- **netns + iptables/nftables.** A netns with OUTPUT rules that "drop everything except traffic destined for Proxy (TCP) and DNS (UDP)", IPv6 disabled, adds ~14 ms per HTTPS request through a MITM with just-in-time certificates and forced HTTP/1.1, measured on an EC2 t3.medium ([dev.to GVM write-up](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)). That is one reference point, not a benchmark of the broker.
- **cgroup `sock_addr` eBPF.** Programs at `connect4/6` and `sendmsg4/6` can deny or **rewrite destination address and port**, giving transparent redirection to a proxy ([docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/)). Needs privilege and keeps a NIC; see [[seccomp-bpf]].

The decision record rejects "`HTTP_PROXY` only" and "eBPF redirect only" in favour of topology, because env vars are bypassable and topology fails closed ([[ADR-003 Topology-Enforced Egress]]).

## Explicit and transparent ingress on top of topology

Topology decides *whether* traffic can leave; ingress modes decide *how* well-behaved and badly-behaved tools reach the broker.

**Proposal** (report). Inside the Linux netns, expose three ingress modes, all bridged to the broker's socket:

1. an explicit HTTP CONNECT listener (the default path for tools that honour `HTTPS_PROXY`);
2. a SOCKS5 listener;
3. a transparent listener that receives all other TCP by nftables redirect inside the namespace and reads the original destination and ClientHello SNI, so static Go binaries and gRPC clients still work and still pass policy.

All three feed one canonicaliser ([[I6 Single Canonicaliser]]) implemented in [[Netguard Ingress]]. The market splits the same way: explicit-proxy designs (ToolHive, Agent Vault) versus transparent designs (Vercel, Cloudflare nftables, OpenShell, agentjail gVisor) (research note 05 inference).

**macOS caveat.** Without a Network Extension, transparent interception is unvalidated; clients that ignore proxy variables simply fail because nothing else is reachable. That fails closed and is accepted for the MVP ([[Open Questions and Unverified Claims]]; [[Seatbelt]]).

## DNS and non-TCP protocols

- The sandbox gets **no UDP/53 and no ICMP**. Names resolve inside the proxy (CONNECT and SOCKS5 hostnames) or via a stub that forwards only to the broker's policy resolver, which blocks DoH endpoints by name ([[Broker DNS Resolver]]). This closes CVE-2025-55284 ([Embrace The Red](https://embracethered.com/blog/posts/2025/claude-code-exfiltration-via-dns-requests/)) and the base32-label, TXT-tunnel and DoH vectors described around a July 2026 incident whose verified path was actually a JFrog Artifactory zero-day chain through the sanctioned egress point (details unconfirmed) ([axeploit](https://axeploit.com/blog/the-hugging-face-sandbox-escape-everyone-watched-the-proxy-nobody-watched-port-53)).
- Raw-IP CIDR allows bypass SNI checks *and* leave DNS open; a catch-all `*` lets SSH pass unbrokered ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)). Deny IP-literal CONNECTs and SNI-less protocols by default.
- Block QUIC/UDP 443 so clients fall back to TCP; E2B notes QUIC defeats domain filtering, and that in its sandbox "blocked connections may appear successful" ([E2B docs](https://docs.e2b.dev/network/internet-access.md)).

## What topology does not close

Allowed destinations remain exfiltration channels: a gist or issue on an allowed github.com, a package registry acting as a proxy (the Artifactory lesson), timing and request counts (research note 01 inference). Those are handled by method/path authorization, credential binding ([[I7 Reject Foreign Credentials]]) and measured covert-channel bandwidth (conformance category 11), not by topology.

## Verdict for the broker

**Proposal.**

- **Use it for:** every backend. `SandboxSpec.egress` is always one of `Uds(path)`, `Loopback(port)` or `Vsock(cid, port)`; there is no variant for "host network" ([[Core Trait Contracts]]).
- **Don't use it for:** proving application-level safety; topology only guarantees the broker sees every byte.
- **How we integrate it.** [[bubblewrap]] `--unshare-net` plus a bind-mounted UDS and an in-namespace bridge (Rust, tokio) that exposes CONNECT, SOCKS5 and the nftables-redirected transparent listener; [[seccomp-bpf]] blocks new `AF_UNIX` after the bridge; [[Landlock]] (ABI ≥4) restricts TCP connect to the bridge port; [[Seatbelt]] SBPL allows only `localhost:${BROKER_PORT}` with a per-session `Proxy-Authorization` sentinel; VM backends attach only vsock. If any piece fails to come up, launch fails ([[I2 Fail-Closed Launch]]); no flag can switch to host networking ([[I8 No Flag Disables Isolation]]).

## How it connects

- decided-by:: [[ADR-003 Topology-Enforced Egress]]
- depends-on:: [[bubblewrap]] (empty netns on Linux)
- depends-on:: [[Seatbelt]] (loopback-port-only on macOS)
- depends-on:: [[seccomp-bpf]] (no second channel after the bridge)
- depends-on:: [[Netguard Ingress]] (CONNECT, SOCKS5, transparent listeners)
- depends-on:: [[Broker DNS Resolver]] (no UDP/53 in the sandbox)
- contrasts-with:: [[Local Credential Proxies]] (env-var proxies without topology)
- contrasts-with:: [[MCP Gateways]] (ToolHive's env-var egress)
- example-of:: [[Vercel Sandbox]] (host-side transparent TCP and DNS redirect)
- mitigates:: [[Claude Code DNS Exfiltration CVE-2025-55284]]
- evaluated-by:: [[Conformance Probe Matrix]] (categories 3, 5, 9)

## Implications for the build

- M0 acceptance: conformance categories 3 (name resolution), 5 (alternate protocols) and 9 (proxy bypass) are 100% denied, including DNS TXT probes ([[M0 Contained Run]]).
- Tests: unset every proxy variable and open a raw TCP socket to a public IP; send UDP/53 and ICMP; attempt QUIC; attempt SSH to port 22. All must fail and be logged.
- Measure added latency against the [[L4 Product Metrics]] thresholds (warm p50 ≤5 ms, p95 ≤25 ms; new terminated connection p50 ≤15 ms).

## Open questions

- Transparent interception on macOS without a Network Extension ([[Open Questions and Unverified Claims]]).
- ECH adoption and its effect on SNI peeking; QUIC, gRPC and WebSocket handling across vendors.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
