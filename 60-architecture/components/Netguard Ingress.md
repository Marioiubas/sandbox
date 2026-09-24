---
title: "Netguard Ingress"
aliases: ["netguard", "Sandbox-Broker Channel", "TB3 Channel", "Ingress Modes"]
type: component
section: architecture
tags: [sandbox/architecture, component, topic/egress, control/egress, boundary/tb3, platform/macos, platform/linux, invariant/i6, invariant/i2, milestone/m0]
status: proposal
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "The only route out and its listeners: the sandbox-broker channel (UDS from an empty netns, loopback port with sentinel Proxy-Authorization on macOS, vsock in VMs) feeding HTTP CONNECT, SOCKS5 and transparent (nftables redirect, original-dst plus SNI) ingress into one canonicaliser."
related: ["[[Topology-Forced Egress]]", "[[Hostname Canonicaliser]]", "[[Broker DNS Resolver]]", "[[TLS Termination and Per-Session CA]]", "[[Trust Boundaries]]", "[[M0 Contained Run]]", "[[ADR-003 Topology-Enforced Egress]]", "[[Core Trait Contracts]]", "[[Open Questions and Unverified Claims]]", "[[Sandbox Launcher]]", "[[I6 Single Canonicaliser]]", "[[I2 Fail-Closed Launch]]", "[[I7 Reject Foreign Credentials]]", "[[Policy Engine and Entity Builder]]", "[[Audit Recorder and Event Schema]]", "[[Conformance Probe Matrix]]", "[[L4 Product Metrics]]", "[[MCP Gateways]]", "[[Vercel Sandbox]]", "[[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]", "[[Broker CLI and Daemon]]"]
sources: ["https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o", "https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes", "https://docs.stacklok.com/toolhive/guides-cli/network-isolation", "https://github.com/anthropic-experimental/sandbox-runtime", "https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox", "https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md", "https://docs.e2b.dev/network/internet-access.md", "https://vercel.com/docs/sandbox/concepts/firewall", "https://blog.cloudflare.com/sandbox-auth/"]
milestone: M0
---

# Netguard Ingress

> The only route out and its listeners: the sandbox-broker channel (UDS from an empty netns, loopback port with sentinel Proxy-Authorization on macOS, vsock in VMs) feeding HTTP CONNECT, SOCKS5 and transparent (nftables redirect, original-dst plus SNI) ingress into one canonicaliser.

## Responsibility

The ingress half of `crates/netguard` (the other halves are [[Hostname Canonicaliser]] and [[Broker DNS Resolver]]). It owns trust boundary TB3 ([[Trust Boundaries]]): "the only network path; capability requests, never raw secrets", carried over "UDS, localhost port or vsock; per-session sentinel". It accepts connections from the sandbox, identifies the session, extracts the requested destination in whatever form the client used, hands raw destination bytes to the canonicaliser, and passes the connection to the TLS/L7 stage ([[TLS Termination and Per-Session CA]]) or denies it.

**It must never:** resolve or connect to a name before canonicalisation and policy; accept a connection it cannot attribute to a session; offer any egress other than through the broker's own pipeline; rely on `HTTP_PROXY` for enforcement; accept UDP (other than to the DNS stub where one is used) or ICMP.

## Why topology, not environment variables

`HTTP_PROXY` alone is "polite": an agent with code execution can call raw sockets ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)). LangSmith's proxy is "not implemented by hoping every language, package manager, SDK, or subprocess respects `HTTP_PROXY`" ([LangChain](https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes)). ToolHive "does not transparently redirect all traffic with iptables or nftables rules", so raw TCP bypasses it ([Stacklok](https://docs.stacklok.com/toolhive/guides-cli/network-isolation)). Only topology forces traffic through the broker ([[Topology-Forced Egress]], [[ADR-003 Topology-Enforced Egress]]).

## The channel per platform

| Platform | Channel | Session identification |
|---|---|---|
| Linux standard | The sandbox's netns has no interface; a bridge inside the namespace connects to a per-session UDS (`data.sock`) owned by `brokerd`, as srt and Codex do ([srt](https://github.com/anthropic-experimental/sandbox-runtime); [codex](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)) | The socket is per session; the path identifies it |
| macOS standard | Seatbelt permits only the per-session loopback port | Sentinel `Proxy-Authorization` value on each CONNECT or SOCKS auth; "leaking it grants nothing beyond the session's own policy, and only on that host" (report) |
| VM hard tier | vsock, or a NIC whose sole peer is the broker | vsock CID per VM |
| CI | UDS, or vsock in a VM; broker outside the sandbox in the runner | as above |
| Cloud gateway (phase 2) | Host-side transparent redirect by the vendor (Vercel, Cloudflare) to the broker as upstream proxy ([Vercel](https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox)) | Vendor OIDC or [[Internal Grant JWT]] |

## Ingress modes (Linux)

Inside the Linux network namespace the broker exposes three listeners, all bridged to the broker's socket (report, Proposal):

1. **HTTP CONNECT** listener (explicit proxy): destination = CONNECT authority.
2. **SOCKS5** listener: destination = SOCKS5 domain name or address; SOCKS4a and SOCKS5 hostname forms are all passed as raw bytes to the canonicaliser (the NUL-byte bypass came through SOCKS5).
3. **Transparent** listener: receives all other TCP by nftables redirect inside the namespace, reads the original destination (`SO_ORIGINAL_DST`) and peeks the ClientHello SNI. "Tools that ignore proxy variables (static Go binaries, gRPC clients) then still work, and still pass policy."

For the transparent listener the destination is (SNI name, original address). Because the sandbox cannot resolve names itself ([[Broker DNS Resolver]]), the original address is normally a broker-synthesised or broker-resolved one, so the pair can be checked for consistency.

On macOS without a Network Extension, transparent interception is unvalidated; clients that ignore proxy variables fail because nothing else is reachable. That fails closed and is accepted for the MVP ([[ADR-013 Seatbelt for macOS MVP with VZ Hedge]]).

## Interface

**Proposal; not compiled.**

```rust
pub enum IngressKind { Connect, Socks5, Transparent }

pub struct RawDestination<'a> {
    pub kind: IngressKind,
    pub host_bytes: &'a [u8],               // exactly as received; never a &str
    pub port: u16,
    pub original_dst: Option<std::net::SocketAddr>, // transparent only
    pub sni: Option<&'a [u8]>,              // peeked, not yet validated
}

pub struct Admitted {
    pub session: SessionId,
    pub host: CanonicalHost,                // from netguard::canon
    pub addrs: Vec<std::net::IpAddr>,       // resolved by the broker resolver
    pub port: u16,
    pub stream: tokio::net::TcpStream,      // or UnixStream/VsockStream, boxed
}

#[async_trait::async_trait]
pub trait Ingress {
    async fn accept(&self) -> anyhow::Result<(SessionId, RawDestination<'_>, BoxedStream)>;
}
```

Config keys (**Proposal**, in the org or user layer only):

```toml
[netguard]
ingress = ["connect", "socks5", "transparent"]   # linux; macOS: connect + socks5
block_udp = true            # always true; not overridable
block_quic = true           # UDP/443 dropped so clients fall back to TCP
deny_ip_literals = true     # default; explicit grants only
deny_port_22 = true
```

The `block_*` keys exist for documentation and exporters; the code treats them as constants ([[I8 No Flag Disables Isolation]]).

## Internal design

**Proposal.** One tokio task per accepted connection:

1. `accept()` yields raw destination bytes.
2. `canon_host(host_bytes)` → `CanonicalHost` or reject (log reason, close).
3. Resolve via the broker resolver; check the name **and** every resolved address against policy (IP class filters: link-local, metadata, RFC 1918 unless granted). For transparent connections, require the original destination to be one the broker resolved for this session and name.
4. Build an L4 Cedar request (`http.read`-class host admission; see [[Policy Engine and Entity Builder]]) and ask for a decision.
5. On allow, hand the stream plus `Admitted` to the TLS stage, which chooses the L4 fast path or the L7 path.
6. On deny, close (for CONNECT, a `403` with a broker error ID; for SOCKS5, a failure reply) and append a deny event with the reason.

Every step records timing for [[L4 Product Metrics]].

## State

Per-session listeners and counters (connections, bytes, denies) used for rate and volume limits; no persistent state.

## Failure modes and fail-closed behaviour

- Listener not ready: session start fails ([[I2 Fail-Closed Launch]]).
- Unknown session (for example a stale macOS sentinel): reject.
- Canonicaliser reject, resolver failure, policy error: deny.
- Broker crash: the sandbox has no other route, so all egress stops.
- Non-TCP traffic: UDP and ICMP have no route in the netns; QUIC therefore fails and clients fall back to TCP, as E2B recommends because "QUIC defeats domain filtering" ([E2B docs](https://docs.e2b.dev/network/internet-access.md)).

## Security considerations

- **Parser differentials.** Every ingress mode passes raw bytes to one canonicaliser; no mode does its own string checks ([[I6 Single Canonicaliser]]).
- **SNI-less and SSH.** Deny SSH and other SNI-less protocols by default; Vercel documents that a catch-all `*` lets SSH pass unbrokered ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)).
- **IP literals.** A raw-IP CIDR allow rule bypasses SNI checks and leaves DNS open ([Vercel docs](https://vercel.com/docs/sandbox/concepts/firewall)); IP-literal CONNECTs are denied by default.
- **Nested proxies.** SOCKS inside CONNECT and similar tunnels are covered by conformance category 5.
- **macOS loopback.** Any local process can reach a loopback port, so the sentinel is mandatory on every connection; it is consumed here and never forwarded ([[I7 Reject Foreign Credentials]]).

## Performance budget

Added latency on a warm connection p50 ≤5 ms and p95 ≤25 ms; new terminated connection p50 ≤15 ms ([[L4 Product Metrics]]). A reference netns, iptables and MITM design added about 14 ms per HTTPS request on an EC2 t3.medium ([dev.to](https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o)).

## Invariants upheld

[[I6 Single Canonicaliser]] (all modes feed one canonicaliser), [[I2 Fail-Closed Launch]] (readiness before launch), [[I7 Reject Foreign Credentials]] (loopback sentinel consumed, not forwarded), and the topology half of [[I1 No Secrets in the Sandbox]] (no direct route to any secret-bearing service).

## Test plan

- Unit: SOCKS5 and CONNECT request parsers with malformed inputs.
- Fuzz: `cargo-fuzz` targets for the CONNECT line parser, SOCKS5 handshake and ClientHello SNI peek.
- Property: for every ingress mode, the same destination bytes yield the same decision.
- Conformance: categories 3, 4, 5, 7 and 9 of [[Conformance Probe Matrix]] through each mode; unset proxy env and use direct sockets (must fail); `curl` to a non-allowlisted host fails ([[M0 Contained Run]]).

## Dependencies

`tokio`, `hyper` 1.x for CONNECT handling, `nix` (namespaces, `SO_ORIGINAL_DST`), nftables tooling inside the namespace, a SOCKS5 implementation (not selected in the record). Versions unverified.

## How it connects

- implements:: [[Topology-Forced Egress]]
- implements:: [[Trust Boundaries]]
- depends-on:: [[Hostname Canonicaliser]]
- depends-on:: [[Broker DNS Resolver]]
- depends-on:: [[Sandbox Launcher]]
- depends-on:: [[Core Trait Contracts]]
- contrasts-with:: [[MCP Gateways]]
- evaluated-by:: [[Conformance Probe Matrix]]
- evaluated-by:: [[L4 Product Metrics]]
- delivered-by:: [[M0 Contained Run]]
- decided-by:: [[ADR-003 Topology-Enforced Egress]]

## Implications for the build

- M0 scope is CONNECT and SOCKS5 with a host allowlist, the canonicaliser and broker DNS; the transparent listener can follow within M0 on Linux once the UDS bridge works.
- The macOS path must be tested with clients that ignore proxy variables to confirm they fail rather than bypass.
- Rate and volume counters live here because allowed domains remain exfiltration channels (learning-loop mitigations).

## Open questions

- Transparent interception on macOS without a Network Extension is unvalidated ([[Open Questions and Unverified Claims]]).
- Choice between a namespace-side bridge process (srt uses socat) and an in-process relay; latency and attack-surface trade-off not measured.
- IPv6 handling inside the namespace (research note 01: block IPv6 unless proxied).

## Sources

- https://dev.to/skwuwu/controlling-ai-agent-outbound-traffic-at-the-kernel-level14ms-overhead-2p8o
- https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes
- https://docs.stacklok.com/toolhive/guides-cli/network-isolation
- https://github.com/anthropic-experimental/sandbox-runtime
- https://vercel.com/blog/a-sandbox-without-a-network-boundary-is-only-half-a-sandbox
- https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md
- https://docs.e2b.dev/network/internet-access.md
- https://vercel.com/docs/sandbox/concepts/firewall
- https://blog.cloudflare.com/sandbox-auth/
- Report: "Topology forces traffic through the broker", ingress-mode Proposal, Interfaces (macOS sentinel), `SandboxSpec.egress`; research notes 01 Q5, 03 Q4 and 05 section 3.2.
