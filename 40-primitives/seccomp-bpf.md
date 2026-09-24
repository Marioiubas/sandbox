---
title: "seccomp-bpf"
aliases: ["seccomp", "apply-seccomp"]
type: "primitive"
section: "primitives"
summary: "Syscall filtering that blocks new AF_UNIX sockets after the broker bridge is set up, plus ptrace, bpf, raw sockets and keyctl, so the sandbox cannot open other channels or reach the control socket; cgroup sock_addr eBPF as a redirect alternative."
tags: [sandbox/primitives, primitive, topic/isolation, topic/egress, platform/linux, control/iso, control/egress, boundary/tb2, boundary/tb3, milestone/m0]
status: verified
confidence: high
milestone: M0
created: 2026-09-24
updated: 2026-09-24
related: ["[[bubblewrap]]", "[[Landlock]]", "[[Sandbox Launcher]]", "[[Topology-Forced Egress]]", "[[Broker CLI and Daemon]]", "[[Tech Stack]]", "[[I2 Fail-Closed Launch]]", "[[ADR-003 Topology-Enforced Egress]]", "[[Open Questions and Unverified Claims]]"]
---

# seccomp-bpf

seccomp-bpf attaches a classic-BPF filter to a process that decides, per system call and its register arguments, whether the kernel allows it, fails it with an errno, traps or kills. In the broker's Linux standard tier it closes every channel that the empty network namespace does not: after the in-sandbox bridge to the broker is up, it forbids creating new `AF_UNIX` sockets (so the sandbox can never reach `brokerd`'s control socket), plus `ptrace`, `bpf`, raw sockets and `keyctl`. cgroup `sock_addr` eBPF programs are the related redirect mechanism, noted here as an alternative.

## Mechanism

- The filter is installed with `PR_SET_NO_NEW_PRIVS` set (Codex does both) and is inherited across `fork` and `execve`; it cannot be removed, only further restricted ([Codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md) for the NNP-plus-filter pattern; inheritance semantics are background knowledge).
- Filters see the syscall number and raw argument registers only. They **cannot dereference pointers**, so they cannot inspect a `connect(2)` path or address (background knowledge, not in the record). That is why the sandbox recipes block socket *creation* by address family rather than trying to filter which socket path is connected.
- `SECCOMP_RET_TRAP` delivers `SIGSYS` to the thread; gVisor's Systrap platform is built on exactly this ("the kernel send[s] SIGSYS to the triggering thread") ([gVisor platforms](https://gvisor.dev/docs/architecture_guide/platforms/)).
- **TCB and cost.** In-kernel BPF evaluation per syscall; overhead is negligible compared with the proxy hop (no figure in the record).

## How srt and Codex use it

| Product | What the filter does | When it is applied | Source |
|---|---|---|---|
| Anthropic srt | a prebuilt static `apply-seccomp` blocks new `AF_UNIX` socket creation, run via "a nested user+PID+mount namespace"; only x64 and arm64 are supported, others need `allowAllUnixSockets` | after the socat bridges to the host proxies exist | [srt](https://github.com/anthropic-experimental/sandbox-runtime) |
| OpenAI Codex CLI | in-process seccomp network filter with `PR_SET_NO_NEW_PRIVS`; in managed-proxy mode, after the TCP→UDS→TCP bridge is created, blocks new `AF_UNIX` and `socketpair` "so the command can't create other UDS channels" | after the bridge | [Codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md) |
| Claude Code | seccomp filter is optional on Linux | n/a | [Claude Code docs](https://code.claude.com/docs/en/sandboxing) |

The ordering matters: the bridge needs one UDS to the host; everything after that must be unable to create another. The broker adopts the same ordering. Claude Code's "optional" seccomp is a posture the broker rejects: under [[I2 Fail-Closed Launch]] a missing seccomp layer refuses launch.

## The broker's filter (Proposal)

**Proposal** (report Linux-laptop row and interfaces paragraph). Default action for listed calls is `EPERM` (so tools fail loudly rather than being killed), with the rest allowed:

| Syscall / argument | Rule | Why |
|---|---|---|
| `socket(AF_UNIX, …)`, `socketpair(AF_UNIX, …)` | deny after the bridge is up | the sandbox cannot open a new channel to `ctl.sock` or any host UDS; the control socket stays unreachable ([[Broker CLI and Daemon]]) |
| `socket(AF_INET/AF_INET6, SOCK_RAW, …)`, `socket(AF_PACKET, …)` | deny | no raw sockets; the `CAP_NET_RAW` packet-socket UAF class (CVE-2025-38617) stays out of reach |
| `socket(AF_NETLINK, …)` | deny unless a tool is shown to need it | † not in the record; decide empirically |
| `ptrace`, `process_vm_readv`, `process_vm_writev` | deny | no reading of sibling processes (for example the shim's memory) |
| `bpf`, `perf_event_open` | deny | no loading of programs that could alter socket behaviour or read kernel state |
| `keyctl`, `add_key`, `request_key` | deny | kernel keyrings are a secret store outside the filesystem policy |
| `mount`, `umount2`, `pivot_root`, `unshare(CLONE_NEWUSER)`, `setns` | deny | no re-shaping of the sandbox from inside († beyond the record's list; Landlock already blocks mount topology changes) |

Rows marked † extend the record's list and must be justified by an agent-workload test before shipping.

Arguments are checked with argument comparators on the `domain`/`type` registers. Architectures without a verified filter (srt supports only x64 and arm64) must refuse launch, not fall back to "allow all unix sockets".

## cgroup `sock_addr` eBPF: the redirect alternative

- `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` attaches at `INET4/6_CONNECT`, `UDP4/6_SENDMSG`, `BIND`, `GETPEERNAME` and others; it can allow or deny, and it can **rewrite the destination address and port**, which gives transparent redirection to a proxy without the application knowing ([docs.ebpf.io](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/)).
- It needs privilege to attach (background knowledge) and keeps a NIC in the sandbox, so the report rejects "eBPF redirect only" as the egress mechanism in favour of topology ([[ADR-003 Topology-Enforced Egress]]). It remains a candidate for the Kubernetes and CI modes where the broker runs privileged on the node.

## Sharp edges

- **Architecture coverage.** Filters are per-architecture syscall tables; srt ships x64 and arm64 only ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).
- **Pointer blindness.** No path or address filtering; combine with [[Landlock]] (paths, TCP ports) and the empty netns ([[bubblewrap]]).
- **io_uring and new syscalls.** Newer kernels add syscalls that open equivalent capabilities; an allow-by-default filter must be reviewed each kernel cycle († background knowledge; consider denying `io_uring_setup` unless needed).
- **Tool breakage.** Some tools use `socketpair(AF_UNIX)` internally (for example for subprocess plumbing); the Codex filter blocks `socketpair` too, so compatibility testing across the agent matrix is required.

## Verdict for the broker

**Proposal.**

- **Use it for:** blocking new `AF_UNIX` sockets after the bridge, raw and packet sockets, `ptrace`, `bpf` and `keyctl` in every Linux standard-tier sandbox and every wrapped MCP server.
- **Don't use it for:** path or hostname policy (it cannot see them); the only layer (pair it with bwrap and Landlock).
- **How we integrate it.** In the in-sandbox shim of the `linux-native` backend ([[Sandbox Launcher]]), compiled with `seccompiler` (pure Rust) or libseccomp bindings; the record lists both and verifies neither ([[Tech Stack]]). Order: `PR_SET_NO_NEW_PRIVS` → [[Landlock]] → start the bridge listener → load seccomp → `execve` agent. `probe()` checks `CONFIG_SECCOMP_FILTER` and the architecture; the loaded filter's hash goes into the session audit event.

## How it connects

- part-of:: [[bubblewrap]] (Linux standard-tier recipe)
- depends-on:: [[Landlock]] (paths and ports that seccomp cannot see)
- delivered-by:: [[Sandbox Launcher]] (shim applies it)
- implements:: [[Topology-Forced Egress]] (no new channels besides the bridge)
- depends-on:: [[Broker CLI and Daemon]] (protects `ctl.sock` from the sandbox)
- decided-by:: [[ADR-003 Topology-Enforced Egress]] (eBPF redirect alone rejected)
- depends-on:: [[Tech Stack]] (seccompiler vs libseccomp)

## Implications for the build

- Test: from inside the sandbox, `socket(AF_UNIX)` after start returns `EPERM`; connecting to `ctl.sock` is impossible; `ptrace` of the shim fails; a raw ICMP socket fails (conformance category 5, 9).
- Fuzz nothing here, but property-test the filter compiler: every rule set produced for x86_64 and aarch64 must deny the listed calls.
- Run the agent × OS e2e matrix with the filter on; record any `socketpair` breakage as a compatibility row, not a reason to relax the filter.

## Open questions

- Exact `seccompiler` vs libseccomp choice and versions are unverified ([[Open Questions and Unverified Claims]]).
- Whether `AF_NETLINK` and `io_uring` must be denied for common agent toolchains is not in the record.

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
