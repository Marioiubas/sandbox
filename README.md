# sandbox

A vendor-neutral egress and credential broker plus sandbox for AI coding
agents: capability-based sandboxing for autonomous agents.

`broker run -- claude` (or `codex`, `gemini`, any command) starts the agent
inside the operating system's own sandbox (Seatbelt on macOS; bubblewrap with
no network interface, Landlock and seccomp on Linux) and makes the broker's
egress proxy the only way out. The proxy canonicalises every destination
once, resolves DNS itself, enforces a host allowlist and writes every
decision to a hash-chained audit log outside the sandbox.

It limits what a hijacked agent can reach to the task's grants and records
every decision. It does **not** stop an injected agent from misusing
authority the task legitimately holds. See
[`code/docs/threat-model.md`](code/docs/threat-model.md).

## Repository layout

- The top level is an Obsidian vault: the design record (threat model,
  architecture, invariants I1-I9, milestones, decisions). Start at
  [`00 Home.md`](00%20Home.md); the build contract is [`CLAUDE.md`](CLAUDE.md).
- [`code/`](code/) is the product: an Apache-2.0 Rust workspace.

## Status

Milestones **M0 (contained run)** and **M1 (secrets outside)** are
implemented and tested; see [`00-meta/Build Log.md`](00-meta/Build%20Log.md)
for exactly what is and is not verified yet. Since M1 the sandbox holds only
per-session sentinels: the broker terminates TLS where rules or credentials
apply, attaches real credentials after authorization (including Claude
Code's own login), rejects credentials it did not issue, and scopes git
pushes per repository, branch and force.

## Quick start

```sh
cd code
cargo build --release --workspace --bins
./target/release/broker doctor          # every isolation layer, per host
./target/release/broker run -- claude   # built-in claude-code profile
./target/release/broker why <request-id>
./target/release/broker audit verify
```

On Ubuntu 23.10 or newer, install `code/packaging/apparmor/broker-bwrap` so
bubblewrap may create user namespaces. Grants live in
`~/.config/broker/broker.toml` ([policy reference](code/docs/policy-reference.md)).

## Tests

```sh
cd code
cargo build --workspace --bins
cargo test --workspace
```

The conformance suite runs deterministic probes inside real sessions
(name resolution, IP literals, alternate protocols, proxy bypass,
filesystem, credential exposure, planted keys, redirects, Host/SNI
mismatch, HTTP framing, git push scoping against a fake GitHub) plus
invariant tests, and replays the public bypass corpus in
`code/tests/bypass-corpus/` through every ingress mode. The end-to-end
check `code/tests/e2e/fix_failing_test.sh claude` needs a logged-in Claude
Code.
