# Running the broker on a laptop

The broker is two programs and a helper: `broker` (the command you run),
`brokerd` (a per-user daemon that `broker` starts when needed) and
`broker-sandbox-shim` (checks the sandbox from the inside before the agent
starts). Keep all three in one directory.

## Requirements

| | macOS | Linux |
|---|---|---|
| Sandbox | `sandbox-exec` (Seatbelt), part of macOS | `bubblewrap` in `/usr/bin` or `/usr/local/bin`, unprivileged user and network namespaces, seccomp, Landlock (ABI 1 or newer) |
| Optional | | Landlock ABI 4 or newer, which also limits outbound TCP to the broker |
| Tools inside sessions | `curl`, `git` and your agent, as usual | the same |

On Ubuntu 23.10 and newer, AppArmor blocks unprivileged user namespaces by
default. Install the profile in `packaging/apparmor/broker-bwrap`, which
lets only the system `bwrap` create one:

```bash
sudo install -m 0644 packaging/apparmor/broker-bwrap /etc/apparmor.d/broker-bwrap
```

```bash
sudo apparmor_parser -r /etc/apparmor.d/broker-bwrap
```

`broker doctor` checks every layer. `broker run` refuses to start an agent
if any required layer is missing; there is no flag that skips a layer.

## Install

Prebuilt `.deb`, `.rpm`, static Linux tarballs and a macOS build are
described in `packages.md`. Or build from source (Rust 1.96 or newer):

```bash
cargo build --release --locked --manifest-path code/Cargo.toml
```

Copy `broker`, `brokerd` and `broker-sandbox-shim` from
`code/target/release/` to a directory on your `PATH` that your agents
cannot write, for example `/usr/local/bin`. The broker refuses to run from
a directory inside a writable mount, such as the repository you run the
agent in.

## Where things live

| | macOS | Linux |
|---|---|---|
| Your policy | `~/.config/broker/broker.toml` | `~/.config/broker/broker.toml` |
| Audit log (hash-chained) | `~/Library/Application Support/broker/audit.db` | `$XDG_STATE_HOME/broker/audit.db` (default `~/.local/state/broker/`) |
| Daemon socket | `~/Library/Application Support/broker/run/` | `$XDG_RUNTIME_DIR/broker/` |

Setting `BROKER_HOME` puts all three under one directory instead (for tests
and CI). None of these paths is readable or writable from inside a session.

## First run

1. Write a policy. With none, sessions get only the built-in agent
   profile's grants. `docs/policy-reference.md` describes every key.
2. Run `broker doctor`: every required layer should say `ok`, and each of
   your grants shows whether its TLS is terminated, spliced or passed
   through.
3. Run your agent: `broker run -- claude`. Denied requests print a request
   ID; `broker why <id>` explains the decision.
4. Optionally sign in to your identity provider with `broker login` (see
   `[identity.login]`), so sessions and audit rows carry your IdP identity
   and groups.

Useful commands: `broker learn -- <agent>` records a
session for `broker suggest`, and `broker daemon stop` stops the daemon
(it also exits on its own when idle and nobody is signed in).

## Reading the record

Every decision is a row in the hash-chained audit log, attributed to you,
the agent (with its binary's hash), the task and the session.

- `broker why <request-id>`: why one request was allowed or denied.
- `broker audit tail` and `broker audit query --session <id> --decision deny`:
  rows; `--json` for scripts.
- `broker audit stats`: per session, allows, denies by reason, approval
  prompts and grants, and refusals by the sandbox itself.
- `broker approvals`, then `broker approve <id>`: a write held back for your
  approval (the Rule of Two, merges, an MCP write tool), with exactly what
  would be allowed and, for an MCP call, every argument. Approve once, or
  for the rest of the session with `--for-session`.
- `broker audit verify`: checks the chain; `broker audit export` sends rows
  to a SIEM as OCSF.

Refusals by the sandbox itself (a blocked file write, a direct connection,
a forbidden system call) appear as `kernel.denied` rows: on macOS from the
kernel's own reports, on Linux for the system calls seccomp refuses.
Landlock and mount refusals on Linux are enforced but not recorded there
(with host audit enabled they reach the host's audit log). `broker doctor`
says which applies on your machine. A missing row proves nothing: the
kernel refuses either way.

## Known limitation: Go programs on macOS

Programs written in Go (for example `gh` and the GitHub MCP server) verify
TLS certificates on macOS only through the system's trust service. They
ignore `SSL_CERT_FILE`, so they cannot trust the broker's per-session
certificate authority, and inside a session the trust service is not
reachable at all. Their HTTPS requests fail with `x509: OSStatus -26276`.
The broker never adds its authority to a system trust store, so there is
no workaround on macOS today; run such tools under the broker on Linux,
where Go honours `SSL_CERT_FILE`.

## What it does not do

The broker limits what an agent can reach and keeps secrets out of it; it
does not make the agent trustworthy. Read `docs/threat-model.md` before
relying on it.
