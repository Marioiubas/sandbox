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

Build from source (Rust 1.96 or newer):

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

Useful commands: `broker audit verify` checks the hash chain,
`broker audit tail` shows recent rows, `broker learn -- <agent>` records a
session for `broker suggest`, and `broker daemon stop` stops the daemon
(it also exits on its own when idle and nobody is signed in).

## What it does not do

The broker limits what an agent can reach and keeps secrets out of it; it
does not make the agent trustworthy. Read `docs/threat-model.md` before
relying on it.
