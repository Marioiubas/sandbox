# Policy reference (M0)

User policy lives in `~/.config/broker/broker.toml` (or
`$BROKER_HOME/config/broker.toml`). It is read by `brokerd`, outside every
sandbox, and merged with the built-in profile of the agent you run.
Repository files (`.broker/`) are **not** loaded in M0; they arrive in M2,
only after content-hash approval, and can only narrow policy.

Everything fails closed: an empty or missing list grants nothing, unknown keys
are errors (the session is refused), and a host that matches no grant is
denied.

```toml
version = 1

[[egress]]
id = "github-api"              # optional; shown in audit rows and `broker why`
host = "api.github.com"        # one canonical host, or "*.example.com"
ports = [443]                  # optional; default [443]; [] grants nothing

[[egress]]
host = "*.githubusercontent.com"

[[egress]]
host = "registry.internal.example"
addrs = ["10.20.30.40"]        # optional pinned addresses; no DNS query is made
allow_addr_classes = ["private"]  # needed to reach a non-public address

[filesystem]
write = ["~/scratch"]          # extra writable roots (never $HOME itself)
deny_read = ["~/secrets"]      # added to the built-in secret list
```

## Host patterns

- `api.github.com` matches exactly that host.
- `*.example.com` matches `a.example.com` and `a.b.example.com`, never
  `example.com` itself and never `evilexample.com`.
- A bare `*`, a wildcard over a public suffix (`*.com`, `*.github.io`) and a
  wildcard over an IP literal are rejected.
- Patterns go through the same canonicaliser as runtime traffic, so a
  pattern can never mean something different at runtime.

## Address classes

Every address the broker resolves for a granted name must be `public`, or a
class the grant lists: `loopback`, `link_local`, `private`, `reserved`,
`metadata`. One disallowed address denies the whole name. IP-literal
destinations are denied unless a grant names the literal.

## Keys that arrive later

`protocol`, `methods`, `allow` (git fetch and push rules) and `credential`
are rejected in M0 rather than silently ignored. They arrive with TLS
termination, the git adapter and credential minting in M1.
