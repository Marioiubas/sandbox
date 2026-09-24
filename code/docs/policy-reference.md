# Policy reference (M1)

User policy lives in `~/.config/broker/broker.toml` (or
`$BROKER_HOME/config/broker.toml`). It is read by `brokerd`, outside every
sandbox, and merged with the built-in profile of the agent you run.
Repository files (`.broker/`) are **not** loaded yet; they arrive in M2,
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
host = "raw.githubusercontent.com"   # githubusercontent.com is a public suffix: no wildcard

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
- A bare `*`, a wildcard over a public suffix (`*.com`, and private
  suffixes such as `*.github.io` or `*.githubusercontent.com`) and a wildcard
  over an IP literal are rejected.
- Patterns go through the same canonicaliser as runtime traffic, so a
  pattern can never mean something different at runtime.

## Address classes

Every address the broker resolves for a granted name must be `public`, or a
class the grant lists: `loopback`, `link_local`, `private`, `reserved`,
`metadata`. One disallowed address denies the whole name. IP-literal
destinations are denied unless a grant names the literal.

## Terminated hosts (L7, M1)

A grant with any of `protocol`, `methods`, `paths`, `allow` or `credential`
makes the broker terminate TLS for that host (with a per-session CA the
sandbox trusts through `SSL_CERT_FILE` and friends) and authorize every
request. Everything else is spliced without decryption. Within a terminated
host, a request no rule matches is **denied**.

```toml
# An LLM API: only these calls, with a key the sandbox never sees.
[[egress]]
host = "api.anthropic.com"
methods = ["POST"]                      # absent = any method, [] = none
paths = ["/v1/messages", "/v1/messages/*"]  # `*` one segment, `**` any
credential = { kind = "static", ref = "keychain:broker-anthropic-api-key", header = "x-api-key", env = "ANTHROPIC_API_KEY" }

# A read-only package registry (GET and HEAD unless `methods` says otherwise).
[[egress]]
host = "registry.npmjs.org"
protocol = "registry"

# git over HTTPS: fetch the session repo; push only agent/* there, never force.
[[egress]]
host = "github.com"
protocol = "git"
allow = { fetch = ["${repo_remote}"], push = { repo = "${repo_remote}", refs = ["agent/*"], force = false } }
credential = { kind = "github_app", issuer = "acme", permissions = { contents = "write" }, repos = ["${repo_remote}"], ttl = "30m" }

# A client that pins certificates: never terminated, never given a credential.
[[egress]]
host = "pinned.example.com"
passthrough = true

# User or org scope only.
[issuers.github_app.acme]
app_id = "123456"
installation_id = "7890123"
private_key = "keychain:broker-github-app-acme"   # the app's PEM key
# api_base = "https://ghe.example.com/api/v3"     # GitHub Enterprise Server

[tls]
extra_roots = ["corp-root.pem"]   # private CAs for upstream verification (never the host store)
```

- **Credentials.** `ref` names where brokerd reads the secret:
  `keychain:<service>[/<account>]` (macOS Keychain, or libsecret via
  `secret-tool`), `env:<VAR>` (brokerd's own environment), `file:<name>`
  (0600 file in the broker config dir) or `file:~/<path>` (0600 file in your
  home), optionally `#a.b` to select a JSON string field, and `a|b` to try
  alternatives in order. The sandbox gets only a per-session sentinel (in
  `env`, if given). The broker attaches the credential to requests the rule
  allows, strips every client credential header, and rejects any credential
  it did not issue (including cookies). `github_app` tokens are always
  limited to `repos` and `permissions`, last at most an hour, and are reused
  only for the same scope.
- **`${repo_remote}`** is the `origin` remote of the checkout you run in
  (read from `.git/config`, never by running git). Outside a checkout, rules
  that use it grant nothing.
- **Pushes.** Each ref update is authorized separately and one denied ref
  denies the push. A push is a fast-forward only if the pushed commits reach
  the old tip; otherwise (including deletes) it counts as `force`.
- **Redirects** are not followed by the broker: the client's next request is
  authorized afresh, and carries no credential unless that host's rule
  attaches one.
- **Not on terminated hosts:** WebSocket/h2c upgrades, HTTP/2, cookies.

## Built-in agent profiles

`claude` runs under `claude-code`, which brokers Claude Code's OAuth token
from its keychain item (or `~/.claude/.credentials.json` on Linux) behind a
sentinel in `CLAUDE_CODE_OAUTH_TOKEN`. API-key users run
`broker run --profile claude-code-apikey -- claude` with the key in the
keychain item `broker-anthropic-api-key` (or `ANTHROPIC_API_KEY` in the
environment that starts brokerd). `codex` and `gemini` broker
`OPENAI_API_KEY` and `GEMINI_API_KEY` the same way; their account-login modes
are not brokered yet and fail closed.

## Checking a policy change (M2)

`broker policy check` proves properties of the compiled policy with
Cedar's symbolic analyzer. It needs cvc5 1.3.1 (the `CVC5` environment
variable, or `cvc5` on `PATH`).

```sh
broker policy check --profile claude-code                 # your broker.toml
broker policy check --policy new.toml --baseline old.toml # a proposed change
broker policy check --repo                                # with .broker/ policy
```

- **Hard gates** (exit 1 on failure; no override): the org ceiling holds;
  each brokered credential is used only for its declared hosts; no policy
  can hit an evaluation error; every deny rule can fire, publishing and
  merging need approval, and a forced push needs a `force = true` rule (or
  a plain host grant, whose traffic is not inspected); a repository layer
  only narrows.
- **Narrowing** (exit 2): with `--baseline`, every request the new policy
  allows must be allowed by the old one. Otherwise the report shows the
  requests it newly permits; that is a change for a human to approve.
- `broker suggest` runs the same gates on its proposal.

A proof covers the policy text. Whether the broker turns hosts, paths and
refs into the right values is tested separately by the conformance suite.
