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
host, a request no rule matches is **denied**. A plain entry (only `host`,
`ports`, address keys) admits the connection and nothing more: if another
rule terminates the same host, the plain entry allows no request there.

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
  merging need approval, and a forced push needs a `force = true` rule; a
  repository layer only narrows.
- **Narrowing** (exit 2): with `--baseline`, every request the new policy
  allows must be allowed by the old one. Otherwise the report shows the
  requests it newly permits; that is a change for a human to approve.
- `broker suggest` runs the same gates on its proposal.

A proof covers the policy text. Whether the broker turns hosts, paths and
refs into the right values is tested separately by the conformance suite.

## Exporting to vendor configs (M2)

`broker policy export --target claude-code --profile claude-code` prints a
Claude Code `managed-settings.json`; `--target codex` prints a Codex
`requirements.toml`. They are a second layer inside the agent, compiled
from the same policy: domain allows only on the ports the broker admits,
the org ceiling as denies, the vendor's fail-closed switches, and the
credential stores as deny-read paths. Method, path and git rules,
credentials and address checks stay with the broker; the export report on
stderr lists them. The broker never installs these files: deploy them with
your MDM (`/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`,
`/etc/codex/`), and keep running agents under `broker run`.

## Trying a policy change in shadow mode (M2)

`broker policy shadow candidate.toml` makes every later `broker run`
session evaluate `candidate.toml` (in place of your `broker.toml`) beside
your policy. Your policy still decides everything; each decision records
what the candidate would have done, and `broker why <request-id>` shows
it. `broker policy shadow --report` lists the requests the candidate would
deny that your policy allowed, and those it would allow that your policy
denied. `broker policy shadow --off` ends it. `broker learn` sessions are
never shadowed. To enforce a candidate, make it your `broker.toml`.

## The GitHub API (M3)

```toml
[[egress]]
host = "api.github.com"
protocol = "github"
verbs = ["repo.read", "pr.create", "issue.comment"]   # never pr.merge by default
repos = ["${repo_remote}"]                           # absent = the task repository only
credential = { kind = "github_app", issuer = "acme", permissions = { contents = "read", pull_requests = "write" }, repos = ["${repo_remote}"] }

[issuers.github_app.acme]               # as in "Terminated hosts" above
app_id = "123456"
installation_id = "7890123"
private_key = "keychain:broker-github-app-acme"
```

Every request on a GitHub grant is a verb, or it is denied: `repo.read`
(`GET` under `/repos/{owner}/{repo}`), `pr.create`, `pr.merge`,
`issue.comment`, `contents.write`, `gist.create`, and `github.read` (other
reads). Unmapped routes are denied. `pr.merge` also needs approval. The
broker looks up each repository's visibility itself and tracks two session
labels: reading a private repository sets **sensitive read**, and reading
issue or PR text (or search results) from a public repository sets
**untrusted input**. Host-wide reads (`github.read`: search, your
repository list, notifications) count as sensitive reads too, because they
can return private repositories; only API metadata, rate limits and
license, gitignore and code-of-conduct templates do not. Cloning or
fetching a repository with git also counts as a sensitive read unless the
repository is public (the broker checks by asking the git host, without
credentials, whether anyone may fetch it). Once both labels
are set, every write in that session is denied (the Rule of Two). A new
`broker run` starts a new session. Mark a credential `risk = "high"` to
treat any use of it as a sensitive read.

**GraphQL** (`POST /graphql`, which `gh` and the GitHub MCP server use)
maps to the same verbs:

| GraphQL | Verb |
|---|---|
| `repository(owner:, name:) { … }` | `repo.read` on that repository |
| `viewer`, `user`, `repositoryOwner`, `rateLimit`, introspection | `github.read` (public data) |
| `createPullRequest` | `pr.create` |
| `mergePullRequest`, `enablePullRequestAutoMerge`, `enqueuePullRequest` | `pr.merge` |
| `addComment` | `issue.comment` |
| any other query field (`search`, `node`, `organization`, …) | `github.read` (sensitive) |

Any other mutation is denied. Mutations name repositories by node ID; the
broker asks GitHub which repository an ID belongs to (with the grant's own
credential) before deciding. A read that reaches beyond one repository
(an owner's other repositories, a pull request's fork, timelines,
projects) also counts as a sensitive host-wide `github.read`. The request
must be JSON (`Content-Type: application/json`) without a query string;
documents the broker cannot read strictly are denied
(`github_graphql_invalid`).

For a stricter rule, your own or your org's policy can deny writes to
public destinations as soon as a session has read untrusted input, even if
it has read nothing sensitive:

```toml
[trifecta]                              # user or org policy only
deny_public_sinks_after_untrusted_input = true
```

With this on, after untrusted input the session cannot open PRs, comment
or write contents on a repository unless the broker knows it is private,
cannot push (pushes carry no visibility, so every push counts), and cannot
create gists or publish packages. Reads still work. The reason in the audit
log is `public_sink_after_untrusted_input`.

## MCP servers (M3)

```toml
[mcp.github]
command = ["/usr/local/bin/github-mcp-server", "stdio"]   # an absolute path
tools.write = ["create_pull_request", "add_issue_comment"]  # external effects
tools.untrusted = ["get_issue", "list_issues"]               # results anyone can write
tools.deny = ["merge_pull_request"]

[[mcp.github.egress]]                   # the server's own grants, nothing else
host = "api.github.com"
protocol = "github"
verbs = ["repo.read", "issue.comment", "pr.create"]
credential = { kind = "static", ref = "keychain:broker-github-mcp", env = "GITHUB_PERSONAL_ACCESS_TOKEN" }
```

Point the agent's MCP configuration at the stub, never at the server:
`{"command": "broker", "args": ["mcp", "connect", "github"]}`. On first
use the server is refused until you run `broker mcp approve github` on
the host, which shows every tool and what changed since the last approval.
Any later change to the server's tools revokes it until you approve again.
The server runs in its own sandbox, and its token reaches it only as a
sentinel. Every tool call is authorized and logged. Resources, prompts and
the server's own requests (such as sampling) are not relayed.
Only your own or your org's policy can define servers; a repository cannot.

## CI identity (M3)

```toml
[[identity.oidc]]                       # user or org policy only
issuer = "https://token.actions.githubusercontent.com"
audience = "broker"
# jwks_url = "https://…"                # default: the issuer's discovery document
# jwks_file = "gha-jwks.json"           # or a key set in the config directory
```

In CI, the GitHub Action (`code/integrations/github-action`) asks the
runner for an OIDC token with this audience and passes it to `broker run`
outside the agent's environment. The broker checks it against the issuers
listed here (RS256 signature, exact issuer and audience, not expired). The
session and every audit row are then attributed to the token's subject,
for example `repo:acme/web:ref:refs/heads/main` (some repositories' subjects
also embed owner and repository IDs; the `repository` claim is recorded too). A token that does not
check out stops the run. The token is never given to the agent or sent
anywhere else.

## Signing in (M3)

```toml
[identity.login]                        # user or org policy only
issuer = "https://acme.okta.com"        # or https://login.microsoftonline.com/<tenant>/v2.0
client_id = "0oa1b2c3d4"                # a public client with the device flow enabled
scopes = ["openid", "profile", "groups", "offline_access"]   # openid is required
# groups_claim = "groups"               # the ID-token claim listing the user's groups
# required = true                       # refuse sessions until someone signs in
# max_age = "12h"                       # sign in again after this (at most 7d)
```

`broker login` prints a web address and a short code. Open the address,
check that it shows the same code, and sign in there. The broker checks
the ID token it receives (issuer, audience, expiry and signature) and from
then on names every new session, and every row in the audit log, after
your IdP subject and groups. Policies can test group membership
(`principal.owner in Broker::Group::"eng"`). `broker login --status` shows
who is signed in; `broker logout` signs out.

The login lives in the daemon's memory only: no token is written to disk,
given to an agent, logged, or sent to any upstream or MCP server. The
daemon renews the ID token with a refresh token when one was issued
(`offline_access`), and stays running while you are signed in. After a
restart, sign in again. Without `required`, sessions with no current login
are named after the local user.

## Amazon S3 through STS (M3)

```toml
[[egress]]
host = "acme-data.s3.us-east-1.amazonaws.com"   # or s3.us-east-1.amazonaws.com (path-style)
protocol = "s3"
s3 = { bucket = "acme-data", read = ["tasks/123/"], write = ["tasks/123/out/"] }   # delete = [...] too
credential = { kind = "aws_sts", issuer = "dev" }

[issuers.aws_sts.dev]                   # user or org policy only
role_arn = "arn:aws:iam::123456789012:role/agent-s3"
region = "us-east-1"
access_key_id = "keychain:broker-aws-dev#access_key_id"          # base credentials that may assume the role
secret_access_key = "keychain:broker-aws-dev#secret_access_key"
# duration = "15m"                      # 15m (default) to 12h, within the role's maximum
# source_identity = true                # the trust policy must allow sts:SetSourceIdentity
```

Each request on an S3 grant is a read (`GetObject`, `HeadObject`), a
listing (`ListObjects`, `ListObjectsV2` on a `prefix`), a write
(`PutObject` and the multipart-upload calls) or a delete (`DeleteObject`),
and it is allowed only on the grant's bucket and under its prefixes.
Everything else is denied: bucket and object settings (`?acl`, `?policy`,
`?tagging`, …), versioned access, copies, batch deletes, presigned URLs,
requests that set ACLs, tags or object locks, and uploads that sign each
chunk. Prefixes are literal (no `*`, `?` or `$`); a prefix of `""` means
the whole bucket.

The agent gets `AWS_ACCESS_KEY_ID` set to a sentinel and
`AWS_SECRET_ACCESS_KEY` set to a placeholder, so AWS SDKs and
`curl --aws-sigv4` sign requests as usual. The broker checks each request,
strips the agent's signature and signs the request again with a session
it gets from STS `AssumeRole`. That session is limited by an inline session
policy the broker builds from the grant (same bucket, same prefixes), so AWS
refuses anything outside them even without the broker's own check. Sessions
last 15 minutes by default, are reused within a `broker run`, and never
enter the sandbox. The role's own policy is the upper limit: a session
policy can only narrow it. With `source_identity` on (the default), the
session's user appears in CloudTrail as `SourceIdentity`.
