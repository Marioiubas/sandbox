# Running the broker in CI (GitHub Actions)

In CI the broker runs the agent the same way as on a laptop, and the
session is attributed to the workflow run: the runner's OIDC identity token
names it. The agent never sees the job's secrets, the runner's tokens or the
token `actions/checkout` stores in `.git/config`.

## Job setup

```yaml
permissions:
  contents: read
  id-token: write            # the runner's identity token
steps:
  - uses: actions/checkout@v4
  # 1. Install broker, brokerd and broker-sandbox-shim on PATH, outside the
  #    workspace (the broker refuses binaries the agent could overwrite).
  # 2. On Ubuntu 24.04 runners, allow bubblewrap's user namespace:
  #    install packaging/apparmor/broker-bwrap (see the laptop guide).
  # 3. Write broker.toml into BROKER_HOME, outside the workspace (below).
  - uses: <owner>/<repo>/code/integrations/github-action@<ref>
    with:
      command: claude -p "fix the failing test"
      audience: broker
```

`BROKER_HOME/config/broker.toml` must trust the runner's issuer, and holds
the job's grants and credential sources like any policy:

```toml
version = 1

[[identity.oidc]]
issuer = "https://token.actions.githubusercontent.com"
audience = "broker"
```

Credentials the agent needs come from the broker, not from the job's
environment: reference CI secrets in `brokerd`'s environment with
`env:NAME` (they reach the broker, not the agent), or mint them with
`github_app` or `aws_sts` issuers.

## What the action does

It removes the persisted checkout token from `.git/config`, asks the
runner for an OIDC token for `audience`, and passes it to `broker run`
outside the agent's environment. The daemon verifies it (RS256 signature
with GitHub's published keys, exact issuer and audience, not expired). The
session and every audit row are then attributed to its subject, and
`session.start` records the claims (repository, ref, workflow, run ID). A
token that does not verify stops the job.

Attribution checks should use the `repository` and `run_id` claims: the
subject's format varies (some repositories' subjects embed owner and
repository IDs).

## After the run

`broker audit query --kind session.start --json` lists the session with
its identity; `broker audit export` sends rows to a SIEM (OCSF). The audit
database is in `BROKER_HOME/state/` if you want to keep it as an artifact.

This repository's own `ci-mode` job runs a scripted agent against an
attacker-written issue (`code/tests/e2e/ci_untrusted_issue/`) and checks
that no runner token, job secret or checkout token is visible to it.
