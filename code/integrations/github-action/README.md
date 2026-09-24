# broker run (GitHub Action)

Runs a coding agent under the broker in a GitHub Actions job: the agent is
sandboxed, reaches the network only through the broker, and never sees the
job's secrets. The session and every audit row are attributed to the
workflow run's OIDC identity.

```yaml
permissions:
  contents: read
  id-token: write            # for the runner's identity token
steps:
  - uses: actions/checkout@v4
  # install the broker binaries on PATH first, outside the workspace
  # (the broker refuses to run from a directory the agent can write)
  - uses: <owner>/<repo>/code/integrations/github-action@<ref>
    with:
      command: claude -p "fix the failing test"
      audience: broker
```

`broker.toml` (in `BROKER_HOME`, outside the workspace) must trust the
runner's issuer:

```toml
[[identity.oidc]]
issuer = "https://token.actions.githubusercontent.com"
audience = "broker"
```

The action removes the token `actions/checkout` persists in `.git/config`
before the agent starts, requests the runner's OIDC token for the audience,
and passes it to `broker run`. The daemon verifies the token against
GitHub's published keys and records the claims; the token is never given
to the agent or forwarded anywhere. A token that does not verify stops the
job. The broker can bound what an injected agent does with the authority it
holds; it cannot make the agent ignore the instructions it reads.
