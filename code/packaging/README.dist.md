# broker (prebuilt)

The broker limits what an AI coding agent can reach and keeps secrets out
of its sandbox. It does not make the agent trustworthy: read the threat
model before relying on it.

## What is in this archive

| File | What it is |
|---|---|
| `broker` | the command you run |
| `brokerd` | the per-user daemon, started on demand by `broker` |
| `broker-sandbox-shim` | checks the sandbox from the inside before the agent starts |
| `apparmor/broker-bwrap` | Linux only: AppArmor profile for Ubuntu 23.10 and newer |
| `sbom/` | CycloneDX SBOMs of the three programs |
| `LICENSE` | Apache-2.0 |

## Install

Keep the three programs together in one directory that your agents cannot
write: `broker` starts `brokerd` from its own directory, and `brokerd` runs
`broker-sandbox-shim` from its own directory.

```bash
sudo install -m 0755 broker brokerd broker-sandbox-shim /usr/local/bin/
broker doctor
```

Linux also needs `bubblewrap` at `/usr/bin/bwrap`. On Ubuntu 23.10 and newer,
where AppArmor restricts unprivileged user namespaces, load the profile
(it lets only `/usr/bin/bwrap` create one; it does not change the sysctl):

```bash
sudo install -m 0644 apparmor/broker-bwrap /etc/apparmor.d/broker-bwrap
sudo apparmor_parser -r /etc/apparmor.d/broker-bwrap
```

The macOS build is not signed or notarised yet; see the packages guide.

## More

- Packages, signatures and provenance:
  https://github.com/Marioiubas/sandbox/blob/main/code/docs/deployment/packages.md
- Running on a laptop:
  https://github.com/Marioiubas/sandbox/blob/main/code/docs/deployment/laptop.md
- Threat model:
  https://github.com/Marioiubas/sandbox/blob/main/code/docs/threat-model.md
