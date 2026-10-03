# Installing from packages

Each release on GitHub carries prebuilt packages for Linux (x86_64 and
aarch64) and macOS. CI creates every release as a draft; a maintainer
publishes it. Verify what you download before you install it (see
[Verify before installing](#verify-before-installing)).

## Release assets

For version `V`:

| Asset | What it is |
|---|---|
| `broker_V_amd64.deb`, `broker_V_arm64.deb` | Debian and Ubuntu packages |
| `broker-V.x86_64.rpm`, `broker-V.aarch64.rpm` | Fedora, RHEL and openSUSE packages |
| `broker-V-x86_64-unknown-linux-musl.tar.gz`, `broker-V-aarch64-unknown-linux-musl.tar.gz` | static Linux binaries (musl), any distribution |
| `broker-V-universal2-apple-darwin.tar.gz` | macOS, Apple silicon and Intel in one binary; **not signed or notarised yet** |
| `broker-V.<program>.<target>.cdx.json` | CycloneDX SBOM of each program, per target (also inside every package and tarball) |
| `SHA256SUMS` | SHA-256 of every asset above |
| `<asset>.sigstore.json` | keyless cosign signature (Sigstore bundle) of that asset |
| `broker-V.provenance.sigstore.json` | SLSA build provenance for every asset (also stored with the repository's GitHub attestations) |

Every package holds the same three programs: `broker` (the command you
run), `brokerd` (the per-user daemon `broker` starts on demand) and
`broker-sandbox-shim` (checks the sandbox from the inside). They must stay
in one directory: `broker` starts `brokerd` from its own directory and
`brokerd` runs the shim from its own directory.

## Debian and Ubuntu

```bash
sudo apt-get install ./broker_V_amd64.deb
broker doctor
```

`apt-get` pulls in `bubblewrap`. The package installs:

| Path | |
|---|---|
| `/usr/bin/broker`, `/usr/bin/brokerd`, `/usr/bin/broker-sandbox-shim` | the programs |
| `/etc/apparmor.d/broker-bwrap` | AppArmor profile for `/usr/bin/bwrap` (below) |
| `/usr/share/doc/broker/` | README, licence and the SBOMs |

### The AppArmor note (Ubuntu 23.10 and newer)

Ubuntu 23.10 and newer restrict unprivileged user namespaces through
AppArmor (`kernel.apparmor_restrict_unprivileged_userns = 1`), and
bubblewrap needs one to build the sandbox. The package ships the
`broker-bwrap` profile, which grants `userns` to `/usr/bin/bwrap` and
nothing else.

- On install, the profile is loaded with `apparmor_parser -r` only when
  AppArmor is running and the kernel exposes
  `apparmor_restrict_unprivileged_userns`. Elsewhere (Ubuntu 22.04, Debian
  without the gate) nothing is loaded.
- The installer never changes the sysctl, and never touches the system
  trust store.
- If the profile cannot be loaded, the install still succeeds, but
  `broker run` refuses to start an agent without a working sandbox;
  `broker doctor` names the missing layer.
- Removing the package unloads the profile and deletes the file (it is not
  a conffile), so `bwrap` loses the exception with the package. Put local
  additions in `/etc/apparmor.d/local/broker-bwrap`.

CI proves this on Ubuntu 24.04 (x86_64 and arm64) with the gate on: before
the install `bwrap` cannot build a sandbox (the gate leaves its new
namespaces without capabilities); after it the same `bwrap` command,
`broker doctor` and a `broker run` session succeed as an ordinary user; after
removal `bwrap` fails again.

## Fedora, RHEL and openSUSE

```bash
sudo dnf install ./broker-V.x86_64.rpm
broker doctor
```

The layout matches the `.deb`; the licence is in
`/usr/share/licenses/broker/`. These distributions do not have Ubuntu's
user-namespace gate, so the install loads nothing.

## Static tarball (any Linux)

```bash
tar -xzf broker-V-x86_64-unknown-linux-musl.tar.gz
cd broker-V-x86_64-unknown-linux-musl
sudo install -m 0755 broker brokerd broker-sandbox-shim /usr/local/bin/
broker doctor
```

The binaries are statically linked (musl). Install `bubblewrap` from your
distribution: the broker uses only `/usr/bin/bwrap` or `/usr/local/bin/bwrap`,
never one found on `PATH`. On Ubuntu 23.10 and newer, load the profile from
the tarball (it covers `/usr/bin/bwrap`):

```bash
sudo install -m 0644 apparmor/broker-bwrap /etc/apparmor.d/broker-bwrap
sudo apparmor_parser -r /etc/apparmor.d/broker-bwrap
```

## macOS

```bash
tar -xzf broker-V-universal2-apple-darwin.tar.gz
cd broker-V-universal2-apple-darwin
sudo install -m 0755 broker brokerd broker-sandbox-shim /usr/local/bin/
broker doctor
```

The macOS binaries are **not signed with a Developer ID and not notarised**
yet; that needs the maintainer's Apple developer account, and the release
workflow skips those steps until it is set up. Files downloaded with a
browser are quarantined by Gatekeeper; verify them first (below), then
clear the quarantine with
`xattr -d com.apple.quarantine broker brokerd broker-sandbox-shim`.
Downloads made with `curl` or `gh release download` are not quarantined.
There is no Homebrew tap yet.

## Verify before installing

Download `SHA256SUMS` and the `.sigstore.json` file next to each asset.

1. **Checksums.**

   ```bash
   sha256sum --ignore-missing -c SHA256SUMS          # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
   ```

2. **Signature** (cosign 2.4 or newer). The certificate must name the
   release workflow at the release tag:

   ```bash
   cosign verify-blob \
     --bundle broker_V_amd64.deb.sigstore.json \
     --certificate-identity "https://github.com/Marioiubas/sandbox/.github/workflows/release.yml@refs/tags/vV" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     broker_V_amd64.deb
   ```

3. **Provenance** (GitHub CLI 2.49 or newer):

   ```bash
   gh attestation verify broker_V_amd64.deb \
     --repo Marioiubas/sandbox \
     --signer-workflow Marioiubas/sandbox/.github/workflows/release.yml \
     --source-ref refs/tags/vV
   ```

   Offline, add `--bundle broker-V.provenance.sigstore.json`.

Always pin the tag (`@refs/tags/vV`, `--source-ref refs/tags/vV`). The
workflow also signs and attests the builds it makes from the `packaging`
branch, to prove the pipeline before a release; their certificates name
`refs/heads/packaging`, so a verification pinned to a tag rejects them.

## How the packages are built

`.github/workflows/release.yml` builds the Linux binaries with
`cargo zigbuild` for `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`, checks they are static (`file`, `readelf`,
`ldd`), packs them with nfpm (`code/packaging/nfpm.yaml`), builds both macOS
slices and merges them with `lipo`, writes the SBOMs with
`cargo-cyclonedx`, then checksums, attests and signs every asset and
verifies each signature and attestation before a draft release is created.
Toolchains are pinned (`rust-toolchain.toml`, tool versions and SHA-256
digests in the workflow) and builds use `--locked`.

## Not yet available

- Developer ID signing and notarisation of the macOS build.
- A Homebrew tap, and apt or yum repositories (install the downloaded files).
- GPG signatures inside the `.deb` and `.rpm` (the cosign signature and
  provenance cover the files).
