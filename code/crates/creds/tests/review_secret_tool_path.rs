//! Adversarial review of the credential path (2026-10-06, branch
//! `review-creds`): the Linux keychain reader runs `secret-tool` by name.
//!
//! `creds::secrets::keychain` (non-macOS) is `Command::new("secret-tool")`,
//! resolved through brokerd's own `PATH`; brokerd never sets `PATH` or its
//! working directory, so both are inherited from the shell where `broker
//! run` first autostarted it (`broker-cli` `ctl::connect_or_start`). That
//! shell routinely has a directory the sandbox can write first on `PATH`: an
//! activated in-repo virtualenv (`<repo>/.venv/bin`), direnv's `PATH_add` or
//! `layout node` (`<repo>/node_modules/.bin`), or an empty/relative entry
//! (resolved against brokerd's cwd, the first repo). An agent writes
//! `secret-tool` there; the next `keychain:` read (every shipped profile's
//! first alternative; a GitHub App key on the first push; AWS base
//! credentials on every mint) runs it as the user, outside the sandbox.
//! macOS is not affected: it runs `/usr/bin/security` by absolute path.
//!
//! Its own test binary: it changes this process's `PATH`.
#![cfg(target_os = "linux")]

use creds::secrets::{OsSecrets, SecretReader};
use policy::l7::SecretSource;
use std::os::unix::fs::PermissionsExt;

#[test]
fn keychain_helper_is_not_resolved_through_an_inherited_path() {
    let d = tempfile::tempdir().unwrap();
    // The agent-writable directory (`<repo>/.venv/bin` in the scenario).
    let venv_bin = d.path().join("repo/.venv/bin");
    std::fs::create_dir_all(&venv_bin).unwrap();
    let marker = d.path().join("ran-outside-the-sandbox");
    let fake = venv_bin.join("secret-tool");
    std::fs::write(&fake, format!("#!/bin/sh\ntouch '{}'\nprintf PLANTED\n", marker.display())).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let inherited = std::env::var("PATH").unwrap_or_default();
    // SAFETY: the only test in this binary; no other thread reads the environment.
    unsafe { std::env::set_var("PATH", format!("{}:{inherited}", venv_bin.display())) };

    let reader = OsSecrets { config_dir: d.path().join("config"), home: d.path().join("home") };
    let got = reader.read_raw(&SecretSource::Keychain { service: "broker-review-canary".into(), account: None });

    assert!(!marker.exists(), "brokerd ran a `secret-tool` planted in an agent-writable directory on its PATH");
    assert!(got.map(|s| s.expose() != b"PLANTED").unwrap_or(true), "the planted helper's output became the secret");
}
