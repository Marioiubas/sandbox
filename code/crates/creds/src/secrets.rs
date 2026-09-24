//! Reading roots: the OS keychain (macOS `security`, Linux `secret-tool`),
//! brokerd's own environment (CI secrets), or a 0600 file in the broker
//! config directory. Errors name the reference, never the value.

use crate::Secret;
use policy::SecretRef;
use policy::l7::SecretSource;
use std::path::PathBuf;
use std::process::Command;

pub trait SecretReader: Send + Sync {
    /// Read the raw secret named by `src` (blocking).
    fn read_raw(&self, src: &SecretSource) -> anyhow::Result<Secret>;

    /// Try each alternative in order; the first that yields a secret (after
    /// the JSON path, if any) wins. Errors list every alternative's cause.
    fn read(&self, r: &SecretRef) -> anyhow::Result<Secret> {
        let mut causes = Vec::new();
        for a in &r.alternatives {
            let got = self.read_raw(&a.source).and_then(|raw| {
                if a.json_path.is_empty() {
                    Ok(raw)
                } else {
                    select_json(&raw, &a.json_path).map_err(|m| anyhow::anyhow!(m))
                }
            });
            match got {
                Ok(s) => return Ok(s),
                Err(e) => causes.push(format!("{e:#}")),
            }
        }
        anyhow::bail!("{}: {}", r.describe(), causes.join("; "))
    }
}

/// Select a string field from a JSON secret without echoing it in errors.
pub fn select_json(raw: &Secret, path: &[String]) -> Result<Secret, String> {
    let v: serde_json::Value = serde_json::from_slice(raw.expose()).map_err(|_| "secret is not JSON".to_string())?;
    let mut cur = &v;
    for p in path {
        cur = cur.get(p).ok_or_else(|| format!("JSON field {p:?} missing"))?;
    }
    match cur {
        serde_json::Value::String(s) if !s.is_empty() => Ok(Secret::new(s.as_bytes().to_vec())),
        _ => Err("selected JSON value is not a non-empty string".into()),
    }
}

/// The real sources.
pub struct OsSecrets {
    /// Directory `file:<name>` references are resolved in.
    pub config_dir: PathBuf,
    /// The user's home (from the password database) for `file:~/...`.
    pub home: PathBuf,
}

fn trim_newline(mut v: Vec<u8>) -> Vec<u8> {
    while v.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        v.pop();
    }
    v
}

impl SecretReader for OsSecrets {
    fn read_raw(&self, src: &SecretSource) -> anyhow::Result<Secret> {
        let v = match src {
            SecretSource::Keychain { service, account } => keychain(service, account.as_deref())?,
            SecretSource::Env(name) => std::env::var_os(name)
                .map(|v| v.into_encoded_bytes())
                .ok_or_else(|| anyhow::anyhow!("env:{name} is not set in brokerd's environment"))?,
            SecretSource::File(name) => {
                use std::os::unix::fs::MetadataExt;
                let p = match name.strip_prefix("~/") {
                    Some(rest) => self.home.join(rest),
                    None => self.config_dir.join(name),
                };
                let m = std::fs::metadata(&p).map_err(|e| anyhow::anyhow!("file:{name}: {e}"))?;
                if m.uid() != nix::unistd::getuid().as_raw() || m.mode() & 0o077 != 0 {
                    anyhow::bail!("file:{name} must be owned by you with mode 0600");
                }
                trim_newline(std::fs::read(&p).map_err(|e| anyhow::anyhow!("file:{name}: {e}"))?)
            }
        };
        if v.is_empty() {
            anyhow::bail!("secret {src:?} is empty");
        }
        Ok(Secret::new(v))
    }
}

#[cfg(target_os = "macos")]
fn keychain(service: &str, account: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let mut c = Command::new("/usr/bin/security");
    c.args(["find-generic-password", "-s", service]);
    if let Some(a) = account {
        c.args(["-a", a]);
    }
    c.arg("-w");
    let out = c.output().map_err(|e| anyhow::anyhow!("keychain:{service}: running security: {e}"))?;
    if !out.status.success() {
        anyhow::bail!("keychain:{service}: item not found or access denied (security exit {})", out.status);
    }
    Ok(trim_newline(out.stdout))
}

#[cfg(not(target_os = "macos"))]
fn keychain(service: &str, account: Option<&str>) -> anyhow::Result<Vec<u8>> {
    let mut c = Command::new("secret-tool");
    c.args(["lookup", "service", service]);
    if let Some(a) = account {
        c.args(["account", a]);
    }
    let out = c.output().map_err(|e| anyhow::anyhow!("keychain:{service}: running secret-tool: {e}"))?;
    if !out.status.success() || out.stdout.is_empty() {
        anyhow::bail!("keychain:{service}: item not found or the secret service is locked");
    }
    Ok(trim_newline(out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_source_requires_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let r = OsSecrets { config_dir: d.path().to_path_buf(), home: d.path().to_path_buf() };
        std::fs::write(d.path().join("k"), b"CANARY-FILE-SECRET\n").unwrap();
        std::fs::set_permissions(d.path().join("k"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = r.read_raw(&SecretSource::File("k".into())).unwrap_err().to_string();
        assert!(e.contains("0600") && !e.contains("CANARY"), "{e}");
        std::fs::set_permissions(d.path().join("k"), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(r.read_raw(&SecretSource::File("k".into())).unwrap().expose(), b"CANARY-FILE-SECRET");
        assert!(r.read_raw(&SecretSource::File("missing".into())).is_err());
        std::fs::create_dir_all(d.path().join(".agent")).unwrap();
        std::fs::write(d.path().join(".agent/creds.json"), br#"{"t":"CANARY-HOME"}"#).unwrap();
        std::fs::set_permissions(d.path().join(".agent/creds.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
        // Alternatives: the first source fails, the second yields.
        let alt = SecretRef::parse("env:BROKER_TEST_SURELY_UNSET_VAR|file:~/.agent/creds.json#t").unwrap();
        assert_eq!(r.read(&alt).unwrap().expose(), b"CANARY-HOME");
        let none = SecretRef::parse("env:BROKER_TEST_SURELY_UNSET_VAR|file:~/.agent/missing.json#t").unwrap();
        let e = format!("{:#}", r.read(&none).unwrap_err());
        assert!(e.contains("BROKER_TEST_SURELY_UNSET_VAR") && e.contains("missing.json"), "{e}");
    }

    #[test]
    fn json_selection_never_echoes() {
        let raw = Secret::new(br#"{"claudeAiOauth":{"accessToken":"CANARY-TOK","n":1}}"#.to_vec());
        let p = |s: &str| s.split('.').map(str::to_string).collect::<Vec<_>>();
        assert_eq!(select_json(&raw, &p("claudeAiOauth.accessToken")).unwrap().expose(), b"CANARY-TOK");
        for bad in ["claudeAiOauth.n", "claudeAiOauth.missing", "claudeAiOauth"] {
            let e = select_json(&raw, &p(bad)).unwrap_err();
            assert!(!e.contains("CANARY"), "{e}");
        }
        assert!(select_json(&Secret::new(b"not json CANARY".to_vec()), &p("a")).unwrap_err().find("CANARY").is_none());
    }

    #[test]
    fn env_source() {
        let r = OsSecrets { config_dir: PathBuf::from("/nonexistent"), home: PathBuf::from("/nonexistent") };
        assert!(r.read_raw(&SecretSource::Env("BROKER_TEST_SURELY_UNSET_VAR".into())).is_err());
        let path = r.read_raw(&SecretSource::Env("PATH".into())).unwrap();
        assert!(!path.is_empty());
    }
}
