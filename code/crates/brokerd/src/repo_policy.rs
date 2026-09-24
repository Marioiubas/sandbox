//! Repository policy (`.broker/broker.toml`, `.broker/policy.cedar`): read
//! by brokerd on the host, never by the agent, and used only after the user
//! approved its exact content hash (I5). Approved policy is conjoined with
//! the user and org layers, so it can only narrow (I4); a changed file is
//! treated as absent until re-approved.

use crate::dirs::BrokerDirs;
use policy::PolicyFile;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Largest repository policy file read (the content is attacker-writable).
pub const MAX_FILE: u64 = 256 << 10;

pub const TOML_FILE: &str = ".broker/broker.toml";
pub const CEDAR_FILE: &str = ".broker/policy.cedar";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoFiles {
    pub toml: Option<String>,
    pub cedar: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Absent,
    /// Present but not approved (or changed since approval): ignored.
    Unapproved {
        sha256: String,
    },
    Approved {
        sha256: String,
        toml: Option<PolicyFile>,
        cedar: Option<String>,
    },
}

impl Status {
    pub fn describe(&self) -> String {
        match self {
            Status::Absent => "none".into(),
            Status::Unapproved { sha256 } => format!("present, not approved ({sha256}); ignored"),
            Status::Approved { sha256, .. } => format!("approved ({sha256})"),
        }
    }
}

fn read_bounded(p: &Path) -> anyhow::Result<Option<String>> {
    match std::fs::symlink_metadata(p) {
        Err(_) => Ok(None),
        Ok(m) if !m.file_type().is_file() => anyhow::bail!("{} is not a regular file", p.display()),
        Ok(m) if m.len() > MAX_FILE => anyhow::bail!("{} is larger than {MAX_FILE} bytes", p.display()),
        Ok(_) => Ok(Some(std::fs::read_to_string(p)?)),
    }
}

pub fn read(repo_root: &Path) -> anyhow::Result<RepoFiles> {
    Ok(RepoFiles { toml: read_bounded(&repo_root.join(TOML_FILE))?, cedar: read_bounded(&repo_root.join(CEDAR_FILE))? })
}

/// `sha256:` over both files with presence markers, so moving content
/// between them or deleting one changes the hash.
pub fn content_hash(f: &RepoFiles) -> Option<String> {
    if f.toml.is_none() && f.cedar.is_none() {
        return None;
    }
    let mut h = Sha256::new();
    for part in [&f.toml, &f.cedar] {
        match part {
            Some(s) => {
                h.update([1u8]);
                h.update((s.len() as u64).to_be_bytes());
                h.update(s.as_bytes());
            }
            None => h.update([0u8]),
        }
    }
    Some(format!("sha256:{}", hex::encode(h.finalize())))
}

fn approvals_file(dirs: &BrokerDirs) -> PathBuf {
    dirs.state_dir.join("repo-policy-approvals.json")
}

fn load_approvals(dirs: &BrokerDirs) -> BTreeMap<String, String> {
    std::fs::read(approvals_file(dirs)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn key(repo_root: &Path) -> String {
    repo_root.canonicalize().unwrap_or_else(|_| repo_root.to_path_buf()).display().to_string()
}

/// Validate repo-scope restrictions on the TOML layer (I4).
pub fn parse_toml(text: &str) -> anyhow::Result<PolicyFile> {
    let p = policy::config::parse_policy_str(text)?;
    if !p.issuers.github_app.is_empty() {
        anyhow::bail!("[issuers] is not allowed in repository policy (it would confer authority; I4)");
    }
    if !p.tls.extra_roots.is_empty() {
        anyhow::bail!("[tls] is not allowed in repository policy (it would confer authority; I4)");
    }
    if !p.identity.oidc.is_empty() {
        anyhow::bail!("[identity] is not allowed in repository policy: it decides who a session is (I4)");
    }
    if !p.mcp.is_empty() {
        anyhow::bail!("[mcp] is not allowed in repository policy: servers are pinned in user or org policy only (I5)");
    }
    if !p.filesystem.write.is_empty() || !p.filesystem.deny_read.is_empty() {
        anyhow::bail!("[filesystem] is not supported in repository policy yet");
    }
    Ok(p)
}

/// The repository policy status for a session.
pub fn status(dirs: &BrokerDirs, repo_root: &Path) -> anyhow::Result<Status> {
    let files = read(repo_root)?;
    let Some(sha256) = content_hash(&files) else { return Ok(Status::Absent) };
    if load_approvals(dirs).get(&key(repo_root)) != Some(&sha256) {
        return Ok(Status::Unapproved { sha256 });
    }
    let toml = files.toml.as_deref().map(parse_toml).transpose()?;
    Ok(Status::Approved { sha256, toml, cedar: files.cedar })
}

/// Record approval of the repository's current policy content.
pub fn approve(dirs: &BrokerDirs, repo_root: &Path) -> anyhow::Result<Option<String>> {
    let files = read(repo_root)?;
    let Some(sha256) = content_hash(&files) else { return Ok(None) };
    if let Some(t) = files.toml.as_deref() {
        parse_toml(t)?;
    }
    let mut a = load_approvals(dirs);
    a.insert(key(repo_root), sha256.clone());
    let tmp = approvals_file(dirs).with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&a)?)?;
    std::fs::rename(&tmp, approvals_file(dirs))?;
    Ok(Some(sha256))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_is_bound_to_content() {
        let home = tempfile::tempdir().unwrap();
        let dirs = BrokerDirs::rooted(home.path());
        dirs.ensure().unwrap();
        let repo = tempfile::tempdir().unwrap();
        assert_eq!(status(&dirs, repo.path()).unwrap(), Status::Absent);
        std::fs::create_dir_all(repo.path().join(".broker")).unwrap();
        let toml = "version = 1\n[[egress]]\nhost = \"api.github.com\"\n";
        std::fs::write(repo.path().join(TOML_FILE), toml).unwrap();
        assert!(matches!(status(&dirs, repo.path()).unwrap(), Status::Unapproved { .. }));
        let h = approve(&dirs, repo.path()).unwrap().unwrap();
        match status(&dirs, repo.path()).unwrap() {
            Status::Approved { sha256, toml: Some(p), cedar: None } => {
                assert_eq!(sha256, h);
                assert_eq!(p.egress.len(), 1);
            }
            other => panic!("{other:?}"),
        }
        // Any change (here: adding a Cedar file) revokes the approval.
        std::fs::write(repo.path().join(CEDAR_FILE), "// narrowing\n").unwrap();
        assert!(matches!(status(&dirs, repo.path()).unwrap(), Status::Unapproved { .. }));
        std::fs::write(repo.path().join(TOML_FILE), format!("{toml}\n")).unwrap();
        assert!(matches!(status(&dirs, repo.path()).unwrap(), Status::Unapproved { .. }));
    }

    #[test]
    fn authority_keys_are_rejected() {
        for bad in [
            "version = 1\n[issuers.github_app.x]\napp_id = \"1\"\ninstallation_id = \"2\"\nprivate_key = \"env:K\"\n",
            "version = 1\n[tls]\nextra_roots = [\"/tmp/evil.pem\"]\n",
            "version = 1\n[filesystem]\nwrite = [\"~/\"]\n",
        ] {
            assert!(parse_toml(bad).is_err(), "{bad}");
        }
        let hashes: Vec<_> = [
            RepoFiles { toml: Some("a".into()), cedar: None },
            RepoFiles { toml: None, cedar: Some("a".into()) },
            RepoFiles { toml: Some("a".into()), cedar: Some(String::new()) },
        ]
        .iter()
        .map(|f| content_hash(f).unwrap())
        .collect();
        assert_eq!(hashes.len(), 3);
        assert!(hashes[0] != hashes[1] && hashes[1] != hashes[2] && hashes[0] != hashes[2]);
    }
}
