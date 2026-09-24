//! Manifest pinning (MCP Guard): a server's `tools/list` hashed over
//! canonical JSON (every tool object, keys sorted, tools sorted by name);
//! approvals bind a server name to that hash and live in the daemon's state
//! directory, outside every sandbox (I5). Any change revokes the server.

use crate::dirs::BrokerDirs;
pub use mcpguard::manifest::{Manifest, canonical, diff, digest, manifest};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn approvals_file(dirs: &BrokerDirs) -> PathBuf {
    dirs.state_dir.join("mcp-approvals.json")
}

fn manifest_file(dirs: &BrokerDirs, name: &str, kind: &str) -> PathBuf {
    dirs.state_dir.join("mcp-manifests").join(format!("{name}.{kind}.json"))
}

fn write_atomic(p: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(d) = p.parent() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(d)?;
    }
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, p)?;
    Ok(())
}

/// The approved digest for a server, if any.
pub fn approved(dirs: &BrokerDirs, name: &str) -> Option<String> {
    let b = std::fs::read(approvals_file(dirs)).ok()?;
    let m: BTreeMap<String, String> = serde_json::from_slice(&b).ok()?;
    m.get(name).cloned()
}

fn load(p: PathBuf) -> Option<Manifest> {
    let v: Value = serde_json::from_slice(&std::fs::read(p).ok()?).ok()?;
    Some(Manifest { sha256: v.get("sha256")?.as_str()?.to_string(), tools: v.get("tools")?.as_array()?.clone() })
}

fn save(p: PathBuf, m: &Manifest) -> anyhow::Result<()> {
    write_atomic(&p, &serde_json::to_vec_pretty(&json!({ "sha256": m.sha256, "tools": m.tools }))?)
}

/// The manifest the daemon last saw for a server (what `approve` shows).
pub fn record_seen(dirs: &BrokerDirs, name: &str, m: &Manifest) -> anyhow::Result<()> {
    save(manifest_file(dirs, name, "seen"), m)
}

pub fn seen(dirs: &BrokerDirs, name: &str) -> Option<Manifest> {
    load(manifest_file(dirs, name, "seen"))
}

pub fn approved_manifest(dirs: &BrokerDirs, name: &str) -> Option<Manifest> {
    load(manifest_file(dirs, name, "approved"))
}

/// Approve exactly this manifest for this server name (the human's CLI).
pub fn approve(dirs: &BrokerDirs, name: &str, m: &Manifest) -> anyhow::Result<()> {
    let mut all: BTreeMap<String, String> =
        std::fs::read(approvals_file(dirs)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    all.insert(name.to_string(), m.sha256.clone());
    save(manifest_file(dirs, name, "approved"), m)?;
    write_atomic(&approvals_file(dirs), &serde_json::to_vec_pretty(&all)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approvals_are_bound_to_the_digest() {
        let home = tempfile::tempdir().unwrap();
        let dirs = BrokerDirs::rooted(home.path());
        dirs.ensure().unwrap();
        let m = manifest(vec![json!({"name": "t"})]).unwrap();
        assert_eq!(approved(&dirs, "gh"), None);
        approve(&dirs, "gh", &m).unwrap();
        assert_eq!(approved(&dirs, "gh"), Some(m.sha256.clone()));
        assert_eq!(approved_manifest(&dirs, "gh"), Some(m));
        assert_eq!(approved(&dirs, "other"), None);
    }
}
