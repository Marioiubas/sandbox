//! Manifest pinning (MCP Guard): everything a server puts in front of the
//! agent (its command by content, what the relay forwards from its
//! `initialize` result, and every tool object: ADR-047) hashed over
//! canonical JSON; approvals bind a server name to that hash and live in
//! the daemon's state directory, outside every sandbox (I5). Any change
//! revokes the server.

use crate::dirs::BrokerDirs;
pub use mcpguard::manifest::{Manifest, build, canonical, changes, diff, digest, forwarded_init, manifest};
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

/// A manifest with nothing in it (what a first approval is compared with).
pub fn empty() -> Manifest {
    Manifest { sha256: String::new(), command: Value::Null, server: Value::Null, tools: vec![] }
}

/// The approved digest for a server, if any.
pub fn approved(dirs: &BrokerDirs, name: &str) -> Option<String> {
    let b = std::fs::read(approvals_file(dirs)).ok()?;
    let m: BTreeMap<String, String> = serde_json::from_slice(&b).ok()?;
    m.get(name).cloned()
}

/// A stored manifest; files written before ADR-047 have no `command` or
/// `server` (null), so their digest never matches a server's now.
fn load(p: PathBuf) -> Option<Manifest> {
    let v: Value = serde_json::from_slice(&std::fs::read(p).ok()?).ok()?;
    Some(Manifest {
        sha256: v.get("sha256")?.as_str()?.to_string(),
        command: v.get("command").cloned().unwrap_or(Value::Null),
        server: v.get("server").cloned().unwrap_or(Value::Null),
        tools: v.get("tools")?.as_array()?.clone(),
    })
}

fn save(p: PathBuf, m: &Manifest) -> anyhow::Result<()> {
    let v = json!({ "sha256": m.sha256, "command": m.command, "server": m.server, "tools": m.tools });
    write_atomic(&p, &serde_json::to_vec_pretty(&v)?)
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
        let m = build(
            json!({"argv": ["/usr/bin/true"], "files": {"/usr/bin/true": "sha256:00"}}),
            json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "instructions": "Be brief."}),
            vec![json!({"name": "t"})],
        )
        .unwrap();
        assert_eq!(approved(&dirs, "gh"), None);
        approve(&dirs, "gh", &m).unwrap();
        assert_eq!(approved(&dirs, "gh"), Some(m.sha256.clone()));
        assert_eq!(approved_manifest(&dirs, "gh"), Some(m.clone()), "the command and server parts are stored");
        assert_eq!(approved(&dirs, "other"), None);
        // A manifest stored before ADR-047 loads with null parts.
        let old = manifest(vec![json!({"name": "t"})]).unwrap();
        let legacy = json!({"sha256": old.sha256, "tools": old.tools});
        std::fs::write(manifest_file(&dirs, "legacy", "approved"), serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert_eq!(approved_manifest(&dirs, "legacy"), Some(old));
    }
}
