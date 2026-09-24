//! Shadow mode (Policy Learning Loop): the enforced policy decides every
//! request; a candidate policy activated with `broker policy shadow <file>`
//! is evaluated on the same requests and its verdict is logged, so a change
//! is measured before it bites. The candidate never changes a decision and
//! never attaches a credential.

use crate::dirs::BrokerDirs;
use audit::Reason;
use netguard::CanonicalHost;
use policy::{Admission, EgressPolicy, PolicyFile};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::PathBuf;

/// Largest candidate file accepted.
pub const MAX_FILE: usize = 256 << 10;

fn path(dirs: &BrokerDirs) -> PathBuf {
    dirs.state_dir.join("shadow-candidate.toml")
}

fn digest(text: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())))
}

/// Validate and store a candidate (it must parse as a user-scope policy).
pub fn activate(dirs: &BrokerDirs, text: &str) -> anyhow::Result<String> {
    if text.len() > MAX_FILE {
        anyhow::bail!("candidate is larger than {MAX_FILE} bytes");
    }
    policy::config::parse_policy_str(text)?;
    let p = path(dirs);
    let tmp = p.with_extension("toml.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, &p)?;
    Ok(digest(text))
}

pub fn deactivate(dirs: &BrokerDirs) -> anyhow::Result<bool> {
    match std::fs::remove_file(path(dirs)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// The active candidate: its digest and parsed policy.
pub fn load(dirs: &BrokerDirs) -> anyhow::Result<Option<(String, PolicyFile)>> {
    let text = match std::fs::read_to_string(path(dirs)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some((digest(&text), policy::config::parse_policy_str(&text)?)))
}

/// The candidate's admission of a destination: the name and port, and the
/// broker-resolved addresses when the enforced policy got that far.
pub fn admission(
    p: &EgressPolicy,
    host: &CanonicalHost,
    port: u16,
    addrs: Option<&[IpAddr]>,
) -> Result<Admission, Reason> {
    let mut adm = p.admit_host(host, port).map_err(|(r, _)| r)?;
    if let Some(a) = addrs {
        p.admit_addrs(&mut adm, a).map_err(|(r, _)| r)?;
    }
    Ok(adm)
}

/// The audit detail for one decision: the candidate's verdict and whether
/// it differs from the applied one. `resolved` is false when the enforced
/// policy denied before resolution (the candidate's verdict is name-level).
pub fn note(candidate: &Result<(), Reason>, applied_allow: bool, resolved: bool) -> Value {
    let allow = candidate.is_ok();
    let mut v = json!({ "allow": allow, "differs": allow != applied_allow });
    if let Err(r) = candidate {
        v["reason"] = json!(r.as_str());
    }
    if !resolved {
        v["name_only"] = json!(true);
    }
    v
}
