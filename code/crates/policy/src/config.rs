//! The human policy layer as accepted in M0: a strict subset of
//! `broker.toml` (see the broker.toml Human Policy Layer note).
//!
//! Keys that need later milestones (`protocol`, `methods`, `allow`,
//! `credential`) are rejected as unknown keys rather than silently ignored,
//! so a policy never appears to grant something the broker cannot enforce.

use serde::Deserialize;
use std::path::Path;

pub const SUPPORTED_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressEntry {
    /// Canonical host or `*.name` wildcard (never a catch-all).
    pub host: String,
    /// Allowed ports; absent means `[443]`; empty means none.
    pub ports: Option<Vec<u16>>,
    /// Address classes this grant may reach besides `public`
    /// (`loopback`, `link_local`, `metadata`, `private`, `reserved`).
    #[serde(default)]
    pub allow_addr_classes: Vec<String>,
    /// Stable ID reported in audit rows and `broker why`.
    pub id: Option<String>,
    /// Pinned addresses: the broker connects only to these and does not
    /// query DNS for this host. Address-class rules still apply.
    #[serde(default)]
    pub addrs: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FsSection {
    /// Extra writable roots (`${repo}` and `${tmp}` are always writable).
    #[serde(default)]
    pub write: Vec<String>,
    /// Extra deny-read paths, added to the built-in secret list.
    #[serde(default)]
    pub deny_read: Vec<String>,
}

/// User- or org-scope policy file (`broker.toml`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub version: u32,
    #[serde(default)]
    pub egress: Vec<EgressEntry>,
    #[serde(default)]
    pub filesystem: FsSection,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentSection {
    /// Agent configuration paths that must stay read-only (I5): settings,
    /// hooks, MCP definitions. Home-relative with `~/`.
    #[serde(default)]
    pub config_readonly: Vec<String>,
    /// Agent state directories the agent must be able to write (session
    /// transcripts, caches). They may not contain configuration.
    #[serde(default)]
    pub state_write: Vec<String>,
    /// Extra non-secret environment variables to pass through by name.
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    /// macOS: the agent keeps its own credentials in the login keychain.
    /// Grants securityd access until M1 moves credentials out (ADR-016).
    #[serde(default)]
    pub macos_keychain: bool,
}

/// A built-in agent profile (`profiles/<name>.toml`).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfileFile {
    pub version: u32,
    pub name: String,
    /// Executable basenames that select this profile.
    #[serde(default)]
    pub binaries: Vec<String>,
    #[serde(default)]
    pub egress: Vec<EgressEntry>,
    #[serde(default)]
    pub filesystem: FsSection,
    #[serde(default)]
    pub agent: AgentSection,
}

/// Environment variable names that may never be passed through, whatever a
/// profile says (I1): anything that commonly carries a credential.
pub fn env_name_is_secretish(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH", "COOKIE", "SESSION"]
        .iter()
        .any(|w| n.contains(w))
}

fn check_version(v: u32) -> anyhow::Result<()> {
    if v != SUPPORTED_VERSION {
        anyhow::bail!("unsupported policy version {v} (this broker understands version {SUPPORTED_VERSION})");
    }
    Ok(())
}

pub fn parse_policy_str(text: &str) -> anyhow::Result<PolicyFile> {
    let p: PolicyFile = toml::from_str(text)?;
    check_version(p.version)?;
    Ok(p)
}

pub fn load_policy_file(path: &Path) -> anyhow::Result<PolicyFile> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    parse_policy_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
}

pub fn load_profile_str(text: &str) -> anyhow::Result<ProfileFile> {
    let p: ProfileFile = toml::from_str(text)?;
    check_version(p.version)?;
    for name in &p.agent.env_passthrough {
        if env_name_is_secretish(name) {
            anyhow::bail!("profile {} may not pass through secret-looking variable {name} (I1)", p.name);
        }
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_keys() {
        assert!(parse_policy_str("version = 1\n[[egress]]\nhost = \"a.com\"\n").is_ok());
        let e = parse_policy_str("version = 1\n[[egress]]\nhost = \"a.com\"\nmethods = [\"GET\"]\n");
        assert!(e.is_err(), "methods is an M1 key and must not be silently ignored");
        let e = parse_policy_str("version = 1\n[[egress]]\nhost = \"a.com\"\ncredential = { kind = \"static\" }\n");
        assert!(e.is_err());
        assert!(parse_policy_str("version = 2\n").is_err());
        assert!(parse_policy_str("egress = []\n").is_err(), "version is required");
        assert!(parse_policy_str("version = 1\nbogus = 1\n").is_err());
    }

    #[test]
    fn profile_env_passthrough_refuses_secrets() {
        let ok = "version = 1\nname = \"x\"\n[agent]\nenv_passthrough = [\"EDITOR\"]\n";
        assert!(load_profile_str(ok).is_ok());
        for bad in ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "NPM_AUTH", "db_password"] {
            let t = format!("version = 1\nname = \"x\"\n[agent]\nenv_passthrough = [\"{bad}\"]\n");
            assert!(load_profile_str(&t).is_err(), "{bad}");
        }
    }
}
