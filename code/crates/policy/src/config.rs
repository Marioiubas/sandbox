//! The human policy layer as accepted through M1: a strict subset of
//! `broker.toml` (see the broker.toml Human Policy Layer note).
//!
//! Every key is known; anything else is a parse error rather than silently
//! ignored, so a policy never appears to grant something the broker cannot
//! enforce. M1 adds the L7 keys (`protocol`, `methods`, `paths`, `allow`,
//! `credential`, `passthrough`) and the user-only `[issuers]` and `[tls]`
//! tables.

use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;
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
    /// `http` (default when any L7 key is set), `git` or `registry`.
    pub protocol: Option<String>,
    /// Allowed HTTP methods on a terminated host; absent means any, empty none.
    pub methods: Option<Vec<String>>,
    /// Allowed path globs (`*` within a segment, `**` any number of
    /// segments); absent means any, empty none.
    pub paths: Option<Vec<String>>,
    /// `protocol = "git"`: fetch and push rules.
    pub allow: Option<GitAllow>,
    /// `protocol = "github"`: granted verbs (`repo.read`, `pr.create`, …);
    /// empty means none.
    pub verbs: Option<Vec<String>>,
    /// `protocol = "github"`: repositories the repository verbs apply to;
    /// absent means `["${repo_remote}"]` (the task repository only).
    pub repos: Option<Vec<String>>,
    /// A credential the broker attaches to requests this entry allows.
    pub credential: Option<CredentialSpec>,
    /// Certificate-pinning clients: never terminate TLS for this host, and
    /// therefore never attach a credential. Incompatible with L7 keys.
    #[serde(default)]
    pub passthrough: bool,
}

impl EgressEntry {
    /// Whether this entry needs TLS termination (L7).
    pub fn wants_l7(&self) -> bool {
        self.protocol.is_some()
            || self.methods.is_some()
            || self.paths.is_some()
            || self.allow.is_some()
            || self.verbs.is_some()
            || self.repos.is_some()
            || self.credential.is_some()
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitAllow {
    /// Repositories that may be fetched (`host/owner/repo`, `host/owner/*`
    /// or `${repo_remote}`).
    #[serde(default)]
    pub fetch: Vec<String>,
    /// Push rules; a single table or an array of tables.
    #[serde(default, deserialize_with = "one_or_many")]
    pub push: Vec<PushRule>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PushRule {
    pub repo: String,
    /// Ref globs; `agent/*` means `refs/heads/agent/*`.
    pub refs: Vec<String>,
    /// Allow non-fast-forward updates and deletes (default false).
    #[serde(default)]
    pub force: bool,
}

fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PushRule>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(PushRule),
        Many(Vec<PushRule>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(r) => vec![r],
        OneOrMany::Many(v) => v,
    })
}

/// `credential = { ... }` on an egress entry.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialSpec {
    /// `static` or `github_app`.
    pub kind: String,
    /// Stable credential ID for audit rows (default: the grant ID).
    pub id: Option<String>,
    /// `static`: where the secret lives (`keychain:<service>[/<account>]`,
    /// `env:<VAR>` of brokerd, `file:<name>` in the broker config dir),
    /// optionally `#json.path` to select a field of a JSON secret.
    #[serde(rename = "ref")]
    pub secret_ref: Option<String>,
    /// Header to set; default `authorization`.
    pub header: Option<String>,
    /// For `authorization`: `bearer` (default), `token` or `basic`.
    pub scheme: Option<String>,
    /// For `scheme = "basic"`: the user name (the secret is the password).
    pub username: Option<String>,
    /// Sandbox environment variable that receives this credential's sentinel.
    pub env: Option<String>,
    /// Swap the sentinel for the secret inside request bodies too.
    #[serde(default)]
    pub swap_body: bool,
    /// `github_app`: the `[issuers.github_app.<name>]` to mint with.
    pub issuer: Option<String>,
    /// `github_app`: installation-token permissions (always sent).
    pub permissions: Option<BTreeMap<String, String>>,
    /// `github_app`: repositories the token is limited to (always sent).
    pub repos: Option<Vec<String>>,
    /// Upper bound on reuse of a minted token (`30m`, `1h`, `900s`).
    pub ttl: Option<String>,
    /// `high`: using this credential raises the session's `sensitive_read`
    /// label (Trifecta Session Labels). Default `standard`.
    pub risk: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GitHubAppIssuerSpec {
    pub app_id: String,
    pub installation_id: String,
    /// Secret reference to the app's private key (PEM).
    pub private_key: String,
    /// Default `https://api.github.com`.
    pub api_base: Option<String>,
    /// Pinned addresses for the API host (tests, GHES); no DNS query then.
    #[serde(default)]
    pub api_addrs: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuersSection {
    #[serde(default)]
    pub github_app: BTreeMap<String, GitHubAppIssuerSpec>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    /// Extra PEM roots trusted for upstream verification (private CAs).
    /// Never added to the host trust store.
    #[serde(default)]
    pub extra_roots: Vec<String>,
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
    /// User/org scope only: credential issuers.
    #[serde(default)]
    pub issuers: IssuersSection,
    /// User/org scope only: upstream trust additions.
    #[serde(default)]
    pub tls: TlsSection,
    /// User/org scope only: pinned MCP servers by name (MCP Guard).
    #[serde(default)]
    pub mcp: BTreeMap<String, crate::mcp::McpServerConfig>,
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
    crate::mcp::validate(&p.mcp).map_err(|e| anyhow::anyhow!(e))?;
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
        let p = parse_policy_str("version = 1\n[[egress]]\nhost = \"a.com\"\nmethods = [\"GET\"]\n").unwrap();
        assert!(p.egress[0].wants_l7());
        let e = parse_policy_str("version = 1\n[[egress]]\nhost = \"a.com\"\nmethod = [\"GET\"]\n");
        assert!(e.is_err(), "a misspelt key must not be silently ignored");
        let e = parse_policy_str(
            "version = 1\n[[egress]]\nhost = \"a.com\"\ncredential = { kind = \"static\", bogus = 1 }\n",
        );
        assert!(e.is_err());
        assert!(parse_policy_str("version = 2\n").is_err());
        assert!(parse_policy_str("egress = []\n").is_err(), "version is required");
        assert!(parse_policy_str("version = 1\nbogus = 1\n").is_err());
    }

    #[test]
    fn git_push_accepts_table_or_array() {
        let one = r#"
version = 1
[[egress]]
host = "github.com"
protocol = "git"
allow = { fetch = ["${repo_remote}"], push = { repo = "${repo_remote}", refs = ["agent/*"], force = false } }
credential = { kind = "github_app", issuer = "acme", permissions = { contents = "write" }, repos = ["${repo_remote}"], ttl = "30m" }
[issuers.github_app.acme]
app_id = "1"
installation_id = "2"
private_key = "keychain:gh-app"
"#;
        let p = parse_policy_str(one).unwrap();
        let a = p.egress[0].allow.as_ref().unwrap();
        assert_eq!(a.push.len(), 1);
        assert_eq!(a.push[0].refs, vec!["agent/*"]);
        assert_eq!(p.issuers.github_app["acme"].installation_id, "2");
        let many = "version = 1\n[[egress]]\nhost = \"github.com\"\nprotocol = \"git\"\n\
                    allow = { push = [{ repo = \"a/b\", refs = [\"x\"] }, { repo = \"a/c\", refs = [\"y\"], force = true }] }\n";
        assert_eq!(parse_policy_str(many).unwrap().egress[0].allow.as_ref().unwrap().push.len(), 2);
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
