//! Credential declarations: how a secret is attached, which issuer mints it,
//! the sandbox variable that receives its sentinel, and the proof
//! (`AllowedBinding`) that a policy decision allowed attaching it.

use super::*;

/// How an issued secret is attached to a forwarded request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachSpec {
    /// `Authorization: Bearer <secret>`
    Bearer,
    /// `Authorization: token <secret>`
    Token,
    /// `Authorization: Basic base64(<username>:<secret>)`
    Basic { username: String },
    /// `<name>: <secret>`
    Header { name: String },
    /// The whole request is signed with AWS Signature Version 4 using the
    /// minted session credentials (`aws_sts`).
    SigV4,
}

impl AttachSpec {
    pub fn header_name(&self) -> &str {
        match self {
            AttachSpec::Header { name } => name,
            _ => "authorization",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredKind {
    Static {
        secret: SecretRef,
    },
    GitHubApp {
        issuer: String,
        permissions: BTreeMap<String, String>,
        repos: Vec<RepoId>,
    },
    /// An STS `AssumeRole` session narrowed by an inline session policy
    /// compiled from the grant's S3 prefixes.
    AwsSts {
        issuer: String,
        session_policy: String,
    },
}

impl CredKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredKind::Static { .. } => "static",
            CredKind::GitHubApp { .. } => "github_app",
            CredKind::AwsSts { .. } => "aws_sts",
        }
    }
}

/// A compiled credential declaration. Holds no secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialDef {
    pub id: String,
    pub kind: CredKind,
    pub attach: AttachSpec,
    /// Sandbox variable that receives the sentinel, if any.
    pub env: Option<String>,
    pub swap_body: bool,
    /// Hosts the credential (and its sentinel) is bound to.
    pub hosts: Vec<HostPattern>,
    pub ttl: Option<Duration>,
    /// `risk = "high"`: using it raises the session's `sensitive_read`.
    pub high_risk: bool,
}

/// Proof that a policy decision allowed attaching this credential. Only
/// this module constructs one; `creds` mints only against it.
#[derive(Clone, Debug)]
pub struct AllowedBinding {
    cred: Arc<CredentialDef>,
    grant_id: String,
}

impl AllowedBinding {
    /// Only the policy crate constructs bindings (after a Cedar allow).
    pub(crate) fn new(cred: Arc<CredentialDef>, grant_id: &str) -> AllowedBinding {
        AllowedBinding { cred, grant_id: grant_id.to_string() }
    }

    pub fn credential(&self) -> &CredentialDef {
        &self.cred
    }
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
}

const RESERVED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
];

pub fn parse_ttl(s: &str) -> Result<Duration, String> {
    let (num, mul) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        _ => return Err(format!("ttl {s:?}: use a unit (s, m or h)")),
    };
    let n: u64 = num.parse().map_err(|_| format!("ttl {s:?} is not a number"))?;
    if n == 0 {
        return Err(format!("ttl {s:?} must be positive"));
    }
    Ok(Duration::from_secs(n * mul))
}

/// GitHub installation tokens last at most an hour; so does any reuse.
pub const GITHUB_APP_MAX_TTL: Duration = Duration::from_secs(3600);

pub(super) fn compile_credential(
    grant_id: &str,
    c: &CredentialSpec,
    protocol: Protocol,
    pattern: &HostPattern,
    env: &CompileEnv,
    s3: Option<&crate::s3::S3Rules>,
) -> Result<CredentialDef, String> {
    let id = c.id.clone().unwrap_or_else(|| grant_id.to_string());
    if let Some(v) = &c.env
        && (!env_name_ok(v) || RESERVED_ENV.contains(&v.to_ascii_uppercase().as_str()) || v.starts_with("BROKER_"))
    {
        return Err(format!("credential {id}: env {v:?} is not an allowed variable name"));
    }
    let attach = if c.kind == "aws_sts" {
        if c.header.is_some() || c.scheme.is_some() || c.username.is_some() {
            return Err(format!(
                "credential {id}: aws_sts signs the request (SigV4); header, scheme and username do not apply"
            ));
        }
        AttachSpec::SigV4
    } else {
        match (c.header.as_deref().map(str::to_ascii_lowercase), c.scheme.as_deref()) {
            (Some(h), _) if !header_name_ok(&h) => return Err(format!("credential {id}: bad header name {h:?}")),
            (Some(h), Some(_)) if h != "authorization" => {
                return Err(format!("credential {id}: scheme applies only to the authorization header"));
            }
            (Some(h), None) if h != "authorization" => AttachSpec::Header { name: h },
            (_, Some("bearer")) => AttachSpec::Bearer,
            (_, Some("token")) => AttachSpec::Token,
            (_, Some("basic")) => AttachSpec::Basic {
                username: c.username.clone().ok_or_else(|| format!("credential {id}: basic needs username"))?,
            },
            (_, Some(other)) => return Err(format!("credential {id}: unknown scheme {other:?}")),
            (_, None) if c.kind == "github_app" && protocol == Protocol::Git => {
                AttachSpec::Basic { username: "x-access-token".into() }
            }
            (_, None) => AttachSpec::Bearer,
        }
    };
    if c.username.is_some() && !matches!(attach, AttachSpec::Basic { .. }) {
        return Err(format!("credential {id}: username applies only to scheme = \"basic\""));
    }
    let ttl = c.ttl.as_deref().map(parse_ttl).transpose().map_err(|m| format!("credential {id}: {m}"))?;
    let kind = match c.kind.as_str() {
        "static" => {
            if c.issuer.is_some() || c.permissions.is_some() || c.repos.is_some() || ttl.is_some() {
                return Err(format!("credential {id}: issuer/permissions/repos/ttl apply to github_app only"));
            }
            let r = c.secret_ref.as_deref().ok_or_else(|| format!("credential {id}: static needs ref"))?;
            CredKind::Static { secret: SecretRef::parse(r).map_err(|m| format!("credential {id}: {m}"))? }
        }
        "github_app" => {
            if c.secret_ref.is_some() || c.swap_body {
                return Err(format!("credential {id}: ref/swap_body apply to static only"));
            }
            let issuer = c.issuer.clone().ok_or_else(|| format!("credential {id}: github_app needs issuer"))?;
            if !env.github_app_issuers.contains(&issuer) {
                return Err(format!("credential {id}: no [issuers.github_app.{issuer}] in user or org policy"));
            }
            let permissions = c.permissions.clone().unwrap_or_default();
            if permissions.is_empty() {
                return Err(format!("credential {id}: github_app needs explicit permissions"));
            }
            for (k, v) in &permissions {
                let name_ok = !k.is_empty() && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
                if !name_ok || !matches!(v.as_str(), "read" | "write" | "admin") {
                    return Err(format!("credential {id}: bad permission {k} = {v:?}"));
                }
            }
            let mut repos = Vec::new();
            for r in c.repos.as_deref().ok_or_else(|| format!("credential {id}: github_app needs repos"))? {
                match RepoPattern::parse(r, env.repo_remote.as_ref()).map_err(|m| format!("credential {id}: {m}"))? {
                    RepoPattern::Exact(x) => repos.push(x),
                    RepoPattern::Nothing(_) => {} // unresolved: the token would cover nothing; never minted
                    RepoPattern::Owner { .. } => {
                        return Err(format!("credential {id}: repos must name repositories, not owner/*"));
                    }
                }
            }
            if let Some(first) = repos.first()
                && repos.iter().any(|r| r.owner() != first.owner() || r.authority() != first.authority())
            {
                return Err(format!("credential {id}: one installation token cannot span owners"));
            }
            if ttl.is_some_and(|t| t > GITHUB_APP_MAX_TTL) {
                return Err(format!("credential {id}: github_app ttl is at most 1h"));
            }
            CredKind::GitHubApp { issuer, permissions, repos }
        }
        "aws_sts" => {
            if c.secret_ref.is_some() || c.swap_body || c.permissions.is_some() || c.repos.is_some() {
                return Err(format!(
                    "credential {id}: ref/swap_body/permissions/repos do not apply to aws_sts (the grant's s3 prefixes are its scope)"
                ));
            }
            if protocol != Protocol::S3 {
                return Err(format!("credential {id}: aws_sts needs protocol = \"s3\""));
            }
            let issuer = c.issuer.clone().ok_or_else(|| format!("credential {id}: aws_sts needs issuer"))?;
            if !env.aws_sts_issuers.contains(&issuer) {
                return Err(format!("credential {id}: no [issuers.aws_sts.{issuer}] in user or org policy"));
            }
            let rules = s3.ok_or_else(|| format!("credential {id}: aws_sts needs the grant's s3 rules"))?;
            let session_policy = crate::s3::session_policy(rules).map_err(|m| format!("credential {id}: {m}"))?;
            CredKind::AwsSts { issuer, session_policy }
        }
        other => return Err(format!("credential {id}: unknown kind {other:?} (static, github_app, aws_sts)")),
    };
    Ok(CredentialDef {
        id,
        kind,
        attach,
        // The SDKs' variable for the access key ID receives the sentinel.
        env: c.env.clone().or_else(|| (c.kind == "aws_sts").then(|| "AWS_ACCESS_KEY_ID".to_string())),
        swap_body: c.swap_body,
        hosts: vec![pattern.clone()],
        ttl,
        high_risk: match c.risk.as_deref() {
            None | Some("standard") => false,
            Some("high") => true,
            Some(r) => return Err(format!("credential {grant_id}: risk {r:?} must be standard or high")),
        },
    })
}
