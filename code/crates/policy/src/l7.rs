//! L7 rules on terminated hosts (M1): the interim representation of the
//! requests Cedar evaluates from M2 on, built as authorization decisions now
//! so the migration changes representation, not semantics.
//!
//! - An HTTP request becomes one or more [`Action`]s (a push updates several
//!   refs); **all** must be allowed, or the request is denied.
//! - Within a granted host, a request no rule matches is denied (ADR-006).
//! - A credential is attached only through an [`AllowedBinding`], which only
//!   this module constructs, and only when the grant declaring the
//!   credential allowed every action of the request.

use crate::config::{CredentialSpec, EgressEntry};
use crate::glob::PathPattern;
use crate::repo::{RefPattern, RepoId, RepoPattern};
use audit::Reason;
use netguard::HostPattern;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Http,
    Git,
    Registry,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Git => "git",
            Protocol::Registry => "registry",
        }
    }
}

/// What a request does, as a protocol adapter classified it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Http {
        method: String,
        path: String,
    },
    GitFetch {
        repo: RepoId,
    },
    /// `info/refs?service=git-receive-pack`: the ref advertisement before a push.
    GitPushAdvertise {
        repo: RepoId,
    },
    GitPush {
        repo: RepoId,
        refname: String,
        force: bool,
        update: &'static str,
    },
}

impl Action {
    /// The audit verb, e.g. `git.push github.com/acme/web refs/heads/main force=false`.
    pub fn verb(&self) -> String {
        match self {
            Action::Http { method, path } => format!("http {method} {path}"),
            Action::GitFetch { repo } => format!("git.fetch {repo}"),
            Action::GitPushAdvertise { repo } => format!("git.push-advertise {repo}"),
            Action::GitPush { repo, refname, force, update } => {
                format!("git.push {repo} {refname} force={force} ({update})")
            }
        }
    }
}

/// Where a secret comes from. Resolution lives in `creds`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretSource {
    Keychain {
        service: String,
        account: Option<String>,
    },
    /// An environment variable of brokerd itself (CI secrets), never the sandbox's.
    Env(String),
    /// A file name inside the broker config directory, or a `~/` path.
    File(String),
}

/// One place a secret may live, optionally selecting a JSON string field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretAlt {
    pub source: SecretSource,
    /// Select a string field of a JSON secret (`#a.b`).
    pub json_path: Vec<String>,
}

/// A secret reference: one or more alternatives (`a|b`), tried in order;
/// the first that yields a secret is used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef {
    pub alternatives: Vec<SecretAlt>,
}

fn parse_alt(whole: &str, s: &str) -> Result<SecretAlt, String> {
    let (src, path) = match s.split_once('#') {
        Some((a, p)) => (a, p.split('.').map(str::to_string).collect::<Vec<_>>()),
        None => (s, vec![]),
    };
    if path.iter().any(|p| p.is_empty()) {
        return Err(format!("secret reference {whole:?}: empty JSON path component"));
    }
    let nonempty = |v: &str| -> Result<String, String> {
        if v.is_empty() || v.bytes().any(|b| b < 0x20 || b == 0x7f) {
            Err(format!("secret reference {whole:?} is empty or has control bytes"))
        } else {
            Ok(v.to_string())
        }
    };
    let source = if let Some(rest) = src.strip_prefix("keychain:") {
        match rest.split_once('/') {
            Some((svc, acct)) => SecretSource::Keychain { service: nonempty(svc)?, account: Some(nonempty(acct)?) },
            None => SecretSource::Keychain { service: nonempty(rest)?, account: None },
        }
    } else if let Some(v) = src.strip_prefix("env:") {
        if !env_name_ok(v) {
            return Err(format!("secret reference {whole:?}: bad variable name"));
        }
        SecretSource::Env(v.to_string())
    } else if let Some(f) = src.strip_prefix("file:") {
        let f = nonempty(f)?;
        let ok = match f.strip_prefix("~/") {
            // Home-relative: an agent's own credential file (made deny-read
            // for the sandbox by the profile that names it).
            Some(rest) => !rest.is_empty() && rest.split('/').all(|c| !c.is_empty() && c != "." && c != ".."),
            // Otherwise a file name in the broker config dir.
            None => !f.contains('/') && !f.starts_with('.'),
        };
        if !ok {
            return Err(format!(
                "secret reference {whole:?}: file: takes a name in the broker config dir or a ~/ path"
            ));
        }
        SecretSource::File(f)
    } else {
        return Err(format!("secret reference {whole:?}: use keychain:, env: or file:"));
    };
    Ok(SecretAlt { source, json_path: path })
}

impl SecretRef {
    pub fn parse(s: &str) -> Result<SecretRef, String> {
        let alternatives = s.split('|').map(|a| parse_alt(s, a)).collect::<Result<Vec<_>, _>>()?;
        Ok(SecretRef { alternatives })
    }

    pub fn describe(&self) -> String {
        self.alternatives
            .iter()
            .map(|a| {
                let base = match &a.source {
                    SecretSource::Keychain { service, account: Some(ac) } => format!("keychain:{service}/{ac}"),
                    SecretSource::Keychain { service, account: None } => format!("keychain:{service}"),
                    SecretSource::Env(v) => format!("env:{v}"),
                    SecretSource::File(f) => format!("file:{f}"),
                };
                if a.json_path.is_empty() { base } else { format!("{base}#{}", a.json_path.join(".")) }
            })
            .collect::<Vec<_>>()
            .join("|")
    }
}

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
    Static { secret: SecretRef },
    GitHubApp { issuer: String, permissions: BTreeMap<String, String>, repos: Vec<RepoId> },
}

impl CredKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredKind::Static { .. } => "static",
            CredKind::GitHubApp { .. } => "github_app",
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
}

/// Proof that a policy decision allowed attaching this credential. Only
/// this module constructs one; `creds` mints only against it.
#[derive(Clone, Debug)]
pub struct AllowedBinding {
    cred: Arc<CredentialDef>,
    grant_id: String,
}

impl AllowedBinding {
    pub fn credential(&self) -> &CredentialDef {
        &self.cred
    }
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
}

#[derive(Clone, Debug)]
struct PushRuleC {
    repo: RepoPattern,
    refs: Vec<RefPattern>,
    force: bool,
}

/// The L7 part of one grant.
#[derive(Clone, Debug)]
pub struct L7Rules {
    pub protocol: Protocol,
    methods: Option<BTreeSet<String>>,
    paths: Option<Vec<PathPattern>>,
    fetch: Vec<RepoPattern>,
    push: Vec<PushRuleC>,
    pub credential: Option<Arc<CredentialDef>>,
}

/// Variables and cross-references available while compiling.
#[derive(Clone, Debug, Default)]
pub struct CompileEnv {
    pub repo_remote: Option<RepoId>,
    pub github_app_issuers: BTreeSet<String>,
}

fn env_name_ok(v: &str) -> bool {
    let b = v.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn header_name_ok(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

/// Variables the broker itself sets in the sandbox; a sentinel may not replace them.
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

fn compile_credential(
    grant_id: &str,
    c: &CredentialSpec,
    protocol: Protocol,
    pattern: &HostPattern,
    env: &CompileEnv,
) -> Result<CredentialDef, String> {
    let id = c.id.clone().unwrap_or_else(|| grant_id.to_string());
    if let Some(v) = &c.env
        && (!env_name_ok(v) || RESERVED_ENV.contains(&v.to_ascii_uppercase().as_str()) || v.starts_with("BROKER_"))
    {
        return Err(format!("credential {id}: env {v:?} is not an allowed variable name"));
    }
    let attach = match (c.header.as_deref().map(str::to_ascii_lowercase), c.scheme.as_deref()) {
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
        other => return Err(format!("credential {id}: unknown kind {other:?} (static, github_app)")),
    };
    Ok(CredentialDef {
        id,
        kind,
        attach,
        env: c.env.clone(),
        swap_body: c.swap_body,
        hosts: vec![pattern.clone()],
        ttl,
    })
}

/// Compile the L7 keys of one egress entry (None when it has none).
pub fn compile_rules(
    grant_id: &str,
    e: &EgressEntry,
    pattern: &HostPattern,
    env: &CompileEnv,
) -> Result<Option<L7Rules>, String> {
    if e.passthrough {
        if e.wants_l7() {
            return Err(format!("{grant_id}: passthrough hosts cannot have L7 rules or credentials"));
        }
        return Ok(None);
    }
    if !e.wants_l7() {
        return Ok(None);
    }
    let protocol = match e.protocol.as_deref() {
        None | Some("http") => Protocol::Http,
        Some("git") => Protocol::Git,
        Some("registry") => Protocol::Registry,
        Some(p) => return Err(format!("{grant_id}: unknown protocol {p:?} (http, git, registry)")),
    };
    let methods = match &e.methods {
        None if protocol == Protocol::Registry => Some(["GET", "HEAD"].iter().map(|s| s.to_string()).collect()),
        None => None,
        Some(ms) => {
            let mut set = BTreeSet::new();
            for m in ms {
                if m.is_empty() || !m.bytes().all(|b| b.is_ascii_uppercase()) {
                    return Err(format!("{grant_id}: method {m:?} must be upper-case letters"));
                }
                set.insert(m.clone());
            }
            Some(set)
        }
    };
    let paths = e
        .paths
        .as_ref()
        .map(|ps| ps.iter().map(|p| PathPattern::parse(p)).collect::<Result<Vec<_>, _>>())
        .transpose()
        .map_err(|m| format!("{grant_id}: {m}"))?;
    let (mut fetch, mut push) = (Vec::new(), Vec::new());
    match (&e.allow, protocol) {
        (Some(_), Protocol::Http | Protocol::Registry) => {
            return Err(format!("{grant_id}: allow = {{ fetch, push }} needs protocol = \"git\""));
        }
        (_, Protocol::Git) if e.methods.is_some() || e.paths.is_some() => {
            return Err(format!("{grant_id}: protocol = \"git\" takes allow rules, not methods/paths"));
        }
        (None, Protocol::Git) => return Err(format!("{grant_id}: protocol = \"git\" needs allow rules")),
        (Some(a), Protocol::Git) => {
            for f in &a.fetch {
                fetch.push(RepoPattern::parse(f, env.repo_remote.as_ref()).map_err(|m| format!("{grant_id}: {m}"))?);
            }
            for p in &a.push {
                if p.refs.is_empty() {
                    return Err(format!("{grant_id}: a push rule needs refs (empty lists deny)"));
                }
                push.push(PushRuleC {
                    repo: RepoPattern::parse(&p.repo, env.repo_remote.as_ref())
                        .map_err(|m| format!("{grant_id}: {m}"))?,
                    refs: p
                        .refs
                        .iter()
                        .map(|r| RefPattern::parse(r))
                        .collect::<Result<_, _>>()
                        .map_err(|m| format!("{grant_id}: {m}"))?,
                    force: p.force,
                });
            }
        }
        (None, _) => {}
    }
    let credential = e
        .credential
        .as_ref()
        .map(|c| compile_credential(grant_id, c, protocol, pattern, env))
        .transpose()?
        .map(Arc::new);
    Ok(Some(L7Rules { protocol, methods, paths, fetch, push, credential }))
}

/// Deny reasons ranked from least to most specific, for reporting.
fn rank(r: Reason) -> u8 {
    match r {
        Reason::GitForcePush => 3,
        Reason::GitRefNotAllowed => 2,
        Reason::GitRepoNotAllowed => 1,
        _ => 0,
    }
}

impl L7Rules {
    pub fn allows(&self, a: &Action) -> Result<(), Reason> {
        match (a, self.protocol) {
            (Action::Http { method, path }, Protocol::Http | Protocol::Registry) => {
                let m_ok = self.methods.as_ref().is_none_or(|ms| ms.contains(method));
                let p_ok = self.paths.as_ref().is_none_or(|ps| ps.iter().any(|p| p.matches(path)));
                if m_ok && p_ok { Ok(()) } else { Err(Reason::L7NoRuleMatched) }
            }
            (Action::GitFetch { repo }, Protocol::Git) => {
                if self.fetch.iter().any(|p| p.matches(repo)) {
                    Ok(())
                } else {
                    Err(Reason::GitRepoNotAllowed)
                }
            }
            (Action::GitPushAdvertise { repo }, Protocol::Git) => {
                if self.push.iter().any(|r| r.repo.matches(repo)) {
                    Ok(())
                } else {
                    Err(Reason::GitRepoNotAllowed)
                }
            }
            (Action::GitPush { repo, refname, force, .. }, Protocol::Git) => {
                let by_repo: Vec<&PushRuleC> = self.push.iter().filter(|r| r.repo.matches(repo)).collect();
                if by_repo.is_empty() {
                    return Err(Reason::GitRepoNotAllowed);
                }
                let by_ref: Vec<&&PushRuleC> =
                    by_repo.iter().filter(|r| r.refs.iter().any(|p| p.matches(refname))).collect();
                if by_ref.is_empty() {
                    return Err(Reason::GitRefNotAllowed);
                }
                if by_ref.iter().any(|r| r.force || !force) { Ok(()) } else { Err(Reason::GitForcePush) }
            }
            _ => Err(Reason::L7NoRuleMatched),
        }
    }
}

/// The outcome of authorizing one terminated request.
#[derive(Clone, Debug)]
pub struct L7Decision {
    pub result: Result<(), Reason>,
    /// Grants that allowed (on allow) or were consulted (on deny).
    pub policy_ids: Vec<String>,
    pub binding: Option<AllowedBinding>,
    /// Per action: verb and result.
    pub actions: Vec<(String, Result<(), Reason>)>,
}

/// Authorize `actions` against the grants that admitted the connection.
/// Each action must be allowed by some grant (a grant without L7 rules
/// allows everything on its host); the credential of a grant is attached
/// only if that grant allowed every action.
pub fn authorize<'a>(
    grants: impl IntoIterator<Item = (&'a str, Option<&'a L7Rules>)>,
    actions: &[Action],
) -> L7Decision {
    let grants: Vec<(&str, Option<&L7Rules>)> = grants.into_iter().collect();
    let consulted: Vec<String> = grants.iter().map(|(id, _)| id.to_string()).collect();
    if actions.is_empty() {
        // An adapter that classified nothing: fail closed.
        return L7Decision {
            result: Err(Reason::L7NoRuleMatched),
            policy_ids: consulted,
            binding: None,
            actions: vec![],
        };
    }
    let mut per_action = Vec::new();
    let mut allowing: BTreeSet<&str> = BTreeSet::new();
    let mut overall: Result<(), Reason> = Ok(());
    for a in actions {
        let mut best: Option<Reason> = None;
        let mut ok = false;
        for (id, rules) in &grants {
            match rules.map(|r| r.allows(a)).unwrap_or(Ok(())) {
                Ok(()) => {
                    ok = true;
                    allowing.insert(id);
                }
                Err(r) => {
                    if best.is_none_or(|b| rank(r) > rank(b)) {
                        best = Some(r);
                    }
                }
            }
        }
        let r = if ok { Ok(()) } else { Err(best.unwrap_or(Reason::L7NoRuleMatched)) };
        if let (Err(e), Ok(())) = (r, overall) {
            overall = Err(e);
        }
        per_action.push((a.verb(), r));
    }
    if let Err(reason) = overall {
        return L7Decision { result: Err(reason), policy_ids: consulted, binding: None, actions: per_action };
    }
    // Grants that allowed every action.
    let full: Vec<&(&str, Option<&L7Rules>)> = grants
        .iter()
        .filter(|(_, rules)| actions.iter().all(|a| rules.map(|r| r.allows(a)).unwrap_or(Ok(())).is_ok()))
        .collect();
    let mut creds: Vec<(&str, &Arc<CredentialDef>)> =
        full.iter().filter_map(|(id, r)| r.and_then(|r| r.credential.as_ref()).map(|c| (*id, c))).collect();
    creds.dedup_by(|a, b| a.1.id == b.1.id);
    let policy_ids: Vec<String> = allowing.iter().map(|s| s.to_string()).collect();
    match creds.len() {
        0 => L7Decision { result: Ok(()), policy_ids, binding: None, actions: per_action },
        1 => L7Decision {
            result: Ok(()),
            policy_ids,
            binding: Some(AllowedBinding { cred: creds[0].1.clone(), grant_id: creds[0].0.to_string() }),
            actions: per_action,
        },
        _ => L7Decision { result: Err(Reason::AmbiguousCredential), policy_ids, binding: None, actions: per_action },
    }
}

#[cfg(test)]
mod tests;
