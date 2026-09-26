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
    /// The GitHub REST API: every request maps to a verb (GitHub API Adapter).
    GitHub,
    /// The Amazon S3 REST API: object reads, listings, writes and deletes
    /// under granted key prefixes (AWS STS Session Policies).
    S3,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Git => "git",
            Protocol::Registry => "registry",
            Protocol::GitHub => "github",
            Protocol::S3 => "s3",
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
        /// The fetch may read a pull request's head (`refs/pull/*`): text
        /// anyone can write on a public repository (ADR-040).
        pull_refs: bool,
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
    /// A GitHub API verb (`pr.create`, `repo.read`, …) on a repository or
    /// on the API host; emitted beside the request's `Http` action.
    GitHub {
        verb: String,
        repo: Option<RepoId>,
        /// Filled by the broker from its session cache before authorizing.
        visibility: crate::github::Visibility,
        /// The response carries issue, PR or comment bodies (label input).
        bodies: bool,
        method: String,
        path: String,
        /// GraphQL: the node ID naming the repository (mutations); the
        /// broker resolves it to `repo` before deciding. Unresolved denies.
        node: Option<String>,
        /// GraphQL: the root field this verb came from (audit only).
        field: Option<String>,
    },
    /// An S3 operation class (`s3.get`, `s3.list`, `s3.put`, `s3.delete`)
    /// on a bucket and key (for listings, the requested prefix); emitted
    /// beside the request's `Http` action.
    S3 {
        op: String,
        bucket: String,
        key: String,
    },
}

impl Action {
    /// Structured form for audit rows (the learner reads this, never `verb`).
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Action::Http { method, path } => serde_json::json!({ "kind": "http", "method": method, "path": path }),
            Action::GitFetch { repo, pull_refs } => {
                serde_json::json!({ "kind": "git.fetch", "repo": repo.to_string(), "pull_refs": pull_refs })
            }
            Action::GitPushAdvertise { repo } => {
                serde_json::json!({ "kind": "git.advertise", "repo": repo.to_string() })
            }
            Action::GitHub { verb, repo, visibility, node, field, .. } => {
                let mut v = serde_json::json!({
                    "kind": "github", "verb": verb, "repo": repo.as_ref().map(|r| r.to_string()),
                    "visibility": visibility.as_str(),
                });
                if let Some(n) = node {
                    v["node"] = n.clone().into();
                }
                if let Some(f) = field {
                    v["graphql"] = f.clone().into();
                }
                v
            }
            Action::GitPush { repo, refname, force, update } => serde_json::json!({
                "kind": "git.push", "repo": repo.to_string(), "ref": refname, "force": force, "update": update,
            }),
            Action::S3 { op, bucket, key } => {
                serde_json::json!({ "kind": "s3", "op": op, "bucket": bucket, "key": key })
            }
        }
    }

    /// Inverse of [`to_json`](Self::to_json) (for replay).
    pub fn from_json(v: &serde_json::Value) -> Option<Action> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let repo = || s("repo").and_then(|r| RepoId::parse(&r));
        Some(match v.get("kind")?.as_str()? {
            "http" => Action::Http { method: s("method")?, path: s("path")? },
            "git.fetch" => Action::GitFetch { repo: repo()?, pull_refs: false },
            "git.advertise" => Action::GitPushAdvertise { repo: repo()? },
            "github" => Action::GitHub {
                verb: s("verb").filter(|v| crate::github::is_verb(v))?,
                repo: s("repo").and_then(|r| RepoId::parse(&r)),
                visibility: crate::github::Visibility::Unknown,
                bodies: false,
                method: String::new(),
                path: String::new(),
                node: None,
                field: None,
            },
            "git.push" => Action::GitPush {
                repo: repo()?,
                refname: s("ref")?,
                force: v.get("force")?.as_bool()?,
                update: "replayed",
            },
            "s3" => Action::S3 { op: s("op").filter(|o| crate::s3::is_op(o))?, bucket: s("bucket")?, key: s("key")? },
            _ => return None,
        })
    }

    pub fn method(&self) -> Option<&str> {
        match self {
            Action::Http { method, .. } => Some(method),
            _ => None,
        }
    }

    /// The audit verb, e.g. `git.push github.com/acme/web refs/heads/main force=false`.
    pub fn verb(&self) -> String {
        match self {
            Action::Http { method, path } => format!("http {method} {path}"),
            Action::GitFetch { repo, .. } => format!("git.fetch {repo}"),
            Action::GitPushAdvertise { repo } => format!("git.push-advertise {repo}"),
            Action::GitPush { repo, refname, force, update } => {
                format!("git.push {repo} {refname} force={force} ({update})")
            }
            Action::GitHub { verb, repo: Some(r), .. } => format!("github {verb} {r}"),
            Action::GitHub { verb, repo: None, .. } => format!("github {verb}"),
            Action::S3 { op, bucket, key } => format!("{op} {bucket}/{key}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PushRuleC {
    pub repo: RepoPattern,
    pub refs: Vec<RefPattern>,
    pub force: bool,
}

/// The L7 part of one grant.
#[derive(Clone, Debug)]
pub struct L7Rules {
    pub protocol: Protocol,
    methods: Option<BTreeSet<String>>,
    paths: Option<Vec<PathPattern>>,
    fetch: Vec<RepoPattern>,
    push: Vec<PushRuleC>,
    /// `protocol = "github"`: granted verbs and the repositories they apply to.
    verbs: BTreeSet<String>,
    repos: Vec<RepoPattern>,
    /// `protocol = "s3"`: the bucket and key prefixes.
    s3: Option<crate::s3::S3Rules>,
    pub credential: Option<Arc<CredentialDef>>,
}

/// Variables and cross-references available while compiling.
#[derive(Clone, Debug, Default)]
pub struct CompileEnv {
    pub repo_remote: Option<RepoId>,
    pub github_app_issuers: BTreeSet<String>,
    pub aws_sts_issuers: BTreeSet<String>,
    /// `[trifecta] deny_public_sinks_after_untrusted_input` (user/org).
    pub deny_public_sinks_after_untrusted_input: bool,
    /// The session's principal (Task) and mode.
    pub session: crate::cedar::SessionInfo,
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
        Some("github") => Protocol::GitHub,
        Some("s3") => Protocol::S3,
        Some(p) => return Err(format!("{grant_id}: unknown protocol {p:?} (http, git, registry, github, s3)")),
    };
    let (verbs, repos) = crate::github::compile_verbs(grant_id, e, protocol, env)?;
    let s3 = crate::s3::compile(grant_id, e, protocol, pattern)?;
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
        (Some(_), Protocol::Http | Protocol::Registry | Protocol::GitHub | Protocol::S3) => {
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
        .map(|c| credential::compile_credential(grant_id, c, protocol, pattern, env, s3.as_ref()))
        .transpose()?
        .map(Arc::new);
    Ok(Some(L7Rules { protocol, methods, paths, fetch, push, verbs, repos, s3, credential }))
}

impl L7Rules {
    pub fn methods(&self) -> Option<&BTreeSet<String>> {
        self.methods.as_ref()
    }
    pub fn paths(&self) -> Option<&[PathPattern]> {
        self.paths.as_deref()
    }
    pub fn fetch(&self) -> &[RepoPattern] {
        &self.fetch
    }
    pub fn push_rules(&self) -> &[PushRuleC] {
        &self.push
    }
    pub fn verbs(&self) -> &BTreeSet<String> {
        &self.verbs
    }
    pub fn repos(&self) -> &[RepoPattern] {
        &self.repos
    }
    pub fn s3(&self) -> Option<&crate::s3::S3Rules> {
        self.s3.as_ref()
    }

    /// The reference (explainer) evaluation of one action against this
    /// grant: Cedar decides; this names the most specific unmet condition.
    pub fn allows(&self, a: &Action) -> Result<(), Reason> {
        match (a, self.protocol) {
            (Action::Http { method, path }, Protocol::Http | Protocol::Registry) => {
                let m_ok = self.methods.as_ref().is_none_or(|ms| ms.contains(method));
                let p_ok = self.paths.as_ref().is_none_or(|ps| ps.iter().any(|p| p.matches(path)));
                if m_ok && p_ok { Ok(()) } else { Err(Reason::L7NoRuleMatched) }
            }
            // On GitHub API and S3 grants the verb or operation decides; the
            // request's Http action rides along.
            (Action::Http { .. }, Protocol::GitHub | Protocol::S3) => Ok(()),
            (Action::S3 { op, bucket, key }, Protocol::S3) => match &self.s3 {
                Some(r) => crate::s3::rule_allows(r, op, bucket, key),
                None => Err(Reason::S3PrefixNotAllowed),
            },
            (Action::GitHub { verb, repo, .. }, Protocol::GitHub) => {
                crate::github::rule_allows(&self.verbs, &self.repos, verb, repo.as_ref())
            }
            (Action::GitFetch { repo, .. }, Protocol::Git) => {
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

mod credential;
mod explain;
mod secret;

pub use credential::{AllowedBinding, AttachSpec, CredKind, CredentialDef, GITHUB_APP_MAX_TTL, parse_ttl};
pub use explain::{L7Decision, explain};
pub use secret::{SecretAlt, SecretRef, SecretSource};

#[cfg(test)]
mod tests;
