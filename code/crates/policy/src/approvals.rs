//! Step-up approvals (Fatigue-Resistant Approval Interfaces, ADR-037): a
//! human, outside the sandbox, approves one exact action for one session.
//! The approval-conditional forbids (`needs_approval`, `rule_of_two`,
//! `public_sink_after_untrusted_input`) then see `context.session.approved`
//! for that action only. An approval is single use unless granted for the
//! rest of the session; approvals die with the session.

use crate::l7::Action;
use audit::Reason;
use netguard::CanonicalHost;
use std::collections::HashMap;
use std::sync::Mutex;

/// How long an approval lasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The next allowed request that uses it.
    Once,
    /// Every request in this session.
    Session,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Once => "once",
            Scope::Session => "session",
        }
    }
}

/// The approvals a session holds, keyed by [`approval_key`].
#[derive(Debug, Default)]
pub struct Approvals {
    granted: Mutex<HashMap<String, Scope>>,
}

impl Approvals {
    pub fn grant(&self, key: String, scope: Scope) {
        let mut g = self.granted.lock().unwrap_or_else(|p| p.into_inner());
        // A session-wide approval is never narrowed back to once.
        if g.get(&key) != Some(&Scope::Session) {
            g.insert(key, scope);
        }
    }

    pub fn is_approved(&self, key: &str) -> bool {
        self.granted.lock().unwrap_or_else(|p| p.into_inner()).contains_key(key)
    }

    /// Use up single-use approvals among `keys` (called once a request that
    /// relied on them is allowed).
    pub fn consume(&self, keys: &[String]) {
        let mut g = self.granted.lock().unwrap_or_else(|p| p.into_inner());
        for k in keys {
            if g.get(k) == Some(&Scope::Once) {
                g.remove(k);
            }
        }
    }
}

/// Reasons a human approval can lift.
pub fn is_approval_reason(r: Reason) -> bool {
    matches!(r, Reason::NeedsApproval | Reason::RuleOfTwo | Reason::PublicSinkAfterUntrustedInput)
}

/// The exact action an approval names: the verb and its resource, with the
/// host and port for host-level actions and the force flag for pushes (a
/// force push is never the same approval as a fast-forward).
pub fn approval_key(host: &CanonicalHost, port: u16, a: &Action) -> String {
    let authority = if port == 443 { host.as_str().to_string() } else { format!("{host}:{port}") };
    match a {
        Action::Http { method, path } => format!("http {method} {authority}{path}"),
        Action::GitFetch { repo, .. } => format!("git.fetch {repo}"),
        Action::GitPushAdvertise { repo } => format!("git.advertise {repo}"),
        Action::GitPush { repo, refname, force, .. } => format!("git.push {repo} {refname} force={force}"),
        Action::GitHub { verb, repo: Some(r), .. } => format!("github {verb} {r}"),
        Action::GitHub { verb, repo: None, .. } => format!("github {verb} {authority}"),
        Action::S3 { op, bucket, key } => format!("{op} {authority}/{bucket}/{key}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::RepoId;
    use netguard::canon_host;

    #[test]
    fn keys_name_the_exact_action() {
        let gh = canon_host(b"github.com").unwrap();
        let repo = RepoId::parse("github.com/acme/web").unwrap();
        let push =
            |force| Action::GitPush { repo: repo.clone(), refname: "refs/heads/agent/x".into(), force, update: "x" };
        assert_eq!(approval_key(&gh, 443, &push(false)), "git.push github.com/acme/web refs/heads/agent/x force=false");
        assert_ne!(approval_key(&gh, 443, &push(false)), approval_key(&gh, 443, &push(true)));
        let api = canon_host(b"api.github.com").unwrap();
        let post = Action::Http { method: "POST".into(), path: "/x".into() };
        assert_eq!(approval_key(&api, 8443, &post), "http POST api.github.com:8443/x");
    }

    #[test]
    fn once_is_used_up_and_session_stays() {
        let a = Approvals::default();
        a.grant("k1".into(), Scope::Once);
        a.grant("k2".into(), Scope::Session);
        a.grant("k2".into(), Scope::Once);
        assert!(a.is_approved("k1") && a.is_approved("k2"));
        a.consume(&["k1".into(), "k2".into()]);
        assert!(!a.is_approved("k1"));
        assert!(a.is_approved("k2"), "a session approval is not used up nor narrowed");
        assert!(!a.is_approved("k3"));
    }
}
