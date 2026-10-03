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

    /// Claim the approvals a decision relied on, atomically: true only if
    /// every key is still held, and then the single-use ones are used up.
    /// False, changing nothing, if another request used one first: a
    /// single-use approval allows exactly one request.
    pub fn claim(&self, keys: &[String]) -> bool {
        let mut g = self.granted.lock().unwrap_or_else(|p| p.into_inner());
        if !keys.iter().all(|k| g.contains_key(k)) {
            return false;
        }
        for k in keys {
            if g.get(k) == Some(&Scope::Once) {
                g.remove(k);
            }
        }
        true
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

/// The exact MCP tool call an approval names: the server, the tool and a
/// digest of its arguments, so an approval never covers other arguments.
pub fn mcp_approval_key(server: &str, tool: &str, args_integrity: &str) -> String {
    format!("mcp.call_tool {server} {tool} args={args_integrity}")
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
    fn a_claim_is_all_or_nothing_and_once_is_claimed_once() {
        let a = Approvals::default();
        a.grant("once".into(), Scope::Once);
        a.grant("session".into(), Scope::Session);
        assert!(a.claim(&[]), "nothing relied on, nothing to claim");
        assert!(!a.claim(&["once".into(), "missing".into()]), "all or nothing");
        assert!(a.is_approved("once"), "a failed claim changes nothing");
        assert!(a.claim(&["once".into(), "session".into()]));
        assert!(!a.claim(&["once".into()]), "used up");
        assert!(a.claim(&["session".into()]) && a.claim(&["session".into()]), "kept for the session");
        // Many threads, one single-use approval: exactly one claim succeeds.
        a.grant("race".into(), Scope::Once);
        let a = std::sync::Arc::new(a);
        let wins: usize = (0..16)
            .map(|_| {
                let a = a.clone();
                std::thread::spawn(move || a.claim(&["race".into()]) as usize)
            })
            .map(|h| h.join().unwrap())
            .sum();
        assert_eq!(wins, 1);
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
