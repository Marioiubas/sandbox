//! Per-session sentinels (Sentinel Swap Pattern). A sentinel is 24 random
//! bytes with a fixed prefix: it encodes nothing, is honoured only by this
//! broker, only for this session and only on the hosts its credential is
//! bound to, so a copy taken off-host is useless (M1 acceptance B5).

use netguard::{CanonicalHost, HostPattern};
use policy::CredentialDef;
use std::sync::Arc;

pub const PREFIX: &str = "brk_s_";

struct Entry {
    value: String,
    credential_id: String,
    env: Option<String>,
    hosts: Vec<HostPattern>,
}

/// The sentinels of one session.
pub struct Sentinels {
    entries: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SentinelCheck {
    /// This session's sentinel for `credential_id`, sent to a bound host.
    Valid(String),
    /// This session's sentinel, sent to a host it is not bound to.
    WrongHost(String),
    /// Not a sentinel of this session.
    NotSentinel,
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn fresh() -> String {
    let mut b = [0u8; 24];
    getrandom::fill(&mut b).expect("OS randomness");
    format!("{PREFIX}{}", hex::encode(b))
}

impl Sentinels {
    /// One fresh sentinel per declared credential.
    pub fn issue(creds: &[Arc<CredentialDef>]) -> Sentinels {
        Sentinels {
            entries: creds
                .iter()
                .map(|c| Entry {
                    value: fresh(),
                    credential_id: c.id.clone(),
                    env: c.env.clone(),
                    hosts: c.hosts.clone(),
                })
                .collect(),
        }
    }

    /// `(variable, sentinel)` pairs for the sandbox environment.
    pub fn env(&self) -> Vec<(String, String)> {
        self.entries.iter().filter_map(|e| e.env.as_ref().map(|v| (v.clone(), e.value.clone()))).collect()
    }

    /// The sentinel issued for a credential (tests and body swap).
    pub fn value_for(&self, credential_id: &str) -> Option<&str> {
        self.entries.iter().find(|e| e.credential_id == credential_id).map(|e| e.value.as_str())
    }

    /// Compare `v` against every sentinel in constant time per entry.
    pub fn check(&self, v: &[u8], dest: &CanonicalHost) -> SentinelCheck {
        let mut hit: Option<&Entry> = None;
        for e in &self.entries {
            if ct_eq(e.value.as_bytes(), v) {
                hit = Some(e);
            }
        }
        match hit {
            None => SentinelCheck::NotSentinel,
            Some(e) if e.hosts.iter().any(|p| p.matches(dest)) => SentinelCheck::Valid(e.credential_id.clone()),
            Some(e) => SentinelCheck::WrongHost(e.credential_id.clone()),
        }
    }

    /// Whether `hay` contains any sentinel of this session.
    pub fn find_any<'a>(&'a self, hay: &[u8]) -> Option<&'a str> {
        self.entries
            .iter()
            .find(|e| hay.windows(e.value.len()).any(|w| w == e.value.as_bytes()))
            .map(|e| e.credential_id.as_str())
    }

    /// Replace every occurrence of `credential_id`'s sentinel in `body` with
    /// `secret`. Returns the new body and the number of replacements.
    pub fn swap_in_body(&self, body: &[u8], credential_id: &str, secret: &[u8]) -> (Vec<u8>, usize) {
        let Some(s) = self.value_for(credential_id).map(str::as_bytes) else { return (body.to_vec(), 0) };
        let mut out = Vec::with_capacity(body.len());
        let (mut i, mut n) = (0, 0);
        while i < body.len() {
            if body[i..].starts_with(s) {
                out.extend_from_slice(secret);
                i += s.len();
                n += 1;
            } else {
                out.push(body[i]);
                i += 1;
            }
        }
        (out, n)
    }
}

impl std::fmt::Debug for Sentinels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sentinels({} bound)", self.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netguard::canon_host;
    use policy::{AttachSpec, CredKind, SecretRef};

    fn cred(id: &str, host: &str, env: &str) -> Arc<CredentialDef> {
        Arc::new(CredentialDef {
            id: id.into(),
            kind: CredKind::Static { secret: SecretRef::parse("env:X").unwrap() },
            attach: AttachSpec::Bearer,
            env: Some(env.into()),
            swap_body: false,
            hosts: vec![HostPattern::parse(host).unwrap()],
            ttl: None,
            high_risk: false,
        })
    }

    #[test]
    fn bound_to_session_and_host() {
        let creds = vec![cred("a", "api.anthropic.com", "ANTHROPIC_API_KEY"), cred("g", "*.github.com", "GH_TOKEN")];
        let s1 = Sentinels::issue(&creds);
        let s2 = Sentinels::issue(&creds);
        let (k, v) = s1.env()[0].clone();
        assert_eq!(k, "ANTHROPIC_API_KEY");
        assert!(v.starts_with(PREFIX) && v.len() == PREFIX.len() + 48);
        let api = canon_host(b"api.anthropic.com").unwrap();
        let evil = canon_host(b"evil.example").unwrap();
        assert_eq!(s1.check(v.as_bytes(), &api), SentinelCheck::Valid("a".into()));
        assert_eq!(s1.check(v.as_bytes(), &evil), SentinelCheck::WrongHost("a".into()));
        assert_eq!(s2.check(v.as_bytes(), &api), SentinelCheck::NotSentinel, "another session's sentinel");
        assert_eq!(s1.check(b"sk-ant-attacker", &api), SentinelCheck::NotSentinel);
        let g = s1.value_for("g").unwrap();
        assert_eq!(s1.check(g.as_bytes(), &canon_host(b"api.github.com").unwrap()), SentinelCheck::Valid("g".into()));
        assert_eq!(s1.check(g.as_bytes(), &canon_host(b"github.com").unwrap()), SentinelCheck::WrongHost("g".into()));
    }

    #[test]
    fn body_swap() {
        let creds = vec![cred("a", "api.example.com", "A")];
        let s = Sentinels::issue(&creds);
        let v = s.value_for("a").unwrap().to_string();
        let body = format!("client_secret={v}&x={v}");
        let (out, n) = s.swap_in_body(body.as_bytes(), "a", b"REAL");
        assert_eq!(n, 2);
        assert_eq!(out, b"client_secret=REAL&x=REAL");
        assert_eq!(s.find_any(body.as_bytes()), Some("a"));
        assert_eq!(s.find_any(b"nothing here"), None);
    }
}
