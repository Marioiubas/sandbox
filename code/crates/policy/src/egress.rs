//! Host admission: the M0 stand-in for the L4 Cedar request.
//!
//! A destination is admitted only if its canonical name matches a grant on
//! that port, and then only if **every** address the broker resolved is of a
//! class the grant may reach (I6: match the name and the resolved address).

use crate::config::EgressEntry;
use crate::doh::is_doh_endpoint;
use crate::l7::{self, Action, CompileEnv, CredentialDef, L7Decision, L7Rules, Protocol};
use audit::Reason;
use netguard::{AddrClass, CanonicalHost, HostPattern, classify_addr};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Grant {
    pub id: String,
    pub pattern: HostPattern,
    pub ports: Vec<u16>,
    pub allow_classes: BTreeSet<AddrClass>,
    pub pinned: Vec<IpAddr>,
    /// L7 rules; `None` for a plain host grant.
    pub l7: Option<Arc<L7Rules>>,
    /// Never terminate TLS for this host (certificate-pinning clients).
    pub passthrough: bool,
}

/// How an admitted connection is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathChoice {
    /// Splice bytes after the SNI check; nothing is decrypted or attached.
    L4,
    /// Terminate TLS, authorize each request, attach credentials.
    L7,
}

#[derive(Clone, Debug, Default)]
pub struct EgressPolicy {
    grants: Vec<Grant>,
}

/// The result of a successful host admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    /// Determining grant IDs (the audit row's `policy_ids`).
    pub policy_ids: Vec<String>,
    allow_classes: BTreeSet<AddrClass>,
    /// For IP-literal hosts named by a grant: that exact address.
    exact_ip: Option<IpAddr>,
    /// Addresses pinned by the matching grants; when non-empty the broker
    /// uses them instead of DNS.
    pub pinned: Vec<IpAddr>,
    /// Indices of the grants that admitted the host on this port.
    grants: Vec<usize>,
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("{id}: {source}")]
    Pattern { id: String, source: netguard::canon::PatternError },
    #[error("{id}: port 0 is not a port")]
    PortZero { id: String },
    #[error("{id}: unknown address class {class:?}")]
    UnknownClass { id: String, class: String },
    #[error("duplicate grant id {0}")]
    DuplicateId(String),
    #[error("{id}: pinned address {addr:?} is not a canonical IP literal")]
    BadPinnedAddr { id: String, addr: String },
    #[error("{0}")]
    L7(String),
    #[error("duplicate credential id {0}")]
    DuplicateCredential(String),
}

impl EgressPolicy {
    /// Compile entries from one or more trusted layers (built-in profile,
    /// user, org). `scope` prefixes generated IDs, e.g. `user:egress[2]`.
    pub fn compile<'a>(layers: impl IntoIterator<Item = (&'a str, &'a [EgressEntry])>) -> Result<Self, CompileError> {
        Self::compile_with(layers, &CompileEnv::default())
    }

    /// As [`compile`](Self::compile), with `${repo_remote}` and the issuer
    /// names from the user/org layers available.
    pub fn compile_with<'a>(
        layers: impl IntoIterator<Item = (&'a str, &'a [EgressEntry])>,
        env: &CompileEnv,
    ) -> Result<Self, CompileError> {
        let mut grants = Vec::new();
        let mut ids = BTreeSet::new();
        let mut cred_ids = BTreeSet::new();
        for (scope, entries) in layers {
            for (i, e) in entries.iter().enumerate() {
                let id = match &e.id {
                    Some(id) => format!("{scope}:{id}"),
                    None => format!("{scope}:egress[{i}]"),
                };
                let pattern =
                    HostPattern::parse(&e.host).map_err(|source| CompileError::Pattern { id: id.clone(), source })?;
                let ports = e.ports.clone().unwrap_or_else(|| vec![443]);
                if ports.contains(&0) {
                    return Err(CompileError::PortZero { id });
                }
                let mut allow_classes = BTreeSet::new();
                for c in &e.allow_addr_classes {
                    let class = AddrClass::parse(c)
                        .ok_or_else(|| CompileError::UnknownClass { id: id.clone(), class: c.clone() })?;
                    allow_classes.insert(class);
                }
                let mut pinned = Vec::new();
                for a in &e.addrs {
                    // Pinned addresses go through the same canonicaliser.
                    let ip = netguard::canon_host(a.as_bytes())
                        .ok()
                        .and_then(|h| h.ip())
                        .ok_or_else(|| CompileError::BadPinnedAddr { id: id.clone(), addr: a.clone() })?;
                    pinned.push(ip);
                }
                if !ids.insert(id.clone()) {
                    return Err(CompileError::DuplicateId(id));
                }
                let l7 = l7::compile_rules(&id, e, &pattern, env).map_err(CompileError::L7)?.map(Arc::new);
                if let Some(c) = l7.as_ref().and_then(|r| r.credential.as_ref())
                    && !cred_ids.insert(c.id.clone())
                {
                    return Err(CompileError::DuplicateCredential(c.id.clone()));
                }
                grants.push(Grant { id, pattern, ports, allow_classes, pinned, l7, passthrough: e.passthrough });
            }
        }
        Ok(EgressPolicy { grants })
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Name (or literal) and port admission. Never touches the network.
    pub fn admit_host(&self, host: &CanonicalHost, port: u16) -> Result<Admission, (Reason, Vec<String>)> {
        if is_doh_endpoint(host) {
            return Err((Reason::DohEndpoint, vec!["builtin:doh-deny".into()]));
        }
        let matching: Vec<&Grant> = self.grants.iter().filter(|g| g.pattern.matches(host)).collect();
        if matching.is_empty() {
            let reason = if host.is_ip_literal() { Reason::IpLiteral } else { Reason::HostNotAllowed };
            return Err((reason, vec![]));
        }
        let on_port: Vec<&Grant> = matching.iter().copied().filter(|g| g.ports.contains(&port)).collect();
        if on_port.is_empty() {
            return Err((Reason::PortNotAllowed, matching.iter().map(|g| g.id.clone()).collect()));
        }
        Ok(Admission {
            policy_ids: on_port.iter().map(|g| g.id.clone()).collect(),
            allow_classes: on_port.iter().flat_map(|g| g.allow_classes.iter().copied()).collect(),
            exact_ip: host.ip(),
            pinned: on_port.iter().flat_map(|g| g.pinned.iter().copied()).collect(),
            grants: self
                .grants
                .iter()
                .enumerate()
                .filter(|(_, g)| g.pattern.matches(host) && g.ports.contains(&port))
                .map(|(i, _)| i)
                .collect(),
        })
    }

    fn admitted<'a>(&'a self, adm: &'a Admission) -> impl Iterator<Item = &'a Grant> + 'a {
        adm.grants.iter().filter_map(|&i| self.grants.get(i))
    }

    /// L4 unless some admitting grant has L7 rules; a passthrough grant
    /// forces L4 (and therefore no credential) for the host.
    pub fn path_choice(&self, adm: &Admission) -> PathChoice {
        if self.admitted(adm).any(|g| g.passthrough) {
            return PathChoice::L4;
        }
        if self.admitted(adm).any(|g| g.l7.is_some()) { PathChoice::L7 } else { PathChoice::L4 }
    }

    /// Protocols the admitting grants declare (selects the adapter).
    pub fn protocols(&self, adm: &Admission) -> BTreeSet<Protocol> {
        self.admitted(adm).filter_map(|g| g.l7.as_ref().map(|r| r.protocol)).collect()
    }

    /// Authorize the actions of one terminated request.
    pub fn authorize_l7(&self, adm: &Admission, actions: &[Action]) -> L7Decision {
        l7::authorize(self.admitted(adm).map(|g| (g.id.as_str(), g.l7.as_deref())), actions)
    }

    /// Every declared credential (for sentinels at session start).
    pub fn credentials(&self) -> Vec<Arc<CredentialDef>> {
        self.grants.iter().filter_map(|g| g.l7.as_ref().and_then(|r| r.credential.clone())).collect()
    }

    /// Address admission over the broker-resolved set: all must pass.
    pub fn admit_addrs(&self, adm: &Admission, addrs: &[IpAddr]) -> Result<(), (Reason, IpAddr)> {
        for &a in addrs {
            let class = classify_addr(a);
            let ok = class == AddrClass::Public || adm.exact_ip == Some(a) || adm.allow_classes.contains(&class);
            if !ok {
                return Err((class.deny_reason().unwrap_or(Reason::ReservedAddr), a));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netguard::canon_host;

    fn entry(host: &str) -> EgressEntry {
        EgressEntry { host: host.into(), ..Default::default() }
    }
    fn h(s: &str) -> CanonicalHost {
        canon_host(s.as_bytes()).unwrap()
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = EgressPolicy::compile([("user", &[][..])]).unwrap();
        assert!(p.is_empty());
        assert_eq!(p.admit_host(&h("api.github.com"), 443).unwrap_err().0, Reason::HostNotAllowed);
        assert_eq!(p.admit_host(&h("8.8.8.8"), 443).unwrap_err().0, Reason::IpLiteral);
    }

    #[test]
    fn name_port_and_classes() {
        let entries = vec![
            entry("api.github.com"),
            EgressEntry { host: "*.example.com".into(), ports: Some(vec![443, 8443]), ..Default::default() },
            EgressEntry { host: "no-ports.test".into(), ports: Some(vec![]), ..Default::default() },
            EgressEntry {
                host: "local.test".into(),
                allow_addr_classes: vec!["loopback".into()],
                ..Default::default()
            },
        ];
        let p = EgressPolicy::compile([("user", entries.as_slice())]).unwrap();
        let a = p.admit_host(&h("API.GitHub.com"), 443).unwrap();
        assert_eq!(a.policy_ids, vec!["user:egress[0]"]);
        assert_eq!(p.admit_host(&h("api.github.com"), 22).unwrap_err().0, Reason::PortNotAllowed);
        assert_eq!(p.admit_host(&h("github.com"), 443).unwrap_err().0, Reason::HostNotAllowed);
        assert!(p.admit_host(&h("a.example.com"), 8443).is_ok());
        assert_eq!(p.admit_host(&h("example.com"), 443).unwrap_err().0, Reason::HostNotAllowed);
        assert_eq!(p.admit_host(&h("no-ports.test"), 443).unwrap_err().0, Reason::PortNotAllowed);

        // Resolved-address checks.
        let a = p.admit_host(&h("api.github.com"), 443).unwrap();
        assert!(p.admit_addrs(&a, &["140.82.112.5".parse().unwrap()]).is_ok());
        assert_eq!(p.admit_addrs(&a, &["169.254.169.254".parse().unwrap()]).unwrap_err().0, Reason::MetadataAddr);
        assert_eq!(
            p.admit_addrs(&a, &["140.82.112.5".parse().unwrap(), "10.0.0.1".parse().unwrap()]).unwrap_err().0,
            Reason::PrivateAddr,
            "one bad address denies the whole name"
        );
        let l = p.admit_host(&h("local.test"), 443).unwrap();
        assert!(p.admit_addrs(&l, &["127.0.0.1".parse().unwrap()]).is_ok());
        assert_eq!(p.admit_addrs(&l, &["169.254.169.254".parse().unwrap()]).unwrap_err().0, Reason::MetadataAddr);
    }

    #[test]
    fn explicit_ip_literal_grant() {
        let entries = vec![entry("10.1.2.3")];
        let p = EgressPolicy::compile([("user", entries.as_slice())]).unwrap();
        let a = p.admit_host(&h("10.1.2.3"), 443).unwrap();
        assert!(p.admit_addrs(&a, &["10.1.2.3".parse().unwrap()]).is_ok());
        assert_eq!(p.admit_host(&h("10.1.2.4"), 443).unwrap_err().0, Reason::IpLiteral);
    }

    #[test]
    fn doh_is_denied_even_when_granted() {
        let entries = vec![entry("*.cloudflare-dns.com"), entry("dns.google")];
        let p = EgressPolicy::compile([("user", entries.as_slice())]).unwrap();
        assert_eq!(p.admit_host(&h("mozilla.cloudflare-dns.com"), 443).unwrap_err().0, Reason::DohEndpoint);
        assert_eq!(p.admit_host(&h("dns.google"), 443).unwrap_err().0, Reason::DohEndpoint);
    }

    #[test]
    fn compile_errors() {
        for bad in ["*", "*.com", "exa\u{0}mple.com", "example.com.", "0x7f.1"] {
            let e = vec![entry(bad)];
            assert!(EgressPolicy::compile([("user", e.as_slice())]).is_err(), "{bad:?}");
        }
        let e = vec![EgressEntry { host: "a.com".into(), addrs: vec!["0177.0.0.1".into()], ..Default::default() }];
        assert!(EgressPolicy::compile([("user", e.as_slice())]).is_err(), "pinned addrs are canonicalised too");
        let e = vec![EgressEntry { host: "a.com".into(), ports: Some(vec![0]), ..Default::default() }];
        assert!(EgressPolicy::compile([("user", e.as_slice())]).is_err());
        let e = vec![EgressEntry {
            host: "a.com".into(),
            allow_addr_classes: vec!["everything".into()],
            ..Default::default()
        }];
        assert!(EgressPolicy::compile([("user", e.as_slice())]).is_err());
        let e = vec![
            EgressEntry { host: "a.com".into(), id: Some("x".into()), ..Default::default() },
            EgressEntry { host: "b.com".into(), id: Some("x".into()), ..Default::default() },
        ];
        assert!(EgressPolicy::compile([("user", e.as_slice())]).is_err());
    }
}
