//! Egress decisions through the Cedar engine (M2).
//!
//! Admission is two Cedar requests: `net.resolve` on the canonical name and
//! port before any DNS query, then `net.connect` with the classes of every
//! address the broker resolved (I6: the name and the resolved address).
//! Terminated requests become one Cedar request per adapter action; all
//! must allow. The M0/M1 rule tables survive only as the explainer that
//! names a specific deny reason (and as the differential oracle in tests).

use crate::cedar::{self, Compiled, Engine, Mode, SessionInfo, Verdict, entities as ent};
use crate::config::EgressEntry;
use crate::l7::{self, Action, AllowedBinding, CompileEnv, CredentialDef, L7Decision, L7Rules, Protocol};
use audit::Reason;
use netguard::{AddrClass, CanonicalHost, HostPattern, classify_addr};
use serde_json::{Value, json};
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

/// One Cedar request derived from an adapter action: action name,
/// resource UID, entities, and the context for a given mode.
type ActionRequest<'a> = (String, Value, Vec<Value>, Box<dyn Fn(Mode) -> Value + 'a>);

#[derive(Clone, Debug)]
pub struct EgressPolicy {
    grants: Vec<Grant>,
    repo_grants: Vec<Grant>,
    engine: Engine,
    session: SessionInfo,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        EgressPolicy::compile([]).expect("the empty policy compiles")
    }
}

/// The result of a successful host admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    /// Grant IDs that admitted the host (the audit row's `policy_ids`).
    pub policy_ids: Vec<String>,
    pub host: CanonicalHost,
    pub port: u16,
    allow_classes: BTreeSet<AddrClass>,
    /// For IP-literal hosts named by a grant: that exact address.
    exact_ip: Option<IpAddr>,
    /// Addresses pinned by the matching grants; when non-empty the broker
    /// uses them instead of DNS.
    pub pinned: Vec<IpAddr>,
    /// Indices of the base grants that admitted the host on this port.
    grants: Vec<usize>,
    /// Classes of the admitted addresses (set by `admit_addrs`).
    pub addr_classes: Vec<String>,
    /// Record mode: the enforce-mode decision would have denied, and why.
    pub would_deny: Option<Reason>,
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
    #[error("{id}: {key} is not allowed in repository policy (it would confer authority; I4)")]
    RepoKey { id: String, key: &'static str },
    #[error("cedar: {0}")]
    Cedar(String),
}

fn build_grants<'a>(
    layers: impl IntoIterator<Item = (&'a str, &'a [EgressEntry])>,
    env: &CompileEnv,
) -> Result<Vec<Grant>, CompileError> {
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
    Ok(grants)
}

fn compile_all(grants: &[Grant]) -> Result<Vec<Compiled>, CompileError> {
    let mut out = Vec::new();
    for (i, g) in grants.iter().enumerate() {
        out.extend(cedar::compile::grant_policies(i, g).map_err(CompileError::Cedar)?);
    }
    Ok(out)
}

fn reason_from(s: &str) -> Reason {
    serde_json::from_value(Value::String(s.to_string())).unwrap_or(Reason::PolicyDenied)
}

impl EgressPolicy {
    /// Compile entries from one or more trusted layers (built-in profile,
    /// user, org). `scope` prefixes generated IDs, e.g. `user:egress[2]`.
    pub fn compile<'a>(layers: impl IntoIterator<Item = (&'a str, &'a [EgressEntry])>) -> Result<Self, CompileError> {
        Self::compile_with(layers, &CompileEnv::default())
    }

    /// As [`compile`](Self::compile), with `${repo_remote}`, the issuer names
    /// from the user/org layers and the session's task available.
    pub fn compile_with<'a>(
        layers: impl IntoIterator<Item = (&'a str, &'a [EgressEntry])>,
        env: &CompileEnv,
    ) -> Result<Self, CompileError> {
        let grants = build_grants(layers, env)?;
        let engine = Engine::new(&compile_all(&grants)?).map_err(CompileError::Cedar)?;
        Ok(EgressPolicy { grants, repo_grants: vec![], engine, session: env.session.clone() })
    }

    /// Conjoin an approved repository layer: it can only narrow (I4). Keys
    /// that confer authority are compile errors.
    pub fn with_repo_layer(mut self, entries: &[EgressEntry], env: &CompileEnv) -> Result<Self, CompileError> {
        for (i, e) in entries.iter().enumerate() {
            let id = e.id.clone().unwrap_or_else(|| format!("egress[{i}]"));
            let bad = if e.credential.is_some() {
                Some("credential")
            } else if e.passthrough {
                Some("passthrough")
            } else if !e.addrs.is_empty() {
                Some("addrs")
            } else {
                None
            };
            if let Some(key) = bad {
                return Err(CompileError::RepoKey { id: format!("repo:{id}"), key });
            }
        }
        let grants = build_grants([("repo", entries)], env)?;
        self.engine = self.engine.with_repo(&compile_all(&grants)?).map_err(CompileError::Cedar)?;
        self.repo_grants = grants;
        Ok(self)
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn session(&self) -> &SessionInfo {
        &self.session
    }

    pub fn mode(&self) -> Mode {
        self.session.mode
    }

    fn host_entities(&self, host: &CanonicalHost) -> Vec<Value> {
        let mut v = ent::principal_entities(&self.session);
        v.push(ent::host_entity(host, &cedar::categories::categories(host)));
        v
    }

    /// Evaluate in the session's mode; in record mode also the enforce-mode
    /// verdict (the would-be decision the learner and `broker why` report).
    fn eval(
        &self,
        action: &str,
        resource: &Value,
        entities: Vec<Value>,
        ctx: impl Fn(Mode) -> Value,
    ) -> (Verdict, Option<Verdict>) {
        let mode = self.session.mode;
        let v = self.engine.authorize(action, resource, entities.clone(), ctx(mode));
        let shadow =
            (mode == Mode::Record).then(|| self.engine.authorize(action, resource, entities, ctx(Mode::Enforce)));
        (v, shadow)
    }

    /// A Cedar deny's reason: a forbid's `@reason`, the repo layer, an
    /// evaluation error, or else the explainer's most specific reason.
    fn deny_reason(&self, v: &Verdict, explain: impl FnOnce() -> Reason) -> Reason {
        if !v.errors.is_empty() {
            return Reason::PolicyError;
        }
        if let Some(r) = v.determining.iter().find_map(|id| self.engine.reason_of(id)) {
            return reason_from(r);
        }
        if v.repo_denied {
            return Reason::RepoPolicyDenied;
        }
        explain()
    }

    fn session_ctx(&self, mode: Mode) -> Value {
        ent::session_record(&self.session, mode, ent::now_epoch())
    }

    fn explain_host(&self, host: &CanonicalHost, port: u16) -> (Reason, Vec<String>) {
        let matching: Vec<&Grant> = self.grants.iter().filter(|g| g.pattern.matches(host)).collect();
        if matching.is_empty() {
            let reason = if host.is_ip_literal() { Reason::IpLiteral } else { Reason::HostNotAllowed };
            return (reason, vec![]);
        }
        let ids = matching.iter().map(|g| g.id.clone()).collect();
        if !matching.iter().any(|g| g.ports.contains(&port)) {
            return (Reason::PortNotAllowed, ids);
        }
        (Reason::PolicyDenied, ids)
    }

    /// Name (or literal) and port admission (`net.resolve`). Never touches
    /// the network.
    pub fn admit_host(&self, host: &CanonicalHost, port: u16) -> Result<Admission, (Reason, Vec<String>)> {
        let ctx = |m: Mode| json!({ "session": self.session_ctx(m), "port": port, "addr_classes": [] });
        let (v, shadow) = self.eval("net.resolve", &ent::host_uid(host), self.host_entities(host), ctx);
        if !v.allowed {
            let reason = self.deny_reason(&v, || self.explain_host(host, port).0);
            let ids = if v.determining.is_empty() { self.explain_host(host, port).1 } else { v.determining.clone() };
            return Err((reason, ids));
        }
        let grants: Vec<usize> = self.engine.grants_in(&v).into_iter().collect();
        let on: Vec<&Grant> = grants.iter().filter_map(|&i| self.grants.get(i)).collect();
        let would_deny =
            shadow.filter(|s| !s.allowed).map(|s| self.deny_reason(&s, || self.explain_host(host, port).0));
        let mut policy_ids: Vec<String> = on.iter().map(|g| g.id.clone()).collect();
        if policy_ids.is_empty() {
            policy_ids = v.determining.clone();
        }
        Ok(Admission {
            policy_ids,
            host: host.clone(),
            port,
            allow_classes: on.iter().flat_map(|g| g.allow_classes.iter().copied()).collect(),
            exact_ip: host.ip(),
            pinned: on.iter().flat_map(|g| g.pinned.iter().copied()).collect(),
            grants,
            addr_classes: vec![],
            would_deny,
        })
    }

    fn admitted<'a>(&'a self, adm: &'a Admission) -> impl Iterator<Item = &'a Grant> + 'a {
        adm.grants.iter().filter_map(|&i| self.grants.get(i))
    }

    fn repo_matching<'a>(&'a self, adm: &'a Admission) -> impl Iterator<Item = &'a Grant> + 'a {
        self.repo_grants.iter().filter(|g| g.pattern.matches(&adm.host) && g.ports.contains(&adm.port))
    }

    /// L4 unless some admitting grant (base or repo layer) has L7 rules; a
    /// passthrough base grant forces L4 (and therefore no credential).
    pub fn path_choice(&self, adm: &Admission) -> PathChoice {
        if self.admitted(adm).any(|g| g.passthrough) {
            return PathChoice::L4;
        }
        if self.admitted(adm).chain(self.repo_matching(adm)).any(|g| g.l7.is_some()) {
            PathChoice::L7
        } else {
            PathChoice::L4
        }
    }

    /// Protocols the admitting grants declare (selects the adapter).
    pub fn protocols(&self, adm: &Admission) -> BTreeSet<Protocol> {
        self.admitted(adm).chain(self.repo_matching(adm)).filter_map(|g| g.l7.as_ref().map(|r| r.protocol)).collect()
    }

    /// Address admission over the broker-resolved set (`net.connect`): the
    /// classes of **all** addresses must be allowed together.
    pub fn admit_addrs(&self, adm: &mut Admission, addrs: &[IpAddr]) -> Result<(), (Reason, IpAddr)> {
        let classes: BTreeSet<&'static str> = addrs.iter().map(|a| classify_addr(*a).as_str()).collect();
        let ctx = |m: Mode| json!({ "session": self.session_ctx(m), "port": adm.port, "addr_classes": classes });
        let host = adm.host.clone();
        let (v, shadow) = self.eval("net.connect", &ent::host_uid(&host), self.host_entities(&host), ctx);
        let explain = |adm: &Admission| -> (Reason, IpAddr) {
            for &a in addrs {
                let class = classify_addr(a);
                let ok = class == AddrClass::Public || adm.exact_ip == Some(a) || adm.allow_classes.contains(&class);
                if !ok {
                    return (class.deny_reason().unwrap_or(Reason::ReservedAddr), a);
                }
            }
            (Reason::PolicyDenied, addrs.first().copied().unwrap_or(IpAddr::from([0, 0, 0, 0])))
        };
        if !v.allowed {
            let (r, a) = explain(adm);
            return Err((self.deny_reason(&v, || r), a));
        }
        if adm.would_deny.is_none()
            && let Some(s) = shadow.filter(|s| !s.allowed)
        {
            let (r, _) = explain(adm);
            adm.would_deny = Some(self.deny_reason(&s, || r));
        }
        adm.addr_classes = classes.iter().map(|c| c.to_string()).collect();
        Ok(())
    }

    fn action_request(&self, adm: &Admission, a: &Action) -> ActionRequest<'_> {
        let mut ents = self.host_entities(&adm.host);
        let port = adm.port;
        let dest_class = adm.addr_classes.first().cloned().unwrap_or_else(|| "public".into());
        match a.clone() {
            Action::Http { method, path } => {
                let host = adm.host.as_str().to_string();
                let ctx = move |m: Mode| {
                    json!({
                        "session": self.session_ctx(m), "port": port, "method": method,
                        "path": ent::path_record(&path), "path_str": path, "sni": host, "host_header": host,
                        "body_bytes": 0, "dest_class": dest_class,
                    })
                };
                let name = cedar::compile::http_action(a.method().unwrap_or(""));
                (name, ent::host_uid(&adm.host), ents, Box::new(ctx))
            }
            Action::GitFetch { repo } | Action::GitPushAdvertise { repo } | Action::GitPush { repo, .. } => {
                let (name, refname, force) = match a {
                    Action::GitFetch { .. } => ("git.fetch", String::new(), false),
                    Action::GitPushAdvertise { .. } => ("git.advertise", String::new(), false),
                    Action::GitPush { refname, force, .. } => ("git.push", refname.clone(), *force),
                    _ => unreachable!(),
                };
                ents.push(ent::repo_entity(&repo, &adm.host));
                let ctx = move |m: Mode| json!({ "session": self.session_ctx(m), "port": port, "ref": refname, "force": force });
                (name.to_string(), ent::repo_uid(&repo), ents, Box::new(ctx))
            }
        }
    }

    /// Authorize the actions of one terminated request: one Cedar request
    /// per action, all must allow; then `credential.use` for the credential
    /// of the grant that allowed every action (if any).
    pub fn authorize_l7(&self, adm: &Admission, actions: &[Action]) -> L7Decision {
        let explained = l7::explain(self.admitted(adm).map(|g| (g.id.as_str(), g.l7.as_deref())), actions);
        if actions.is_empty() {
            return L7Decision { would_deny: None, ..explained };
        }
        let mut per = Vec::new();
        let mut overall: Result<(), Reason> = Ok(());
        let mut would: Option<Reason> = None;
        let mut full: Option<BTreeSet<usize>> = None;
        let mut determining = Vec::new();
        for (k, a) in actions.iter().enumerate() {
            let (name, res, ents, ctx) = self.action_request(adm, a);
            let (v, shadow) = self.eval(&name, &res, ents, ctx);
            let explain = || explained.actions.get(k).and_then(|(_, r)| r.err()).unwrap_or(Reason::PolicyDenied);
            let r = if v.allowed { Ok(()) } else { Err(self.deny_reason(&v, explain)) };
            if let (Err(e), Ok(())) = (r, overall) {
                overall = Err(e);
            }
            if would.is_none()
                && let Some(s) = shadow.filter(|s| !s.allowed)
            {
                would = Some(self.deny_reason(&s, explain));
            }
            let gs = self.engine.grants_in(&v);
            full = Some(match full {
                None => gs,
                Some(prev) => prev.intersection(&gs).copied().collect(),
            });
            determining.extend(v.determining.iter().cloned());
            per.push((a.verb(), r));
        }
        determining.sort();
        determining.dedup();
        if let Err(reason) = overall {
            let ids = if determining.is_empty() { explained.policy_ids } else { determining };
            return L7Decision { result: Err(reason), policy_ids: ids, binding: None, actions: per, would_deny: would };
        }
        // The credential of the grant(s) that allowed every action.
        let mut creds: Vec<(usize, Arc<CredentialDef>)> = full
            .unwrap_or_default()
            .into_iter()
            .filter_map(|i| {
                self.grants.get(i).and_then(|g| g.l7.as_ref()).and_then(|r| r.credential.clone()).map(|c| (i, c))
            })
            .collect();
        creds.dedup_by(|a, b| a.1.id == b.1.id);
        let binding = match creds.as_slice() {
            [] => None,
            [(i, c)] => match self.credential_use(adm, c, &actions[0]) {
                Ok(()) => Some(AllowedBinding::new(c.clone(), &self.grants[*i].id)),
                Err(r) => {
                    return L7Decision {
                        result: Err(r),
                        policy_ids: determining,
                        binding: None,
                        actions: per,
                        would_deny: would,
                    };
                }
            },
            _ => {
                return L7Decision {
                    result: Err(Reason::AmbiguousCredential),
                    policy_ids: determining,
                    binding: None,
                    actions: per,
                    would_deny: would,
                };
            }
        };
        L7Decision { result: Ok(()), policy_ids: determining, binding, actions: per, would_deny: would }
    }

    /// The `credential.use` request (base set only; the ceiling forbid
    /// confines each credential to its declared hosts).
    fn credential_use(&self, adm: &Admission, c: &CredentialDef, first: &Action) -> Result<(), Reason> {
        let (hosts, domains): (Vec<String>, Vec<String>) = c.hosts.iter().fold((vec![], vec![]), |mut acc, p| {
            match p {
                HostPattern::Exact(h) => acc.0.push(h.as_str().to_string()),
                HostPattern::Subdomains(b) => acc.1.push(b.as_str().to_string()),
            }
            acc
        });
        let mut ents = ent::principal_entities(&self.session);
        ents.push(ent::credential_entity(&c.id, c.kind.as_str(), &hosts, &domains));
        let (method, path) = match first {
            Action::Http { method, path } => (method.clone(), path.clone()),
            _ => (String::new(), String::new()),
        };
        let ctx = json!({
            "session": self.session_ctx(Mode::Enforce),
            "dest_host": adm.host.as_str(), "dest_domains": ent::domain_suffixes(&adm.host),
            "port": adm.port, "method": method, "path_str": path, "verb": first.verb(),
        });
        let v = self.engine.authorize("credential.use", &ent::credential_uid(&c.id), ents, ctx);
        if v.allowed { Ok(()) } else { Err(self.deny_reason(&v, || Reason::CredentialHostCeiling)) }
    }

    /// Every declared credential (for sentinels at session start).
    pub fn credentials(&self) -> Vec<Arc<CredentialDef>> {
        self.grants.iter().filter_map(|g| g.l7.as_ref().and_then(|r| r.credential.clone())).collect()
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
        assert!(p.admit_addrs(&mut a.clone(), &["140.82.112.5".parse().unwrap()]).is_ok());
        assert_eq!(
            p.admit_addrs(&mut a.clone(), &["169.254.169.254".parse().unwrap()]).unwrap_err().0,
            Reason::MetadataAddr
        );
        assert_eq!(
            p.admit_addrs(&mut a.clone(), &["140.82.112.5".parse().unwrap(), "10.0.0.1".parse().unwrap()])
                .unwrap_err()
                .0,
            Reason::PrivateAddr,
            "one bad address denies the whole name"
        );
        let l = p.admit_host(&h("local.test"), 443).unwrap();
        assert!(p.admit_addrs(&mut l.clone(), &["127.0.0.1".parse().unwrap()]).is_ok());
        assert_eq!(
            p.admit_addrs(&mut l.clone(), &["169.254.169.254".parse().unwrap()]).unwrap_err().0,
            Reason::MetadataAddr
        );
    }

    #[test]
    fn explicit_ip_literal_grant() {
        let entries = vec![entry("10.1.2.3")];
        let p = EgressPolicy::compile([("user", entries.as_slice())]).unwrap();
        let a = p.admit_host(&h("10.1.2.3"), 443).unwrap();
        assert!(p.admit_addrs(&mut a.clone(), &["10.1.2.3".parse().unwrap()]).is_ok());
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
