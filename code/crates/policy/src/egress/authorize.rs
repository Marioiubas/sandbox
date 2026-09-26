//! Authorizing terminated requests: one Cedar request per adapter action
//! (all must allow), then `credential.use` for the credential of the grant
//! that allowed every action.

use super::*;

/// One Cedar request derived from an adapter action: action name,
/// resource UID, entities, and the context for a given mode.
type ActionRequest<'a> = (String, Value, Vec<Value>, Box<dyn Fn(Mode) -> Value + 'a>);

impl EgressPolicy {
    /// `adapted`: the request's actions include a GitHub or S3 verb, which
    /// decides whether it writes (the Rule of Two keys on the verb).
    /// `approved`: a human approved exactly this action (ADR-037).
    fn action_request(&self, adm: &Admission, a: &Action, adapted: bool, approved: bool) -> ActionRequest<'_> {
        let session_ctx = move |m: Mode| {
            let mut s = self.session_ctx(m);
            s["approved"] = json!(approved);
            s
        };
        let mut ents = self.host_entities(&adm.host);
        let port = adm.port;
        let dest_class = adm.addr_classes.first().cloned().unwrap_or_else(|| "public".into());
        match a.clone() {
            Action::Http { method, path } => {
                let host = adm.host.as_str().to_string();
                let ctx = move |m: Mode| {
                    json!({
                        "session": session_ctx(m), "port": port, "method": method,
                        "path": ent::path_record(&path), "path_str": path, "sni": host, "host_header": host,
                        "body_bytes": 0, "dest_class": dest_class, "adapted": adapted,
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
                let ctx =
                    move |m: Mode| json!({ "session": session_ctx(m), "port": port, "ref": refname, "force": force });
                (name.to_string(), ent::repo_uid(&repo), ents, Box::new(ctx))
            }
            Action::GitHub { verb, repo, visibility, method, path, .. } => {
                let ctx = move |m: Mode| json!({ "session": session_ctx(m), "port": port, "method": method, "path_str": path });
                // A repository verb without a repository cannot be granted.
                let res = match (&repo, crate::github::is_repo_verb(&verb)) {
                    (Some(r), true) => {
                        ents.push(ent::repo_entity_with(r, &adm.host, visibility));
                        ent::repo_uid(r)
                    }
                    // No entity for it: every permit fails and the request denies.
                    (None, true) => json!({ "type": "Broker::Repo", "id": "" }),
                    _ => ent::host_uid(&adm.host),
                };
                (verb, res, ents, Box::new(ctx))
            }
            Action::S3 { op, bucket, key } => {
                let ctx =
                    move |m: Mode| json!({ "session": session_ctx(m), "port": port, "bucket": bucket, "key": key });
                (op, ent::host_uid(&adm.host), ents, Box::new(ctx))
            }
        }
    }

    /// Authorize the actions of one terminated request: one Cedar request
    /// per action, all must allow; then `credential.use` for the credential
    /// of the grant that allowed every action (if any).
    pub fn authorize_l7(&self, adm: &Admission, actions: &[Action]) -> L7Decision {
        self.authorize_l7_approving(adm, actions, &[])
    }

    /// If `dec` denied these actions only for want of a human approval, the
    /// approval keys that would allow the request (checked by deciding again
    /// as if they were approved); `None` when approval would not help.
    pub fn approvable(&self, adm: &Admission, actions: &[Action], dec: &L7Decision) -> Option<Vec<String>> {
        use crate::approvals::{approval_key, is_approval_reason};
        if !dec.result.is_err_and(is_approval_reason) {
            return None;
        }
        let keys: Vec<String> = dec
            .actions
            .iter()
            .zip(actions)
            .filter(|((_, r), _)| r.is_err_and(is_approval_reason))
            .map(|(_, a)| approval_key(&adm.host, adm.port, a))
            .collect();
        if keys.is_empty() {
            return None;
        }
        self.authorize_l7_approving(adm, actions, &keys).result.is_ok().then_some(keys)
    }

    /// The approval keys of `actions` that this session holds.
    pub fn approvals_used(&self, adm: &Admission, actions: &[Action]) -> Vec<String> {
        actions
            .iter()
            .map(|a| crate::approvals::approval_key(&adm.host, adm.port, a))
            .filter(|k| self.approvals().is_approved(k))
            .collect()
    }

    /// As [`authorize_l7`](Self::authorize_l7), also treating `extra` keys
    /// as approved (the "would approval help" check).
    fn authorize_l7_approving(&self, adm: &Admission, actions: &[Action], extra: &[String]) -> L7Decision {
        let explained = l7::explain(self.admitted(adm).map(|g| (g.id.as_str(), g.l7.as_deref())), actions);
        if actions.is_empty() {
            return L7Decision { would_deny: None, ..explained };
        }
        let mut per = Vec::new();
        let mut overall: Result<(), Reason> = Ok(());
        let mut would: Option<Reason> = None;
        let mut full: Option<BTreeSet<usize>> = None;
        let mut determining = Vec::new();
        let adapted = actions.iter().any(|a| matches!(a, Action::GitHub { .. } | Action::S3 { .. }));
        for (k, a) in actions.iter().enumerate() {
            let key = crate::approvals::approval_key(&adm.host, adm.port, a);
            let approved = extra.contains(&key) || self.approvals().is_approved(&key);
            let (name, res, ents, ctx) = self.action_request(adm, a, adapted, approved);
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
}
