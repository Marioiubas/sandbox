//! Pending step-up approvals (ADR-037; Fatigue-Resistant Approval
//! Interfaces). A request denied only for want of a human approval leaves a
//! pending approval naming the exact actions (the authority diff); the user,
//! outside the sandbox, lists it with `broker approvals` and grants it with
//! `broker approve`. The control socket is not reachable from any sandbox,
//! so an agent cannot approve its own requests. Pending approvals expire
//! after 30 minutes and die with their session, as do granted ones.

use audit::Reason;
use policy::EgressPolicy;
use policy::approvals::Scope;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// How long a pending approval waits for the user.
pub const TTL_SECS: i64 = 30 * 60;
/// Most pending approvals per session (later ones deny without one).
pub const MAX_PENDING_PER_SESSION: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub id: String,
    pub session: String,
    /// The denied request that asked for it.
    pub request_id: String,
    pub reason: Reason,
    /// The approval keys: exactly the actions that would be allowed.
    pub keys: Vec<String>,
    pub created: i64,
}

#[derive(Default)]
pub struct Registry {
    sessions: Mutex<HashMap<String, Arc<EgressPolicy>>>,
    pending: Mutex<HashMap<String, Pending>>,
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn new_id() -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let mut b = [0u8; 10];
    getrandom::fill(&mut b).expect("the OS random source");
    let s: String = b.iter().map(|x| ALPHABET[(*x as usize) % ALPHABET.len()] as char).collect();
    format!("apr-{s}")
}

impl Registry {
    /// A running session whose policy approvals are granted into.
    pub fn register(&self, session: &str, policy: Arc<EgressPolicy>) {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner()).insert(session.to_string(), policy);
    }

    /// The session ended: its pending approvals go with it.
    pub fn unregister(&self, session: &str) {
        self.sessions.lock().unwrap_or_else(|p| p.into_inner()).remove(session);
        self.pending.lock().unwrap_or_else(|p| p.into_inner()).retain(|_, p| p.session != session);
    }

    /// Record a pending approval and return its ID. The same session and
    /// actions reuse one pending approval; `None` when the session already
    /// has too many (the request is then denied without one).
    pub fn request(&self, session: &str, request_id: &str, reason: Reason, keys: Vec<String>) -> Option<String> {
        let t = now();
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        pending.retain(|_, p| t - p.created < TTL_SECS);
        if let Some(p) = pending.values().find(|p| p.session == session && p.keys == keys) {
            return Some(p.id.clone());
        }
        if pending.values().filter(|p| p.session == session).count() >= MAX_PENDING_PER_SESSION {
            return None;
        }
        let id = new_id();
        let p = Pending {
            id: id.clone(),
            session: session.to_string(),
            request_id: request_id.to_string(),
            reason,
            keys,
            created: t,
        };
        pending.insert(id.clone(), p);
        Some(id)
    }

    /// Pending approvals, oldest first.
    pub fn list(&self) -> Vec<Pending> {
        let t = now();
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        pending.retain(|_, p| t - p.created < TTL_SECS);
        let mut v: Vec<Pending> = pending.values().cloned().collect();
        v.sort_by(|a, b| (a.created, &a.id).cmp(&(b.created, &b.id)));
        v
    }

    /// Drop a pending approval (its request could not be logged).
    pub fn cancel(&self, id: &str) {
        self.pending.lock().unwrap_or_else(|p| p.into_inner()).remove(id);
    }

    pub fn get(&self, id: &str) -> Option<Pending> {
        self.list().into_iter().find(|p| p.id == id)
    }

    /// Grant a pending approval into its session's policy.
    pub fn grant(&self, id: &str, scope: Scope) -> Result<Pending, String> {
        let p =
            self.get(id).ok_or_else(|| format!("no pending approval {id} (expired, granted, or its session ended)"))?;
        let policy = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&p.session)
            .cloned()
            .ok_or_else(|| format!("the session of {id} is no longer running"))?;
        for k in &p.keys {
            policy.approvals().grant(k.clone(), scope);
        }
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
        Ok(p)
    }
}

/// `approval.list`: each pending approval with its authority diff and the
/// provenance a decision needs: which requests raised the session's labels
/// (ground truth from the audit log, never the agent's own account).
pub fn list_json(d: &crate::session::Daemon) -> serde_json::Value {
    let t = now();
    let items: Vec<serde_json::Value> = d
        .approvals
        .list()
        .into_iter()
        .map(|p| {
            let q = audit::Query {
                after_seq: 0,
                session: Some(p.session.clone()),
                kind: Some(audit::EventKind::SessionLabel),
                decision: None,
                reason: None,
                host: None,
                limit: 100,
            };
            let provenance: Vec<serde_json::Value> = d
                .recorder
                .query_filtered(&q)
                .unwrap_or_default()
                .into_iter()
                .map(|e| {
                    serde_json::json!({
                        "label": e.event.detail.get("label"),
                        "cause": e.event.detail.get("cause"),
                        "request_id": e.event.request_id.map(|r| r.to_string()),
                    })
                })
                .collect();
            serde_json::json!({
                "id": p.id,
                "session": p.session,
                "request_id": p.request_id,
                "reason": p.reason.as_str(),
                "why": p.reason.explain(),
                "authority_diff": p.keys.iter().map(|k| format!("+ {k}")).collect::<Vec<_>>(),
                "provenance": provenance,
                "age_secs": t - p.created,
                "expires_in_secs": TTL_SECS - (t - p.created),
            })
        })
        .collect();
    serde_json::Value::Array(items)
}

/// `approval.grant {approval, scope}`: grant it into the session and log
/// `approval.granted` (who approved what, for how long).
pub fn grant_json(d: &crate::session::Daemon, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    let id = params.get("approval").and_then(|v| v.as_str()).ok_or("approval is required")?;
    let scope = match params.get("scope").and_then(|v| v.as_str()).unwrap_or("once") {
        "once" => Scope::Once,
        "session" => Scope::Session,
        other => return Err(format!("scope must be once or session, not {other:?}")),
    };
    let p = d
        .approvals
        .get(id)
        .ok_or_else(|| format!("no pending approval {id} (expired, granted, or its session ended)"))?;
    let session = audit::SessionId::try_from(p.session.clone()).map_err(|e| e.to_string())?;
    let approver = crate::dirs::passwd_user().map(|u| format!("local:{}", u.name)).unwrap_or_else(|_| "local".into());
    // On record first (I9): no row, no approval.
    let mut ev = audit::AuditEvent::new(audit::EventKind::ApprovalGranted)
        .session(&session)
        .detail("approval", p.id.as_str())
        .detail("scope", scope.as_str())
        .detail("approver", approver.as_str())
        .detail("authority_diff", p.keys.iter().map(|k| format!("+ {k}")).collect::<Vec<_>>());
    if let Ok(r) = audit::RequestId::try_from(p.request_id.clone()) {
        ev = ev.request(&r);
    }
    audit::Recorder::append(d.recorder.as_ref(), &ev).map_err(|e| format!("audit log unavailable: {e:#}"))?;
    let p = d.approvals.grant(id, scope)?;
    Ok(serde_json::json!({ "approval": p.id, "scope": scope.as_str(), "keys": p.keys }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_deduplicated_bounded_and_granted_into_the_session() {
        let r = Registry::default();
        let policy = Arc::new(EgressPolicy::default());
        r.register("s1", policy.clone());
        let k = vec!["github pr.create github.com/acme/web".to_string()];
        let a = r.request("s1", "req-1", Reason::RuleOfTwo, k.clone()).unwrap();
        assert!(a.starts_with("apr-") && a.len() == 14);
        assert_eq!(
            r.request("s1", "req-2", Reason::RuleOfTwo, k.clone()),
            Some(a.clone()),
            "same actions, same approval"
        );
        for n in 1..MAX_PENDING_PER_SESSION {
            assert!(r.request("s1", "req", Reason::RuleOfTwo, vec![format!("k{n}")]).is_some());
        }
        assert_eq!(r.request("s1", "req", Reason::RuleOfTwo, vec!["one too many".into()]), None);
        let p = r.grant(&a, Scope::Once).unwrap();
        assert_eq!(p.keys, k);
        assert!(policy.approvals().is_approved(&k[0]));
        assert!(r.grant(&a, Scope::Once).is_err(), "granted once, then gone");
        // A session that ended takes its pending approvals with it.
        let b = r.list()[0].id.clone();
        r.unregister("s1");
        assert!(r.list().is_empty());
        assert!(r.grant(&b, Scope::Session).is_err());
    }
}
