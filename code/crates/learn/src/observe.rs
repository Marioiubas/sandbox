//! Record-mode sessions and their observations, read only from committed,
//! hash-chained audit rows. A session that carried a foreign credential,
//! sent a sentinel to the wrong host or had a secret reflected is excluded
//! entirely (P2) and reported.

use audit::{AuditEvent, DecisionResult, EventKind, Reason};
use policy::Action;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub profile: String,
    pub agent: String,
    pub cwd: String,
    pub record: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum What {
    /// A tunnel to a host that was spliced (not inspected).
    Connect,
    /// A terminated request's actions.
    L7(Vec<Action>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub session: String,
    pub host: String,
    pub port: u16,
    pub addrs: Vec<String>,
    pub what: What,
    pub allowed: bool,
    /// Denied: why. Allowed in record mode: what enforce would have said.
    pub reason: Option<Reason>,
    pub would_deny: Option<Reason>,
}

#[derive(Clone, Debug, Default)]
pub struct Corpus {
    pub sessions: BTreeMap<String, Session>,
    pub observations: Vec<Observation>,
    /// Excluded sessions and why (P2).
    pub excluded: BTreeMap<String, String>,
}

const POISON: &[Reason] = &[Reason::ForeignCredential, Reason::SentinelWrongHost, Reason::SecretReflected];

fn reason_of(s: &str) -> Option<Reason> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

/// Build the corpus from audit events (oldest first).
pub fn corpus(events: &[AuditEvent]) -> Corpus {
    let mut c = Corpus::default();
    for e in events.iter().filter(|e| e.kind == EventKind::SessionStart) {
        let Some(id) = e.session.as_ref().map(|s| s.to_string()) else { continue };
        let d = |k: &str| e.detail.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        c.sessions.insert(
            id.clone(),
            Session {
                id,
                profile: d("profile"),
                agent: e.agent.clone().unwrap_or_default(),
                cwd: d("cwd"),
                record: d("mode") == "record",
            },
        );
    }
    for e in events {
        let Some(sid) = e.session.as_ref().map(|s| s.to_string()) else { continue };
        if !c.sessions.get(&sid).is_some_and(|s| s.record) {
            continue;
        }
        if let Some(r) = e.reason
            && POISON.contains(&r)
        {
            c.excluded.entry(sid.clone()).or_insert_with(|| format!("{} observed", r.as_str()));
        }
        if e.kind != EventKind::RequestDecision {
            continue;
        }
        let (Some(dest), Some(dec)) = (&e.dest, &e.decision) else { continue };
        let (Some(host), Some(port)) = (dest.host.clone(), dest.port) else { continue };
        let what = if e.detail.get("layer").and_then(|v| v.as_str()) == Some("l7") {
            let acts: Vec<Action> = e
                .detail
                .get("actions")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(Action::from_json).collect())
                .unwrap_or_default();
            if acts.is_empty() {
                continue;
            }
            What::L7(acts)
        } else {
            What::Connect
        };
        c.observations.push(Observation {
            session: sid,
            host,
            port,
            addrs: dest.addrs.clone(),
            what,
            allowed: dec.result == DecisionResult::Allow,
            reason: e.reason,
            would_deny: e.detail.get("would_deny").and_then(|v| v.as_str()).and_then(reason_of),
        });
    }
    let excluded = c.excluded.clone();
    c.observations.retain(|o| !excluded.contains_key(&o.session));
    c
}
