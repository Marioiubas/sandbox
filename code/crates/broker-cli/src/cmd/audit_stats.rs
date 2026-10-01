//! `broker audit stats`: per-session friction and enforcement counts from
//! the audit log (L4 Product Metrics: prompts and denies per session, from
//! the broker's records rather than the agent's account). A prompt is an
//! `approval.requested` row: the only thing the broker ever asks a human.

use super::{EXIT_BROKER, ctl};
use audit::{AuditEvent, EventKind, SqliteRecorder};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
struct Session {
    agent: String,
    enduser: String,
    start: String,
    allows: u64,
    denies: BTreeMap<String, u64>,
    prompts: u64,
    granted: u64,
    kernel_denied: u64,
    labels: Vec<String>,
}

fn tally(evs: &[AuditEvent], only: Option<&str>) -> BTreeMap<String, Session> {
    let mut out: BTreeMap<String, Session> = BTreeMap::new();
    for e in evs {
        let Some(id) = e.session.as_ref().map(|s| s.to_string()) else { continue };
        if only.is_some_and(|o| o != id) {
            continue;
        }
        let s = out.entry(id).or_default();
        match e.kind {
            EventKind::SessionStart => {
                s.agent = e.agent.clone().unwrap_or_default();
                s.enduser = e.enduser.clone().unwrap_or_default();
                s.start = e.ts.clone();
            }
            EventKind::RequestDecision if e.is_deny() => {
                let r = e.reason.map(|r| r.as_str()).unwrap_or("unknown");
                *s.denies.entry(r.to_string()).or_default() += 1;
            }
            EventKind::RequestDecision => s.allows += 1,
            EventKind::ApprovalRequested => s.prompts += 1,
            EventKind::ApprovalGranted => s.granted += 1,
            EventKind::KernelDenied => s.kernel_denied += 1,
            EventKind::SessionLabel => {
                if let Some(l) = e.detail.get("label").and_then(|v| v.as_str()) {
                    s.labels.push(l.to_string());
                }
            }
            _ => {}
        }
    }
    out
}

fn to_json(id: &str, s: &Session) -> Value {
    json!({
        "session": id, "agent": s.agent, "enduser": s.enduser, "start": s.start,
        "allows": s.allows, "denies": s.denies.values().sum::<u64>(), "denies_by_reason": s.denies,
        "prompts": s.prompts, "approvals_granted": s.granted, "kernel_denied": s.kernel_denied,
        "labels": s.labels,
    })
}

pub fn stats(session: Option<String>, as_json: bool) -> i32 {
    let run = || -> anyhow::Result<i32> {
        let dirs = ctl::dirs()?;
        let evs: Vec<AuditEvent> =
            SqliteRecorder::open_read_only(&dirs.audit_db())?.tail(u32::MAX)?.into_iter().map(|s| s.event).collect();
        let sessions = tally(&evs, session.as_deref());
        if as_json {
            let v: Vec<Value> = sessions.iter().map(|(id, s)| to_json(id, s)).collect();
            println!("{}", serde_json::to_string_pretty(&v)?);
            return Ok(0);
        }
        println!(
            "{:<28} {:<16} {:>7} {:>6} {:>8} {:>7} {:>7}  top deny reason",
            "session", "agent", "allows", "denies", "prompts", "granted", "kernel"
        );
        for (id, s) in &sessions {
            let top = s.denies.iter().max_by_key(|(_, n)| **n).map(|(r, n)| format!("{r} ({n})")).unwrap_or_default();
            let agent = s.agent.rsplit('/').next().unwrap_or("");
            println!(
                "{id:<28} {agent:<16} {:>7} {:>6} {:>8} {:>7} {:>7}  {top}",
                s.allows,
                s.denies.values().sum::<u64>(),
                s.prompts,
                s.granted,
                s.kernel_denied
            );
        }
        Ok(0)
    };
    run().unwrap_or_else(|e| {
        eprintln!("broker: {e:#}");
        EXIT_BROKER
    })
}
