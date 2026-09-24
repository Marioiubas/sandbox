//! `broker why <request-id>`: explain a decision from the audit log only
//! (never from an agent transcript, I9).

use super::{EXIT_BROKER, ctl};
use audit::{DecisionResult, RequestId, SqliteRecorder, StoredEvent};

pub fn render(events: &[StoredEvent]) -> String {
    let mut out = String::new();
    for s in events {
        let e = &s.event;
        out.push_str(&format!(
            "{}  {}  session {}\n",
            e.request_id.as_ref().map(|r| r.as_str()).unwrap_or("-"),
            e.kind.as_str(),
            e.session.as_ref().map(|r| r.as_str()).unwrap_or("-")
        ));
        if let Some(d) = &e.decision {
            let res = match d.result {
                DecisionResult::Allow => "allow",
                DecisionResult::Deny => "deny",
            };
            out.push_str(&format!("  decision  {res} ({:?} mode)\n", d.mode).to_lowercase());
            if !d.policy_ids.is_empty() {
                out.push_str(&format!("  policy    {}\n", d.policy_ids.join(", ")));
            }
        }
        if let Some(r) = e.reason {
            out.push_str(&format!("  reason    {}  [stage {}, boundary {}]\n", r.as_str(), r.stage(), r.boundary()));
            out.push_str(&format!("  why       {}\n", r.explain()));
        }
        if let Some(d) = &e.dest {
            out.push_str(&format!(
                "  dest      {} {}:{}{}\n",
                d.ingress.as_deref().unwrap_or("-"),
                d.host.as_deref().unwrap_or("-"),
                d.port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                if d.addrs.is_empty() { String::new() } else { format!(" -> {}", d.addrs.join(", ")) }
            ));
        }
        let mut detail = e.detail.clone();
        // The adapter's verbs (one per action: `git.push <repo> <ref> force=..`).
        if let Some(v) = detail.remove("verb").and_then(|v| v.as_str().map(str::to_string)) {
            for part in v.split("; ") {
                out.push_str(&format!("  verb      {part}\n"));
            }
        }
        if let Some(c) = detail.get("credential_id").and_then(|v| v.as_str()) {
            let origin = detail.get("credential_origin").and_then(|v| v.as_str()).unwrap_or("-");
            out.push_str(&format!("  credential {c} ({origin}; the value is never logged)\n"));
        }
        if let Some(sh) = detail.remove("shadow") {
            let allow = sh.get("allow").and_then(|v| v.as_bool()).unwrap_or(false);
            let why = sh.get("reason").and_then(|v| v.as_str()).map(|r| format!(" ({r})")).unwrap_or_default();
            let scope = if sh.get("name_only").is_some() { " on the name alone" } else { "" };
            out.push_str(&format!(
                "  shadow    the candidate policy would {}{why}{scope}; it decided nothing\n",
                if allow { "allow" } else { "deny" }
            ));
        }
        if !detail.is_empty() {
            out.push_str(&format!("  detail    {}\n", serde_json::Value::Object(detail)));
        }
        out.push_str(&format!("  at        {}  (audit seq {}, chain {}…)\n", e.ts, s.seq, &s.hash.to_hex()[..16]));
    }
    out
}

pub fn why(id: &str) -> i32 {
    let rid = match RequestId::try_from(id.to_string()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("broker: {e}");
            return 2;
        }
    };
    let dirs = match ctl::dirs() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("broker: {e:#}");
            return EXIT_BROKER;
        }
    };
    let rec = match SqliteRecorder::open_read_only(&dirs.audit_db()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("broker: cannot open the audit log {}: {e:#}", dirs.audit_db().display());
            return EXIT_BROKER;
        }
    };
    match rec.by_request(&rid) {
        Ok(evs) if evs.is_empty() => {
            eprintln!("broker: no decision recorded with id {id}");
            1
        }
        Ok(evs) => {
            print!("{}", render(&evs));
            0
        }
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}
