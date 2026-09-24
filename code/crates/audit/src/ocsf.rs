//! OCSF export (Audit Recorder and Event Schema). Decisions map to OCSF
//! 1.9.0 classes, verified against schema.ocsf.io on 2026-09-24:
//!
//! - an L4 admission → Network Activity (class 4001, category 4);
//! - a terminated HTTP request → HTTP Activity (4002, category 4);
//! - a git operation → API Activity (6003, category 6).
//!
//! `type_uid = class_uid * 100 + activity_id`. Allow/deny is the
//! security_control profile's `action_id`/`disposition_id`. Broker-specific
//! fields (session, request ID, chain position, credential ID) go in
//! `unmapped.broker`. Secrets never appear: the source event holds none (I1).

use crate::{AuditEvent, DecisionResult, EventKind, StoredEvent};
use serde_json::{Value, json};

pub const OCSF_VERSION: &str = "1.9.0";

/// Required attributes and enums of the three classes (OCSF 1.9.0, base
/// schema without optional profiles), captured from schema.ocsf.io.
struct ClassSpec {
    uid: u64,
    category: u64,
    required: &'static [&'static str],
    activities: &'static [u64],
}

const NETWORK_ACTIVITY: ClassSpec = ClassSpec {
    uid: 4001,
    category: 4,
    required: &["activity_id", "category_uid", "class_uid", "metadata", "severity_id", "time", "type_uid"],
    activities: &[0, 1, 2, 3, 4, 5, 6, 7, 99],
};
const HTTP_ACTIVITY: ClassSpec = ClassSpec {
    uid: 4002,
    category: 4,
    required: &["activity_id", "category_uid", "class_uid", "metadata", "severity_id", "time", "type_uid"],
    activities: &[
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 99,
    ],
};
const API_ACTIVITY: ClassSpec = ClassSpec {
    uid: 6003,
    category: 6,
    required: &[
        "activity_id",
        "actor",
        "api",
        "category_uid",
        "class_uid",
        "metadata",
        "severity_id",
        "src_endpoint",
        "time",
        "type_uid",
    ],
    activities: &[0, 1, 2, 3, 4, 99],
};
const SEVERITIES: &[u64] = &[0, 1, 2, 3, 4, 5, 6, 99];
const ACTIONS: &[u64] = &[0, 1, 2, 3, 4, 99];
const DISPOSITIONS: &[u64] =
    &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 99];

fn spec(class: u64) -> Option<&'static ClassSpec> {
    [&NETWORK_ACTIVITY, &HTTP_ACTIVITY, &API_ACTIVITY].into_iter().find(|s| s.uid == class)
}

/// HTTP Activity `activity_id` for a method.
pub fn http_activity(method: &str) -> u64 {
    match method {
        "CONNECT" => 1,
        "DELETE" => 2,
        "GET" => 3,
        "HEAD" => 4,
        "OPTIONS" => 5,
        "POST" => 6,
        "PUT" => 7,
        "TRACE" => 8,
        "PATCH" => 9,
        _ => 99,
    }
}

fn epoch_ms(ts: &str) -> i64 {
    time::OffsetDateTime::parse(ts, &time::format_description::well_known::Rfc3339)
        .map(|t| (t.unix_timestamp_nanos() / 1_000_000) as i64)
        .unwrap_or(0)
}

/// Map one stored decision to an OCSF event (other kinds are not exported).
pub fn to_ocsf(s: &StoredEvent) -> Option<Value> {
    let e: &AuditEvent = &s.event;
    if e.kind != EventKind::RequestDecision {
        return None;
    }
    let d = e.decision.as_ref()?;
    let allowed = d.result == DecisionResult::Allow;
    let dest = e.dest.clone().unwrap_or_default();
    let host = dest.host.clone().unwrap_or_default();
    let port = dest.port.unwrap_or(0);
    let actions = e.detail.get("actions").and_then(|a| a.as_array()).cloned().unwrap_or_default();
    let first = actions.first();
    let kind = first.and_then(|a| a.get("kind")).and_then(|k| k.as_str()).unwrap_or("");
    let l7 = e.detail.get("layer").and_then(|v| v.as_str()) == Some("l7");
    let (class, activity) = if l7 && kind.starts_with("git.") {
        (API_ACTIVITY.uid, if kind == "git.push" { 3 } else { 2 })
    } else if l7 {
        let m = first.and_then(|a| a.get("method")).and_then(|m| m.as_str()).unwrap_or("");
        (HTTP_ACTIVITY.uid, if m.is_empty() { 99 } else { http_activity(m) })
    } else {
        (NETWORK_ACTIVITY.uid, if allowed { 1 } else { 5 })
    };
    let sp = spec(class)?;
    let reason = e.reason.map(|r| r.as_str().to_string());
    let mut dst = json!({ "hostname": host, "port": port });
    if let Some(ip) = dest.addrs.first() {
        dst["ip"] = json!(ip);
    }
    let mut v = json!({
        "class_uid": class,
        "category_uid": sp.category,
        "activity_id": activity,
        "type_uid": class * 100 + activity,
        "time": epoch_ms(&e.ts),
        "severity_id": if allowed { 1 } else { 3 },
        "action_id": if allowed { 1 } else { 2 },
        "disposition_id": if allowed { 1 } else { 2 },
        "status_id": if allowed { 1 } else { 2 },
        "metadata": {
            "version": OCSF_VERSION,
            "product": { "name": "broker", "vendor_name": "broker (Apache-2.0)", "version": env!("CARGO_PKG_VERSION") },
            "profiles": ["security_control"],
            "log_name": "broker-audit",
            "uid": s.hash.to_hex(),
            "sequence": s.seq,
            "correlation_uid": e.session.as_ref().map(|x| x.to_string()),
        },
        "dst_endpoint": dst,
        "unmapped": { "broker": {
            "session": e.session.as_ref().map(|x| x.to_string()),
            "request_id": e.request_id.as_ref().map(|x| x.to_string()),
            "enduser": e.enduser,
            "agent": e.agent,
            "mode": format!("{:?}", d.mode).to_lowercase(),
            "policy_ids": d.policy_ids,
            "reason": reason,
            "verb": e.detail.get("verb"),
            "credential_id": e.detail.get("credential_id"),
            "would_deny": e.detail.get("would_deny"),
            "chain_seq": s.seq,
        }},
    });
    if let Some(r) = &reason {
        v["status_detail"] = json!(r);
        v["message"] = json!(e.reason.map(|x| x.explain()).unwrap_or_default());
    }
    if !d.policy_ids.is_empty() {
        v["policy"] = json!({ "name": d.policy_ids.join(","), "uid": d.policy_ids[0] });
    }
    if class == HTTP_ACTIVITY.uid {
        let path = first.and_then(|a| a.get("path")).and_then(|p| p.as_str()).unwrap_or("");
        let method = first.and_then(|a| a.get("method")).and_then(|m| m.as_str()).unwrap_or("");
        v["http_request"] = json!({
            "http_method": method,
            "url": { "hostname": host, "path": path, "port": port, "scheme": "https" },
        });
    }
    if class == API_ACTIVITY.uid {
        v["api"] = json!({
            "operation": kind,
            "service": { "name": "git" },
            "request": { "uid": e.request_id.as_ref().map(|x| x.to_string()) },
        });
        v["actor"] = json!({ "user": { "name": e.enduser.clone().unwrap_or_default() }, "app_name": e.agent });
        v["src_endpoint"] = json!({ "name": e.sandbox.clone().unwrap_or_default() });
    }
    Some(v)
}

fn uint(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(|x| x.as_u64())
}

/// Validate an exported event against the captured OCSF 1.9.0 subset.
pub fn validate(v: &Value) -> Result<(), String> {
    let class = uint(v, "class_uid").ok_or("class_uid missing")?;
    let sp = spec(class).ok_or_else(|| format!("unexpected class_uid {class}"))?;
    for k in sp.required {
        match v.get(*k) {
            None | Some(Value::Null) => return Err(format!("{class}: required attribute {k} missing")),
            _ => {}
        }
    }
    if uint(v, "category_uid") != Some(sp.category) {
        return Err(format!("{class}: category_uid must be {}", sp.category));
    }
    let activity = uint(v, "activity_id").ok_or("activity_id is not an integer")?;
    if !sp.activities.contains(&activity) {
        return Err(format!("{class}: activity_id {activity} not in the enum"));
    }
    if uint(v, "type_uid") != Some(class * 100 + activity) {
        return Err(format!("{class}: type_uid must be class_uid * 100 + activity_id"));
    }
    if !uint(v, "severity_id").is_some_and(|s| SEVERITIES.contains(&s)) {
        return Err("severity_id not in the enum".into());
    }
    if uint(v, "action_id").is_some_and(|a| !ACTIONS.contains(&a)) {
        return Err("action_id not in the enum".into());
    }
    if uint(v, "disposition_id").is_some_and(|a| !DISPOSITIONS.contains(&a)) {
        return Err("disposition_id not in the enum".into());
    }
    let md = v.get("metadata").ok_or("metadata missing")?;
    if md.get("product").is_none() || md.get("version").and_then(|x| x.as_str()) != Some(OCSF_VERSION) {
        return Err("metadata.product and metadata.version are required".into());
    }
    if v.get("time").and_then(|t| t.as_i64()).is_none_or(|t| t <= 0) {
        return Err("time must be epoch milliseconds".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dest, Reason, RequestId, SessionId, SqliteRecorder};

    fn stored(ev: AuditEvent) -> StoredEvent {
        let d = tempfile_dir();
        let r = SqliteRecorder::open(&d.join("a.db")).unwrap();
        crate::Recorder::append(&r, &ev).unwrap();
        r.tail(1).unwrap().remove(0)
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ocsf-test-{}", RequestId::new()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn dest() -> Dest {
        Dest {
            ingress: Some("connect".into()),
            host: Some("api.github.com".into()),
            registrable: None,
            port: Some(443),
            addrs: vec!["140.82.112.5".into()],
        }
    }

    #[test]
    fn classes_map_and_validate() {
        let s = SessionId::new();
        let l4 = AuditEvent::new(EventKind::RequestDecision)
            .session(&s)
            .request(&RequestId::new())
            .deny(Reason::HostNotAllowed, vec![])
            .dest(dest());
        let v = to_ocsf(&stored(l4)).unwrap();
        validate(&v).unwrap();
        assert_eq!(
            (v["class_uid"].as_u64(), v["activity_id"].as_u64(), v["type_uid"].as_u64()),
            (Some(4001), Some(5), Some(400105))
        );
        assert_eq!(v["action_id"], 2);
        assert_eq!(v["status_detail"], "host_not_allowed");

        let http = AuditEvent::new(EventKind::RequestDecision)
            .session(&s)
            .request(&RequestId::new())
            .allow(vec!["user:llm#http".into()])
            .dest(dest())
            .detail("layer", "l7")
            .detail("actions", json!([{ "kind": "http", "method": "POST", "path": "/v1/messages" }]))
            .detail("credential_id", "user:llm");
        let v = to_ocsf(&stored(http)).unwrap();
        validate(&v).unwrap();
        assert_eq!((v["class_uid"].as_u64(), v["activity_id"].as_u64()), (Some(4002), Some(6)));
        assert_eq!(v["http_request"]["url"]["path"], "/v1/messages");
        assert_eq!(v["unmapped"]["broker"]["credential_id"], "user:llm");

        let git = AuditEvent::new(EventKind::RequestDecision)
            .session(&s)
            .request(&RequestId::new())
            .deny(Reason::GitRefNotAllowed, vec![])
            .dest(dest())
            .detail("layer", "l7")
            .detail("actions", json!([{ "kind": "git.push", "repo": "github.com/acme/web", "ref": "refs/heads/main", "force": false }]));
        let v = to_ocsf(&stored(git)).unwrap();
        validate(&v).unwrap();
        assert_eq!((v["class_uid"].as_u64(), v["activity_id"].as_u64()), (Some(6003), Some(3)));
        assert_eq!(v["api"]["operation"], "git.push");

        // Non-decisions are not exported; malformed events do not validate.
        assert!(to_ocsf(&stored(AuditEvent::new(EventKind::SessionStart).session(&s))).is_none());
        let mut bad = v.clone();
        bad["type_uid"] = json!(1);
        assert!(validate(&bad).is_err());
        let mut bad = v;
        bad.as_object_mut().unwrap().remove("actor");
        assert!(validate(&bad).is_err());
    }
}
