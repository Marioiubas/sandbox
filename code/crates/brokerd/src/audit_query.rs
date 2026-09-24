//! `audit.query` on the control socket: filtered reads of the audit log.
//! Parameters are validated here, at the boundary: unknown keys, unknown
//! kinds or reasons, and hosts the canonicaliser rejects are errors, never
//! ignored filters (an ignored filter would silently widen the answer).

use audit::{DecisionResult, EventKind, Query, Reason, SessionId};
use serde_json::Value;

const KEYS: &[&str] = &["after_seq", "session", "kind", "decision", "reason", "host", "limit"];

/// Default number of rows when `limit` is absent.
pub const DEFAULT_LIMIT: u32 = 100;

fn string(v: &Value, k: &str) -> Result<Option<String>, String> {
    match v.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.len() <= 256 => Ok(Some(s.clone())),
        Some(_) => Err(format!("{k} must be a string of at most 256 bytes")),
    }
}

pub fn parse(params: &Value) -> Result<Query, String> {
    let obj = match params {
        Value::Null => return Ok(Query { limit: DEFAULT_LIMIT, ..Default::default() }),
        Value::Object(o) => o,
        _ => return Err("params must be an object".into()),
    };
    if let Some(k) = obj.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(format!("unknown parameter {k:?}"));
    }
    let after_seq = match obj.get("after_seq") {
        None | Some(Value::Null) => 0,
        Some(v) => v.as_i64().filter(|n| *n >= 0).ok_or("after_seq must be a non-negative integer")?,
    };
    let limit = match obj.get("limit") {
        None | Some(Value::Null) => DEFAULT_LIMIT,
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=u64::from(Query::MAX_LIMIT)).contains(n))
            .map(|n| n as u32)
            .ok_or_else(|| format!("limit must be 1..={}", Query::MAX_LIMIT))?,
    };
    let session = string(params, "session")?.map(|s| SessionId::try_from(s).map(|x| x.to_string())).transpose()?;
    let kind = string(params, "kind")?
        .map(|s| {
            serde_json::from_value::<EventKind>(Value::String(s.clone())).map_err(|_| format!("unknown kind {s:?}"))
        })
        .transpose()?;
    let decision = match string(params, "decision")?.as_deref() {
        None => None,
        Some("allow") => Some(DecisionResult::Allow),
        Some("deny") => Some(DecisionResult::Deny),
        Some(d) => return Err(format!("decision must be allow or deny, not {d:?}")),
    };
    let reason = string(params, "reason")?
        .map(|s| {
            serde_json::from_value::<Reason>(Value::String(s.clone())).map_err(|_| format!("unknown reason {s:?}"))
        })
        .transpose()?;
    // The one canonicaliser (I6): rows store canonical hosts.
    let host = string(params, "host")?
        .map(|h| netguard::canon_host(h.as_bytes()).map(|c| c.as_str().to_string()).map_err(|e| format!("host: {e:?}")))
        .transpose()?;
    Ok(Query { after_seq, session, kind, decision, reason, host, limit })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn filters_are_validated_not_ignored() {
        let q =
            parse(&json!({"decision": "deny", "host": "EVIL.test", "reason": "host_not_allowed", "limit": 5})).unwrap();
        assert_eq!(q.decision, Some(DecisionResult::Deny));
        assert_eq!(q.host.as_deref(), Some("evil.test"));
        assert_eq!(q.reason, Some(Reason::HostNotAllowed));
        assert_eq!(q.limit, 5);
        assert_eq!(parse(&Value::Null).unwrap().limit, DEFAULT_LIMIT);
        for bad in [
            json!({"hots": "x"}),
            json!({"decision": "maybe"}),
            json!({"reason": "nope"}),
            json!({"kind": "request.anything"}),
            json!({"host": "a\u{0}b.test"}),
            json!({"limit": 0}),
            json!({"limit": 1001}),
            json!({"after_seq": -1}),
            json!({"session": "../../x"}),
            json!([1]),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }
}
