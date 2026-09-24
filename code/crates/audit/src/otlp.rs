//! OTLP/HTTP JSON log export: one log record per exported decision, the
//! body being its OCSF event (so a collector can route it to any backend).
//! Encoding follows the OTLP protobuf-JSON mapping for `ExportLogsServiceRequest`.

use serde_json::{Value, json};

fn attr(k: &str, v: &str) -> Value {
    json!({ "key": k, "value": { "stringValue": v } })
}

/// Wrap OCSF events into one `resourceLogs` request.
pub fn logs_request(ocsf: &[Value]) -> Value {
    let records: Vec<Value> = ocsf
        .iter()
        .map(|e| {
            let denied = e.get("action_id").and_then(|a| a.as_u64()) == Some(2);
            let ms = e.get("time").and_then(|t| t.as_i64()).unwrap_or(0);
            let mut attrs = vec![
                attr("ocsf.class_uid", &e["class_uid"].to_string()),
                attr("broker.decision", if denied { "deny" } else { "allow" }),
            ];
            if let Some(s) = e.pointer("/unmapped/broker/session").and_then(|s| s.as_str()) {
                attrs.push(attr("broker.session", s));
            }
            if let Some(r) = e.get("status_detail").and_then(|s| s.as_str()) {
                attrs.push(attr("broker.reason", r));
            }
            json!({
                "timeUnixNano": (ms as i128 * 1_000_000).to_string(),
                // OTLP SeverityNumber: INFO = 9, WARN = 13.
                "severityNumber": if denied { 13 } else { 9 },
                "severityText": if denied { "WARN" } else { "INFO" },
                "body": { "stringValue": e.to_string() },
                "attributes": attrs,
            })
        })
        .collect();
    json!({
        "resourceLogs": [{
            "resource": { "attributes": [attr("service.name", "broker")] },
            "scopeLogs": [{ "scope": { "name": "broker.audit", "version": env!("CARGO_PKG_VERSION") }, "logRecords": records }],
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_each_event() {
        let e =
            json!({ "class_uid": 4001, "time": 1790000000000i64, "action_id": 2, "status_detail": "host_not_allowed" });
        let r = logs_request(&[e]);
        let rec = &r["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["severityText"], "WARN");
        assert_eq!(rec["timeUnixNano"], "1790000000000000000");
        assert!(rec["body"]["stringValue"].as_str().unwrap().contains("host_not_allowed"));
    }
}
