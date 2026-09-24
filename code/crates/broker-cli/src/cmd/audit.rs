//! `broker audit verify|tail|query`.

use super::{EXIT_BROKER, ctl};
use audit::SqliteRecorder;

pub fn verify() -> i32 {
    let Ok(dirs) = ctl::dirs() else { return EXIT_BROKER };
    let db = dirs.audit_db();
    if !db.exists() {
        eprintln!("broker: no audit log at {}", db.display());
        return 1;
    }
    match SqliteRecorder::verify_path(&db) {
        Ok(n) => {
            println!("audit chain OK: {n} events ({})", db.display());
            0
        }
        Err(e) => {
            println!("audit chain BROKEN: {e} ({})", db.display());
            1
        }
    }
}

fn line(seq: i64, e: &audit::AuditEvent) -> String {
    format!(
        "{:>6} {} {:<16} {:<5} {:<24} {}",
        seq,
        e.ts,
        e.kind.as_str(),
        match &e.decision {
            Some(d) if d.result == audit::DecisionResult::Deny => "deny",
            Some(_) => "allow",
            None => "",
        },
        e.reason.map(|r| r.as_str()).unwrap_or(""),
        e.dest
            .as_ref()
            .map(|d| format!("{}:{}", d.host.as_deref().unwrap_or("-"), d.port.unwrap_or(0)))
            .or_else(|| e.request_id.as_ref().map(|r| r.to_string()))
            .unwrap_or_default()
    )
}

pub fn tail(n: u32) -> i32 {
    let Ok(dirs) = ctl::dirs() else { return EXIT_BROKER };
    match SqliteRecorder::open_read_only(&dirs.audit_db()).and_then(|r| r.tail(n)) {
        Ok(evs) => {
            for s in evs {
                println!("{}", line(s.seq, &s.event));
            }
            0
        }
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

/// `broker audit query`: filtered rows through `audit.query` on the
/// control socket (the daemon validates every filter).
pub fn query(params: serde_json::Value, json: bool) -> i32 {
    let run = || -> anyhow::Result<i32> {
        let dirs = ctl::dirs()?;
        drop(ctl::connect_or_start(&dirs)?);
        let r = ctl::call(&dirs, "audit.query", params)?;
        if let Some(e) = r.error {
            eprintln!("broker: {}", e.message);
            return Ok(2);
        }
        for row in r.result.and_then(|v| v.as_array().cloned()).unwrap_or_default() {
            if json {
                println!("{row}");
            } else {
                let seq = row["seq"].as_i64().unwrap_or(0);
                let ev: audit::AuditEvent = serde_json::from_value(row["event"].clone())?;
                println!("{}", line(seq, &ev));
            }
        }
        Ok(0)
    };
    run().unwrap_or_else(|e| {
        eprintln!("broker: {e:#}");
        EXIT_BROKER
    })
}
