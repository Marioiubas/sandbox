//! `broker audit verify|tail`.

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

pub fn tail(n: u32) -> i32 {
    let Ok(dirs) = ctl::dirs() else { return EXIT_BROKER };
    match SqliteRecorder::open_read_only(&dirs.audit_db()).and_then(|r| r.tail(n)) {
        Ok(evs) => {
            for s in evs {
                let e = &s.event;
                println!(
                    "{:>6} {} {:<16} {:<5} {:<24} {}",
                    s.seq,
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
                );
            }
            0
        }
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}
