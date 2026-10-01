//! Linux: the syscalls the seccomp layer refuses, on the session's record
//! (ADR-043). The deny filter returns `USER_NOTIF`; the launcher's serving
//! thread answers each notification `-EPERM` and passes on the syscall
//! number and plain register arguments ([`launcher::SeccompDenial`]); this
//! turns them into `kernel.denied` rows (reason `sandbox_denied`, layer
//! `seccomp`), deduplicated per process name, syscall and arguments, at
//! most [`MAX_ROWS`] per session like the macOS collector.
//!
//! The answer comes first and the row after: the kernel holds the call
//! until brokerd answers, and the answer never depends on the record.

use super::MAX_ROWS;
use audit::{AuditEvent, EventKind, Reason, Recorder, RequestId};
use launcher::SeccompDenial;
use std::collections::HashSet;
use std::sync::Arc;

/// The shim's `comm` (`broker-sandbox-shim`, cut to 15 bytes by the kernel):
/// its own seccomp check before the agent runs is flagged `launch_check`.
const SHIM_COMM: &str = "broker-sandbox-";

/// Rows for one session's refused syscalls: deduplicated and capped.
pub struct SeccompRecording {
    /// The session's attribution (only that is copied onto each row).
    base: AuditEvent,
    seen: HashSet<(String, String)>,
    rows: usize,
}

impl SeccompRecording {
    pub fn new(base: AuditEvent) -> Self {
        SeccompRecording { base, seen: HashSet::new(), rows: 0 }
    }

    /// The row for one refused syscall, if it is new for this process name
    /// (per process for the shim's name, so its check never hides the
    /// agent's own attempt) and the cap is not reached.
    pub fn row(&mut self, d: &SeccompDenial) -> Option<AuditEvent> {
        let process = d.process.clone().unwrap_or_default();
        let shim = process == SHIM_COMM;
        let who = if shim { format!("{process}({})", d.pid) } else { process.clone() };
        let what = format!("{}{:?}", d.syscall, d.args);
        if self.rows > MAX_ROWS || !self.seen.insert((who, what)) {
            return None;
        }
        self.rows += 1;
        let mut ev = AuditEvent::new(EventKind::KernelDenied)
            .attributed_as(&self.base)
            .request(&RequestId::new())
            .deny(Reason::SandboxDenied, vec![])
            .detail("layer", "seccomp");
        if self.rows > MAX_ROWS {
            return Some(ev.detail("suppressed", "further kernel denials in this session are not recorded"));
        }
        ev = ev.detail("syscall", d.syscall).detail("nr", d.nr);
        for (k, v) in &d.args {
            ev = ev.detail(k, *v);
        }
        ev = ev.detail("process", process).detail("pid", d.pid);
        if shim {
            ev = ev.detail("launch_check", true);
        }
        Some(ev)
    }
}

/// Record the session's refused syscalls on a thread of its own until the
/// launcher's serving thread ends (the session's sandbox is gone, or the
/// collector stopped it).
pub fn drain(feed: std::sync::mpsc::Receiver<SeccompDenial>, base: AuditEvent, recorder: Arc<dyn Recorder>) {
    let mut rec = SeccompRecording::new(base);
    let spawned = std::thread::Builder::new().name("seccomp-record".into()).spawn(move || {
        while let Ok(d) = feed.recv() {
            if let Some(ev) = rec.row(&d)
                && let Err(e) = recorder.append(&ev)
            {
                eprintln!("brokerd: audit append failed for a seccomp denial: {e:#}");
            }
        }
    });
    if let Err(e) = spawned {
        // The refusals stand (brokerd's serving thread still answers them).
        eprintln!("brokerd: cannot record seccomp denials: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use audit::SessionId;

    fn denial(
        process: &str,
        pid: u32,
        nr: i64,
        syscall: &'static str,
        args: Vec<(&'static str, u64)>,
    ) -> SeccompDenial {
        SeccompDenial { pid, process: Some(process.into()), nr, syscall, args }
    }

    #[test]
    fn rows_are_attributed_deduplicated_and_flag_the_shim() {
        let s = SessionId::new();
        let mut base = AuditEvent::new(EventKind::SessionStart).session(&s);
        base.enduser = Some("00uTEST".into());
        base.agent_sha256 = Some("ab".repeat(32));
        let base_ts = base.ts.clone();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut r = SeccompRecording::new(base);
        let unix = || vec![("domain", 1), ("type", 1), ("protocol", 0)];
        let ev = r.row(&denial("conformance-pro", 40, 41, "socket", unix())).unwrap();
        assert_eq!((ev.kind, ev.reason), (EventKind::KernelDenied, Some(Reason::SandboxDenied)));
        assert_eq!(ev.session.as_ref(), Some(&s));
        assert_eq!(ev.enduser.as_deref(), Some("00uTEST"), "attributed like every row (I9)");
        assert_eq!(ev.agent_sha256.as_deref(), Some("ab".repeat(32).as_str()));
        assert!(ev.ts > base_ts, "the row's own time, not the template's");
        assert!(ev.request_id.is_some());
        assert_eq!(ev.detail["layer"], "seccomp");
        assert_eq!(ev.detail["syscall"], "socket");
        assert_eq!((ev.detail["domain"].as_u64(), ev.detail["type"].as_u64()), (Some(1), Some(1)));
        assert_eq!((ev.detail["process"].as_str(), ev.detail["pid"].as_u64()), (Some("conformance-pro"), Some(40)));
        assert!(ev.detail.get("launch_check").is_none());
        assert!(r.row(&denial("conformance-pro", 41, 41, "socket", unix())).is_none(), "deduplicated");
        let other = vec![("domain", 17), ("type", 3), ("protocol", 0)];
        assert!(r.row(&denial("conformance-pro", 41, 41, "socket", other)).is_some(), "other arguments");
        assert!(r.row(&denial("sh", 42, 41, "socket", unix())).is_some(), "another process");
        // The shim's check is recorded and flagged (the name is no proof),
        // per pid, and never hides the agent's own identical attempt.
        let ev = r.row(&denial(SHIM_COMM, 7, 41, "socket", unix())).unwrap();
        assert_eq!(ev.detail["launch_check"], true);
        assert!(r.row(&denial(SHIM_COMM, 8, 41, "socket", unix())).is_some(), "per pid");
        // A process gone before its name was read is still recorded.
        let gone = SeccompDenial { pid: 9, process: None, nr: 272, syscall: "unshare", args: vec![("flags", 1 << 28)] };
        assert_eq!(r.row(&gone).unwrap().detail["flags"], 1u64 << 28);
    }

    #[test]
    fn rows_are_capped_with_one_note() {
        let mut r = SeccompRecording::new(AuditEvent::new(EventKind::SessionStart).session(&SessionId::new()));
        let mut n = 0;
        for k in 0..(MAX_ROWS as u64 + 50) {
            if let Some(ev) = r.row(&denial("p", 1, 41, "socket", vec![("domain", k)])) {
                n += 1;
                if n == MAX_ROWS + 1 {
                    assert!(ev.detail.contains_key("suppressed"));
                }
            }
        }
        assert_eq!(n, MAX_ROWS + 1);
    }

    #[test]
    fn drain_records_until_the_feed_ends() {
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(audit::SqliteRecorder::open(&dir.path().join("a.db")).unwrap());
        let base = AuditEvent::new(EventKind::SessionStart).session(&SessionId::new());
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        drain(rx, base, rec.clone() as Arc<dyn Recorder>);
        tx.send(denial("x", 1, 41, "socket", vec![("domain", 1)])).unwrap();
        tx.send(denial("x", 1, 41, "socket", vec![("domain", 1)])).unwrap();
        drop(tx);
        let ok = (0..200).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            rec.tail(10).map(|v| v.iter().filter(|r| r.event.kind == EventKind::KernelDenied).count()).unwrap_or(0) == 1
        });
        assert!(ok, "one row for two identical denials");
    }
}
