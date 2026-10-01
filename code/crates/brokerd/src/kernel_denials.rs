//! Kernel-enforced denials on the audit record (ADR-041). On macOS every
//! Seatbelt deny rule of a session carries the tag `broker:<session>`
//! (`with message`); the kernel's report of each denial reaches the unified
//! log as `Sandbox: cat(123) deny(1) file-read-data /path\nbroker:<session>`,
//! which the daemon streams for the session's tag while it runs, taking
//! only reports the kernel's Sandbox extension logged. Each distinct
//! process name, operation and target becomes one `kernel.denied` row
//! (reason `sandbox_denied`), at most [`MAX_ROWS`] per session.
//!
//! The kernel enforces the denial whether or not it is recorded: this is
//! the record, not the control. The kernel rate-limits its reports, and a
//! collector that cannot start (no `log`, no permission) records nothing,
//! so the absence of rows proves nothing. On Linux, Landlock does not
//! report denials to an unprivileged process (a residual, ADR-041); the
//! syscalls seccomp refuses reach brokerd as user notifications and are
//! recorded by [`seccomp`] (ADR-043).

use audit::{AuditEvent, EventKind, Reason, Recorder, RequestId, SessionId};
use std::sync::Arc;

pub mod seccomp;

/// Most `kernel.denied` rows per session; one more row says the rest were
/// suppressed.
pub const MAX_ROWS: usize = 500;
/// Longest target kept on a row.
const MAX_TARGET: usize = 512;
/// Only the kernel's Sandbox extension reports denials: any process can log
/// a message that looks like one, and name its binary `Sandbox` (tested).
const KERNEL_SANDBOX: &str = "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox";

/// The unified-log predicate for one session's reports.
pub fn predicate(tag: &str) -> String {
    format!(
        "processID == 0 AND processImagePath == \"/kernel\" AND senderImagePath == \"{KERNEL_SANDBOX}\" \
         AND eventMessage CONTAINS \"{tag}\""
    )
}

/// The message of one `log stream --style ndjson` line, if the kernel's
/// Sandbox extension logged it (checked again here, not only in the
/// predicate).
pub fn kernel_message(line: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let from_kernel = v.get("processID").and_then(|p| p.as_u64()) == Some(0)
        && v.get("processImagePath").and_then(|p| p.as_str()) == Some("/kernel")
        && v.get("senderImagePath").and_then(|p| p.as_str()) == Some(KERNEL_SANDBOX);
    if !from_kernel {
        return None;
    }
    v.get("eventMessage")?.as_str().map(str::to_string)
}

/// One kernel report of a denial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial {
    pub process: String,
    pub pid: u32,
    pub operation: String,
    pub target: String,
}

/// Parse one report for this session's `tag`; anything else is `None`.
pub fn parse(message: &str, tag: &str) -> Option<Denial> {
    let (body, t) = message.rsplit_once('\n')?;
    if t.trim() != tag {
        return None;
    }
    let rest = body.trim_end().strip_prefix("Sandbox: ")?;
    let (proc_pid, rest) = rest.split_once(' ')?;
    let (process, pid) = proc_pid.strip_suffix(')')?.rsplit_once('(')?;
    let pid = pid.parse().ok()?;
    let rest = rest.strip_prefix("deny(")?;
    let (_, rest) = rest.split_once(") ")?;
    let (operation, target) = rest.split_once(' ').unwrap_or((rest, ""));
    if operation.is_empty() || !operation.bytes().all(|b| b.is_ascii_lowercase() || b == b'-' || b == b'*') {
        return None;
    }
    let target: String = target.chars().take(MAX_TARGET).collect();
    Some(Denial { process: process.to_string(), pid, operation: operation.to_string(), target })
}

/// The in-sandbox shim, whose start-up checks (a denied read, create and
/// connect, before the agent runs) are denials too.
const SHIM: &str = "broker-sandbox-shim";

/// Rows for one session's reports: deduplicated and capped. Nothing is left
/// out by process name: a process can take any name, so the shim's checks
/// are recorded like everything else and only flagged `launch_check`
/// (advisory, the name is not proof).
pub struct Recording {
    /// The session's attribution (session, end user, groups, agent,
    /// sandbox), copied onto every row (I9).
    base: AuditEvent,
    tag: String,
    seen: std::collections::HashSet<(String, String, String)>,
    rows: usize,
}

impl Recording {
    /// `base` carries the session's attribution (only that is copied).
    pub fn new(base: AuditEvent) -> Option<Self> {
        let session: &SessionId = base.session.as_ref()?;
        let tag = launcher::backends::seatbelt_session_tag(session.as_str())?;
        Some(Recording { base, tag, seen: Default::default(), rows: 0 })
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// The row for one unified-log message, if it is a new denial of this
    /// session and the cap is not reached. Deduplicated per process name
    /// (per process for the shim's name), so the shim's check of a connect
    /// never hides the agent's own attempt.
    pub fn row(&mut self, message: &str) -> Option<AuditEvent> {
        let d = parse(message, &self.tag)?;
        let shim = d.process == SHIM;
        let who = if shim { format!("{}({})", d.process, d.pid) } else { d.process.clone() };
        if self.rows > MAX_ROWS || !self.seen.insert((who, d.operation.clone(), d.target.clone())) {
            return None;
        }
        self.rows += 1;
        let mut ev = AuditEvent::new(EventKind::KernelDenied)
            .attributed_as(&self.base)
            .request(&RequestId::new())
            .deny(Reason::SandboxDenied, vec![])
            .detail("layer", "seatbelt");
        if self.rows > MAX_ROWS {
            return Some(ev.detail("suppressed", "further kernel denials in this session are not recorded"));
        }
        ev = ev
            .detail("operation", d.operation)
            .detail("target", d.target)
            .detail("process", d.process)
            .detail("pid", d.pid);
        if shim {
            ev = ev.detail("launch_check", true);
        }
        Some(ev)
    }
}

/// The unified-log stream for one session (macOS), or the session's
/// seccomp listener (Linux, ADR-043), stopped at teardown.
pub struct Collector {
    child: Option<tokio::process::Child>,
    reader: Option<tokio::task::JoinHandle<()>>,
    seccomp: Option<launcher::SeccompStop>,
}

impl Collector {
    /// Start streaming the session's reports into `recorder`. Never fails a
    /// launch: without a collector the kernel still enforces every rule.
    /// Returns once `log stream` has printed its header (at most 2 s), so
    /// the agent's first denials are not lost to a stream not yet live.
    pub async fn start(base: AuditEvent, recorder: Arc<dyn Recorder>) -> Collector {
        use tokio::io::AsyncBufReadExt;
        let inert = Collector { child: None, reader: None, seccomp: None };
        if !cfg!(target_os = "macos") {
            return inert;
        }
        let Some(mut rec) = Recording::new(base) else { return inert };
        let predicate = predicate(rec.tag());
        let spawned = tokio::process::Command::new("/usr/bin/log")
            .args(["stream", "--style", "ndjson", "--level", "default", "--predicate", &predicate])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let Ok(mut child) = spawned else { return inert };
        let Some(out) = child.stdout.take() else { return inert };
        let mut lines = tokio::io::BufReader::new(out).lines();
        let first = match tokio::time::timeout(std::time::Duration::from_secs(2), lines.next_line()).await {
            Ok(Ok(Some(l))) => Some(l),
            _ => None,
        };
        let reader = tokio::spawn(async move {
            let mut take = |line: &str| {
                let Some(msg) = kernel_message(line) else { return };
                if let Some(ev) = rec.row(&msg)
                    && let Err(e) = recorder.append(&ev)
                {
                    eprintln!("brokerd: audit append failed for a kernel denial: {e:#}");
                }
            };
            if let Some(l) = first {
                take(&l);
            }
            while let Ok(Some(line)) = lines.next_line().await {
                take(&line);
            }
        });
        Collector { child: Some(child), reader: Some(reader), seccomp: None }
    }

    /// Linux: record the syscalls the launcher's serving thread answers for
    /// this session (ADR-043). `base` carries the session's attribution.
    pub fn attach_seccomp(&mut self, feed: launcher::SeccompFeed, base: AuditEvent, recorder: Arc<dyn Recorder>) {
        let launcher::SeccompFeed { denials, stop } = feed;
        seccomp::drain(denials, base, recorder);
        self.seccomp = Some(stop);
    }

    /// Stop after a short drain: the kernel's reports arrive shortly after
    /// the denial, so the last ones of a session would otherwise be lost.
    /// A seccomp listener is closed at once (its rows are already queued;
    /// anything still running in the sandbox now gets ENOSYS).
    pub fn stop(mut self) {
        drop(self.seccomp.take());
        let (Some(mut child), Some(reader)) = (self.child.take(), self.reader.take()) else { return };
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let _ = child.kill().await;
            reader.abort();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_are_parsed_attributed_and_deduplicated() {
        let s = SessionId::new();
        let mut base = AuditEvent::new(EventKind::SessionStart).session(&s);
        base.enduser = Some("00uTEST".into());
        let base_ts = base.ts.clone();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut r = Recording::new(base).unwrap();
        let tag = r.tag().to_string();
        let msg = |p: &str, op: &str, t: &str| format!("Sandbox: {p} deny(1) {op} {t}\n{tag}");
        let d = parse(&msg("cat(26863)", "file-read-data", "/Users/x/.ssh/id_ed25519"), &tag).unwrap();
        assert_eq!(
            d,
            Denial {
                process: "cat".into(),
                pid: 26863,
                operation: "file-read-data".into(),
                target: "/Users/x/.ssh/id_ed25519".into()
            }
        );
        // Another session's tag, a malformed report, or no tag: nothing.
        assert_eq!(parse(&msg("cat(1)", "file-read-data", "/x").replace(&tag, "broker:OTHER"), &tag), None);
        assert_eq!(parse("Sandbox: cat(1) deny(1) file-read-data /x", &tag), None);
        assert_eq!(parse(&format!("garbage\n{tag}"), &tag), None);
        // One row per process name, operation and target.
        let ev = r.row(&msg("cat(5)", "file-read-data", "/secret")).unwrap();
        assert_eq!((ev.kind, ev.reason), (EventKind::KernelDenied, Some(Reason::SandboxDenied)));
        assert_eq!(ev.session.as_ref(), Some(&s));
        assert_eq!(ev.enduser.as_deref(), Some("00uTEST"), "attributed like every row (I9)");
        assert!(ev.ts > base_ts, "the row's own time, not the template's");
        assert!(ev.request_id.is_some());
        assert_eq!(ev.detail["target"], "/secret");
        assert!(r.row(&msg("cat(6)", "file-read-data", "/secret")).is_none(), "deduplicated");
        assert!(r.row(&msg("sh(7)", "file-read-data", "/secret")).is_some(), "another process");
        // The shim's checks are recorded (flagged, the name is no proof),
        // and never hide the agent's own attempt at the same thing.
        let ev = r.row(&msg("broker-sandbox-shim(8)", "network-outbound", "remote:*:443")).unwrap();
        assert_eq!(ev.detail["launch_check"], true);
        let ev = r.row(&msg("node(8)", "network-outbound", "remote:*:443")).unwrap();
        assert!(ev.detail.get("launch_check").is_none());
        assert!(r.row(&msg("broker-sandbox-shim(9)", "network-outbound", "remote:*:443")).is_some(), "per pid");
    }

    /// A process of any name can log a look-alike report (a binary named
    /// `Sandbox` logging from inside a session was seen in the unified log
    /// with `sender == "Sandbox"`); only the kernel's own are taken.
    #[test]
    fn only_the_kernels_reports_are_taken() {
        let msg = "Sandbox: cat(1) deny(1) file-read-data /x\nbroker:ABC";
        let line = |pid: u64, image: &str, sender: &str| {
            serde_json::json!({
                "processID": pid, "processImagePath": image, "senderImagePath": sender, "eventMessage": msg
            })
            .to_string()
        };
        assert_eq!(kernel_message(&line(0, "/kernel", KERNEL_SANDBOX)).as_deref(), Some(msg));
        assert_eq!(kernel_message(&line(39214, "/tmp/forge/Sandbox", "/tmp/forge/Sandbox")), None);
        assert_eq!(kernel_message(&line(0, "/kernel", "/tmp/forge/Sandbox")), None);
        assert_eq!(kernel_message(&line(7, "/kernel", KERNEL_SANDBOX)), None);
        assert_eq!(kernel_message("not json"), None);
        let p = predicate("broker:ABC");
        assert!(p.starts_with("processID == 0 AND ") && p.contains(KERNEL_SANDBOX) && p.ends_with("\"broker:ABC\""));
    }

    #[test]
    fn rows_are_capped_with_one_note() {
        let mut r = Recording::new(AuditEvent::new(EventKind::SessionStart).session(&SessionId::new())).unwrap();
        let tag = r.tag().to_string();
        let mut n = 0;
        for k in 0..(MAX_ROWS + 50) {
            if let Some(ev) = r.row(&format!("Sandbox: cat(1) deny(1) file-read-data /f{k}\n{tag}")) {
                n += 1;
                if n == MAX_ROWS + 1 {
                    assert!(ev.detail.contains_key("suppressed"));
                }
            }
        }
        assert_eq!(n, MAX_ROWS + 1);
    }

    proptest::proptest! {
        #[test]
        fn parse_is_total(s in "\\PC{0,200}") {
            let _ = parse(&s, "broker:ABC");
        }
    }
}
