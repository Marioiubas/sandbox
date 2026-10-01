//! Kernel-enforced denials reach the audit record (ADR-041, macOS): a write
//! to a protected path and a direct connection, refused by Seatbelt inside
//! a session, become `kernel.denied` rows on that session with reason
//! `sandbox_denied`, attributed like every row, separate from the shim's
//! own launch checks. On Linux there is no collector (a residual).

#[cfg(target_os = "macos")]
#[test]
fn kernel_denials_are_on_the_sessions_record() {
    use audit::{EventKind, Reason};
    use conformance::m1::wait_for;
    use conformance::*;
    use std::time::Duration;

    let h = Harness::new("version = 1\n");
    let r = h.sh("echo x > .git/hooks/pre-commit 2>/dev/null; /usr/bin/nc -z -G 2 1.1.1.1 443 2>/dev/null; echo DONE");
    assert!(r.stdout.contains("DONE"), "{r:?}");
    let session = h
        .events()
        .into_iter()
        .find(|e| e.kind == EventKind::SessionStart)
        .and_then(|e| e.session)
        .expect("session.start");
    let rows = wait_for(Duration::from_secs(20), || {
        let v: Vec<_> = h.events().into_iter().filter(|e| e.kind == EventKind::KernelDenied).collect();
        let s = |e: &audit::AuditEvent, k: &str| e.detail.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        // The agent's own denials, not the shim's launch checks (which
        // include a connect to port 443 and are flagged `launch_check`).
        let agent = |e: &&audit::AuditEvent| e.detail.get("launch_check").is_none();
        let write = v
            .iter()
            .filter(agent)
            .any(|e| s(e, "operation").starts_with("file-write") && s(e, "target").ends_with(".git/hooks/pre-commit"));
        let net = v.iter().filter(agent).any(|e| s(e, "operation") == "network-outbound" && s(e, "process") == "nc");
        (write && net).then_some(v)
    })
    .expect("both denials recorded within 20 s");
    for e in &rows {
        assert_eq!(e.reason, Some(Reason::SandboxDenied));
        assert_eq!(e.session.as_ref(), Some(&session), "attributed to the session that was denied");
        assert!(e.enduser.is_some() && e.agent.is_some() && e.sandbox.is_some(), "{e:?}");
    }
    // The shim's checks are the first thing a session does: their rows
    // prove the stream was live before the agent started.
    let checks = wait_for(Duration::from_secs(10), || {
        let n = h.events().iter().filter(|e| e.detail.get("launch_check").is_some()).count();
        (n > 0).then_some(n)
    });
    assert!(checks.is_some(), "the shim's launch checks are on the record");
    assert!(!h.repo_path().join(".git/hooks/pre-commit").exists(), "and the kernel refused it");
    h.assert_attributed();
    h.verify_audit().unwrap();
}

/// Linux (ADR-041): brokerd cannot read Landlock's denials unprivileged, but
/// from ABI 7 the launcher asks the kernel to log the agent's denials after
/// exec to the host's audit log. A TCP connect to a loopback port other than
/// the bridge is refused by Landlock alone; its record must appear. Needs
/// auditd running and passwordless sudo to read the log: run by CI on
/// ubuntu-24.04 (ABI 7).
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs host audit (auditd) and sudo; run by CI on ubuntu-24.04"]
fn landlock_denials_reach_the_host_audit_log() {
    use audit::EventKind;
    use conformance::*;
    use std::process::Command;

    let log = || {
        let out = Command::new("sudo").args(["-n", "cat", "/var/log/audit/audit.log"]).output().unwrap();
        assert!(out.status.success(), "cannot read the host audit log: {out:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let port = 20000 + (std::process::id() % 40000) as u16;
    let pattern = format!("dest={port}");
    let before = log().lines().filter(|l| l.contains(&pattern)).count();

    let h = Harness::new("version = 1\n");
    let r = h.probe(&["tcp", "127.0.0.1", &port.to_string()]);
    assert!(r.denied(), "{r:?}");
    let ready = h.events().into_iter().find(|e| e.kind == EventKind::SessionReady).expect("session.ready");
    let layers = serde_json::to_string(&ready.detail["layers"]).unwrap();
    assert!(layers.contains("host audit after exec on"), "ABI 7 or later expected: {layers}");

    let found = conformance::m1::wait_for(std::time::Duration::from_secs(10), || {
        let lines: Vec<String> = log()
            .lines()
            .filter(|l| l.contains(&pattern) && l.contains("blockers=net.connect_tcp"))
            .map(str::to_string)
            .collect();
        (lines.len() > before).then_some(lines)
    });
    assert!(found.is_some(), "no Landlock record for {pattern}; last lines:\n{}", {
        let all = log();
        all.lines().rev().take(20).collect::<Vec<_>>().join("\n")
    });
}
