//! Kernel-enforced denials reach the audit record (ADR-041, macOS): a write
//! to a protected path and a direct connection, refused by Seatbelt inside
//! a session, become `kernel.denied` rows on that session with reason
//! `sandbox_denied`, attributed like every row, separate from the shim's
//! own launch checks. On Linux the syscalls seccomp refuses do too
//! (ADR-043, user notification); Landlock's go to the host's audit log only.

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

/// Linux (ADR-043): socket(AF_UNIX), socket(AF_PACKET), unshare(CLONE_NEWUSER)
/// and ptrace inside a session are refused with EPERM, answered by brokerd
/// through the seccomp listener, and each becomes an attributed
/// `kernel.denied` row with layer `seccomp`, the syscall and its plain
/// arguments. The shim's own check (socket(AF_UNIX) before exec) is on the
/// record too, flagged `launch_check`: the listener was served before the
/// agent ran.
#[cfg(target_os = "linux")]
#[test]
fn seccomp_denials_are_on_the_sessions_record() {
    use audit::{AuditEvent, EventKind, Reason};
    use conformance::m1::wait_for;
    use conformance::*;
    use std::time::Duration;

    let h = Harness::new("version = 1\n");
    let probes: Vec<Vec<String>> =
        [vec!["unix-socket"], vec!["packet-socket"], vec!["unshare-user"], vec!["ptrace", "1"]]
            .iter()
            .map(|p| p.iter().map(|s| s.to_string()).collect())
            .collect();
    for (p, r) in probes.iter().zip(h.probe_batch(&probes)) {
        assert!(r.denied(), "{p:?}: {r:?}");
        assert_eq!(r.errno(), Some("EPERM"), "{p:?}: brokerd's answer, not ENOSYS: {r:?}");
    }
    let ready = h.events().into_iter().find(|e| e.kind == EventKind::SessionReady).expect("session.ready");
    let layers = ready.detail["layers"].as_array().cloned().unwrap_or_default();
    let notify = layers.iter().rfind(|l| l["name"] == "seccomp_notify").expect("seccomp_notify layer");
    assert_eq!((notify["ok"].as_bool(), notify["required"].as_bool()), (Some(true), Some(false)), "{notify}");
    let session = ready.session.clone().expect("session");

    let num = |e: &AuditEvent, k: &str| e.detail.get(k).and_then(|v| v.as_u64());
    let text = |e: &AuditEvent, k: &str| e.detail.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let wanted: [(&str, &str, u64); 4] = [
        ("socket", "domain", libc::AF_UNIX as u64),
        ("socket", "domain", libc::AF_PACKET as u64),
        ("unshare", "flags", libc::CLONE_NEWUSER as u64),
        ("ptrace", "request", libc::PTRACE_ATTACH as u64),
    ];
    let rows = wait_for(Duration::from_secs(10), || {
        let v: Vec<AuditEvent> = h
            .events()
            .into_iter()
            .filter(|e| e.kind == EventKind::KernelDenied && text(e, "layer") == "seccomp")
            .collect();
        // The probe's own attempts (comm `conformance-probe` cut to 15 bytes).
        let agent = |e: &&AuditEvent| e.detail.get("launch_check").is_none() && text(e, "process") == "conformance-pro";
        let all = wanted.iter().all(|&(sys, k, val)| {
            v.iter().filter(agent).any(|e: &AuditEvent| text(e, "syscall") == sys && num(e, k) == Some(val))
        });
        all.then_some(v)
    })
    .expect("every refused syscall recorded within 10 s");
    for e in &rows {
        assert_eq!(e.reason, Some(Reason::SandboxDenied), "{e:?}");
        assert_eq!(e.session.as_ref(), Some(&session), "attributed to the session that was denied");
        assert!(num(e, "pid").is_some() && e.detail.contains_key("nr"), "{e:?}");
    }
    let check = rows.iter().find(|e| e.detail.get("launch_check").is_some()).expect("the shim's check is recorded");
    assert_eq!((text(check, "syscall"), num(check, "domain")), ("socket".to_string(), Some(libc::AF_UNIX as u64)));
    h.assert_attributed();
    h.verify_audit().unwrap();
}

/// Linux (ADR-043): if brokerd does not take the seccomp listener, the
/// shim's check gets ENOSYS instead of EPERM and the launch is refused
/// before the agent runs (I2): no refused syscall is ever allowed for want
/// of an answer.
#[cfg(target_os = "linux")]
#[test]
fn an_unserved_seccomp_listener_refuses_the_launch() {
    use audit::EventKind;
    use conformance::*;

    let h = Harness::with_daemon_env("version = 1\n", &[("BROKER_FAULT_INJECT", "seccomp_notify")]);
    let marker = h.repo_path().join("AGENT-RAN");
    let r = h.probe(&["write-new", &marker.display().to_string()]);
    assert_eq!(r.code, 125, "{r:?}");
    assert!(!marker.exists(), "the agent ran");
    assert!(r.stderr.contains("launch refused") && r.stderr.contains("ENOSYS"), "{}", r.stderr);
    assert_eq!(h.events().iter().filter(|e| e.kind == EventKind::LaunchRefused).count(), 1);
    assert!(h.events().iter().all(|e| e.kind != EventKind::SessionReady), "no session.ready");
}
