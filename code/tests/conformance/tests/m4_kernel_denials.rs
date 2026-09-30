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
    assert!(!h.repo_path().join(".git/hooks/pre-commit").exists(), "and the kernel refused it");
    h.verify_audit().unwrap();
}
