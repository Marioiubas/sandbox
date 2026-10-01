//! Kernel denial reports (ADR-041): the unified-log line and the report in
//! it carry a process name and a target the sandbox chooses. Never panics;
//! only the session's own tag yields a row; targets are bounded; rows are
//! capped per session.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let _ = brokerd::kernel_denials::kernel_message(text);
    let session = audit::SessionId::new();
    let base = audit::AuditEvent::new(audit::EventKind::SessionStart).session(&session);
    let mut rec = brokerd::kernel_denials::Recording::new(base).unwrap();
    let tag = rec.tag().to_string();
    // Without this session's (random) tag: never a report of this session.
    assert!(brokerd::kernel_denials::parse(text, &tag).is_none());
    // As the kernel would append this session's tag.
    let msg = format!("{text}\n{tag}");
    if let Some(d) = brokerd::kernel_denials::parse(&msg, &tag) {
        assert!(!d.operation.is_empty());
        assert!(d.target.chars().count() <= 512);
    }
    let mut rows = 0;
    for line in text.lines().take(2000) {
        if let Some(ev) = rec.row(&format!("{line}\n{tag}")) {
            assert_eq!(ev.kind, audit::EventKind::KernelDenied);
            assert_eq!(ev.session.as_ref(), Some(&session));
            rows += 1;
        }
    }
    assert!(rows <= brokerd::kernel_denials::MAX_ROWS + 1);
});
