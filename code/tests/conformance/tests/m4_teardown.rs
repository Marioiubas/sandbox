//! Teardown (TB2; Broker CLI and Daemon: on agent exit the supervisor kills
//! the tree): a process that left the sandbox's process group does not
//! outlive its session.

use conformance::Harness;
use std::time::Duration;

/// `setsid()` leaves the group; a double fork whose middle process exits
/// leaves the ancestry too (the survivor is reparented). On macOS
/// Seatbelt does not mediate either; the survivor still runs under the
/// session's profile, and teardown finds it by that (ADR-049). On Linux it
/// is still in the session's PID namespace. Either way it stops with the
/// session: its heartbeat file stops growing. (It lets go of the session's
/// stdio first, so a survivor fails this test instead of hanging it, and it
/// exits once the fixture's repository is gone.)
#[test]
fn a_daemonised_process_does_not_outlive_its_session() {
    let h = Harness::new("version = 1\n");
    let beat = h.repo_path().join("heartbeat");
    let script = format!(
        "/usr/bin/perl -e 'use POSIX; if (fork() == 0) {{ POSIX::setsid(); if (fork() == 0) {{ \
         open(STDIN, \"<\", \"/dev/null\"); open(STDOUT, \">\", \"/dev/null\"); open(STDERR, \">\", \"/dev/null\"); \
         while (1) {{ open(my $f, \">>\", \"{0}\") or exit 0; print $f \"x\"; close $f; select(undef, undef, undef, 0.05) }} }} \
         exit 0 }}' && n=0; while [ ! -s '{0}' ] && [ $n -lt 100 ]; do sleep 0.05; n=$((n+1)); done; \
         [ -s '{0}' ] && echo STARTED",
        beat.display()
    );
    let r = h.sh(&script);
    assert!(r.stdout.contains("STARTED"), "the daemonised process never ran: {r:?}");
    // `broker run` returns after teardown wrote `session.stop`.
    let size = || std::fs::metadata(&beat).map(|m| m.len()).unwrap_or(0);
    std::thread::sleep(Duration::from_millis(200));
    let before = size();
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(size(), before, "a process of the session that left its group is still running after the session ended");
}
