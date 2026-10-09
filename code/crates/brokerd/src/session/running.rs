//! The session's accept loop and the running session's lifecycle
//! (signals, teardown and `session.stop`).

use super::{Daemon, Running};
use crate::pipeline::{self, PipelineCtx};
use crate::proto::Exited;
use crate::session_util::signal_target;
use audit::{AuditEvent, EventKind, Recorder};
use std::sync::Arc;
use std::time::Duration;

pub(super) enum Listener {
    Unix(tokio::net::UnixListener),
    Tcp(tokio::net::TcpListener),
}

pub(super) async fn accept_loop(l: Listener, ctx: Arc<PipelineCtx>) {
    loop {
        match &l {
            Listener::Unix(u) => match u.accept().await {
                Ok((s, _)) => {
                    let c = ctx.clone();
                    tokio::spawn(async move {
                        pipeline::handle(&c, s).await;
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            },
            Listener::Tcp(t) => match t.accept().await {
                Ok((s, peer)) => {
                    // Loopback only; the sentinel authenticates the session.
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    let _ = s.set_nodelay(true);
                    let c = ctx.clone();
                    tokio::spawn(async move {
                        pipeline::handle(&c, s).await;
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            },
        }
    }
}

impl Running {
    /// Forward a signal to the agent. Only a small set is accepted.
    pub fn signal(&self, name: &str) {
        let sig = match name {
            "INT" => libc::SIGINT,
            "TERM" => libc::SIGTERM,
            "HUP" => libc::SIGHUP,
            "WINCH" => libc::SIGWINCH,
            "QUIT" => libc::SIGQUIT,
            _ => return,
        };
        let target = signal_target(self.pid);
        // SAFETY: plain kill(2).
        unsafe { libc::kill(target as i32, sig) };
    }

    pub fn take_child(&mut self) -> Option<std::process::Child> {
        self.child.take()
    }

    /// Kill everything left in the session, remove its directories, and
    /// write `session.stop`.
    pub fn teardown(mut self, daemon: &Daemon, exited: &Exited) {
        self.accept.abort();
        // SAFETY: the sandbox leads its own process group (setsid).
        unsafe { libc::kill(-(self.pid as i32), libc::SIGKILL) };
        for p in &self.placeholders {
            launcher::fs_compile::remove_placeholder(p);
        }
        // A repository the session created below the root (Linux cannot
        // refuse it): renamed aside before anyone's git reads it (ADR-046).
        let id = self.id.as_str();
        let tag = &id[id.len().saturating_sub(8)..];
        let quarantined = launcher::fs_compile::quarantine_new_nested_git(&self.nested_git.0, &self.nested_git.1, tag);
        for g in &quarantined {
            eprintln!("brokerd: session {id} created a repository at {}: renamed aside (ADR-046)", g.display());
        }
        let _ = std::fs::remove_dir_all(&self.session_dir);
        let _ = std::fs::remove_dir_all(&self.session_tmp);
        if let Ok(mut s) = daemon.sessions.lock() {
            s.remove(self.id.as_str());
        }
        daemon.approvals.unregister(self.id.as_str());
        if let Some(c) = self.collector.take() {
            c.stop();
        }
        let ev = AuditEvent::new(EventKind::SessionStop)
            .attributed_as(&self.attribution)
            .detail("exit_code", exited.code.map(i64::from))
            .detail("exit_signal", exited.signal.map(i64::from))
            .detail("stats", self.stats.snapshot());
        let ev = if quarantined.is_empty() {
            ev
        } else {
            ev.detail("quarantined_git", quarantined.iter().map(|p| p.display().to_string()).collect::<Vec<_>>())
        };
        let _ = self.recorder.append(&ev);
    }
}

/// macOS only: on Linux the sandbox is a PID namespace whose init dies with
/// bwrap (`--unshare-pid --die-with-parent`), which this unit test does not
/// model; Seatbelt has no such container.
#[cfg(all(test, target_os = "macos"))]
mod review_tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    struct NoBackend;
    impl launcher::SandboxBackend for NoBackend {
        fn name(&self) -> &'static str {
            "test"
        }
        fn probe(&self) -> anyhow::Result<launcher::BackendReport> {
            Ok(Default::default())
        }
        fn launch(&self, _: launcher::SandboxSpec) -> anyhow::Result<launcher::SandboxHandle> {
            anyhow::bail!("no backend in this test")
        }
    }

    /// Review (TB2, I9, Broker CLI and Daemon "Supervisor: on session.stop
    /// or agent exit it kills the tree"): teardown, and the CLI-gone path in
    /// `Server::session`, kill only the sandbox's process group
    /// (`kill(-pid)`). Nothing stops a sandboxed process from calling
    /// `setsid()` (Seatbelt does not mediate it; checked with
    /// `sandbox-exec` and a deny-default profile allowing only
    /// process-fork/exec, file-read, signal and process-info within the
    /// sandbox). Such a process outlives its session on macOS: still holding
    /// the user's terminal (fds 0-2, readable because it is not its
    /// controlling terminal) and write access to the repository and agent
    /// state, after `session.stop` is on record and the kernel-denial
    /// collector has stopped. Here the agent is started as
    /// `spawn_with_status` starts it (leader of its own session), forks a
    /// child that calls `setsid()`, and the session is torn down.
    #[tokio::test]
    async fn review_teardown_kills_sandboxed_processes_that_left_the_group() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let dirs = crate::dirs::BrokerDirs::rooted(&root.join("broker"));
        dirs.ensure().unwrap();
        std::fs::create_dir_all(root.join("repo")).unwrap();
        let rec = Arc::new(audit::SqliteRecorder::open(&dirs.audit_db()).unwrap());
        let daemon = Daemon::new(
            dirs,
            rec.clone(),
            Arc::new(NoBackend),
            Arc::new(netguard::resolver::SystemResolver::new()),
            "/nonexistent/broker-sandbox-shim".into(),
        );
        let pidfile = root.join("escaped.pid");
        let script = format!(
            "use POSIX; if (fork() == 0) {{ POSIX::setsid(); open(my $f, '>', '{}.tmp'); print $f $$; close $f; \
             rename('{0}.tmp', '{0}'); sleep 30; exit 0 }} sleep 30;",
            pidfile.display()
        );
        let mut cmd = std::process::Command::new("/usr/bin/perl");
        cmd.arg("-e").arg(script);
        // SAFETY: setsid is async-signal-safe (as in launcher's spawn_with_status).
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !pidfile.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let escaped: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let id = audit::SessionId::new();
        let mut running = Running {
            id: id.clone(),
            result: Default::default(),
            pid: child.id(),
            child: Some(child),
            accept: tokio::spawn(async {}),
            session_dir: root.join("session"),
            session_tmp: root.join("tmp"),
            placeholders: vec![],
            stats: Default::default(),
            recorder: rec.clone(),
            attribution: AuditEvent::new(EventKind::SessionStart).session(&id),
            collector: None,
            nested_git: (root.join("repo"), vec![]),
        };
        let mut child = running.take_child().unwrap();
        running.teardown(&daemon, &Exited::default());
        let _ = child.wait();
        tokio::time::sleep(Duration::from_millis(500)).await;
        // SAFETY: plain kill(2) probes and cleanup.
        let alive = unsafe { libc::kill(escaped, 0) } == 0;
        if alive {
            unsafe { libc::kill(escaped, libc::SIGKILL) };
        }
        assert!(
            !alive,
            "process {escaped} of session {id} called setsid() and is still running after teardown wrote session.stop"
        );
    }
}
