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
