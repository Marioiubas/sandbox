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
    pub fn teardown(self, daemon: &Daemon, exited: &Exited) {
        self.accept.abort();
        // SAFETY: the sandbox leads its own process group (setsid).
        unsafe { libc::kill(-(self.pid as i32), libc::SIGKILL) };
        for p in &self.placeholders {
            let _ = std::fs::remove_dir(p);
        }
        let _ = std::fs::remove_dir_all(&self.session_dir);
        let _ = std::fs::remove_dir_all(&self.session_tmp);
        if let Ok(mut s) = daemon.sessions.lock() {
            s.remove(self.id.as_str());
        }
        let mut ev = AuditEvent::new(EventKind::SessionStop)
            .session(&self.id)
            .detail("exit_code", exited.code.map(i64::from))
            .detail("exit_signal", exited.signal.map(i64::from))
            .detail("stats", self.stats.snapshot());
        ev.enduser = Some(self.enduser);
        ev.agent = Some(self.agent);
        ev.sandbox = Some(self.backend_name);
        let _ = self.recorder.append(&ev);
    }
}
