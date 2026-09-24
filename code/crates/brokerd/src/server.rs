//! The `ctl.sock` server: accept, check the peer's UID, dispatch.

use crate::proto::{self, Request, StartParams, codes};
use crate::session::{Daemon, exited_from};
use serde_json::{Value, json};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Interest};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

pub struct Server {
    pub daemon: Arc<Daemon>,
    pub idle_exit: Duration,
    shutdown: Notify,
    open_conns: AtomicUsize,
}

impl Server {
    pub fn new(daemon: Arc<Daemon>, idle_exit: Duration) -> Arc<Self> {
        Arc::new(Server { daemon, idle_exit, shutdown: Notify::new(), open_conns: AtomicUsize::new(0) })
    }

    pub fn bind(&self) -> anyhow::Result<UnixListener> {
        use std::os::unix::fs::PermissionsExt;
        let sock = self.daemon.dirs.ctl_sock();
        if sock.as_os_str().len() > 100 {
            anyhow::bail!("control socket path too long for a Unix socket: {}", sock.display());
        }
        if sock.exists() {
            if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
                anyhow::bail!("another brokerd is already listening on {}", sock.display());
            }
            std::fs::remove_file(&sock)?;
        }
        let l = UnixListener::bind(&sock)?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
        std::fs::write(self.daemon.dirs.run_dir.join("brokerd.pid"), std::process::id().to_string())?;
        Ok(l)
    }

    pub async fn run(self: Arc<Self>, listener: UnixListener) -> anyhow::Result<()> {
        let my_uid = nix::unistd::getuid().as_raw();
        let mut last_busy = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        loop {
            tokio::select! {
                acc = listener.accept() => {
                    let Ok((stream, _)) = acc else { continue };
                    match stream.peer_cred() {
                        Ok(c) if c.uid() == my_uid => {}
                        other => {
                            eprintln!("brokerd: rejected ctl connection from peer {other:?}");
                            continue;
                        }
                    }
                    let me = self.clone();
                    me.open_conns.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        if let Err(e) = me.clone().handle(stream).await {
                            eprintln!("brokerd: ctl connection error: {e:#}");
                        }
                        me.open_conns.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                _ = tick.tick() => {
                    if self.daemon.active_sessions() > 0 || self.open_conns.load(Ordering::SeqCst) > 0 {
                        last_busy = Instant::now();
                    } else if last_busy.elapsed() >= self.idle_exit {
                        break;
                    }
                }
                _ = self.shutdown.notified() => break,
                _ = term.recv() => break,
            }
        }
        let _ = std::fs::remove_file(self.daemon.dirs.ctl_sock());
        let _ = std::fs::remove_file(self.daemon.dirs.run_dir.join("brokerd.pid"));
        Ok(())
    }

    async fn handle(self: Arc<Self>, stream: UnixStream) -> anyhow::Result<()> {
        let (line, fds, rest) = read_first(&stream).await?;
        let req: Request = match serde_json::from_slice(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = proto::err(Value::Null, codes::PARSE_ERROR, format!("bad request: {e}"), None);
                let mut s = stream;
                s.write_all(&proto::to_line(&resp)).await?;
                return Ok(());
            }
        };
        let id = req.id.clone().unwrap_or(Value::Null);
        if req.method == "session.start" {
            return self.session(stream, id, req.params, fds, rest).await;
        }
        drop(fds);
        let resp = self.one_shot(id, &req).await;
        let mut s = stream;
        s.write_all(&proto::to_line(&resp)).await?;
        Ok(())
    }

    async fn one_shot(&self, id: Value, req: &Request) -> proto::Response {
        let d = &self.daemon;
        match req.method.as_str() {
            "daemon.status" => proto::ok(
                id,
                json!({"pid": std::process::id(), "version": env!("CARGO_PKG_VERSION"), "sessions": d.active_sessions(),
                       "backend": d.backend.name(), "audit_db": d.dirs.audit_db()}),
            ),
            "daemon.shutdown" => {
                if d.active_sessions() > 0 {
                    proto::err(id, codes::BUSY, "sessions are running", None)
                } else {
                    self.shutdown.notify_one();
                    proto::ok(id, json!({"stopping": true}))
                }
            }
            "doctor" => match d.backend.probe() {
                Ok(r) => proto::ok(id, r),
                Err(e) => proto::err(id, codes::LAUNCH_REFUSED, format!("{e:#}"), None),
            },
            "audit.verify" => match d.recorder.verify() {
                Ok(n) => proto::ok(id, json!({"ok": true, "events": n})),
                Err(e) => proto::ok(id, json!({"ok": false, "error": e.to_string()})),
            },
            "decision.explain" => {
                let rid = req.params.get("request_id").and_then(Value::as_str).unwrap_or_default().to_string();
                match audit::RequestId::try_from(rid) {
                    Ok(r) => match d.recorder.by_request(&r) {
                        Ok(evs) if !evs.is_empty() => proto::ok(
                            id,
                            evs.into_iter()
                                .map(|e| json!({"seq": e.seq, "hash": e.hash.to_hex(), "event": e.event}))
                                .collect::<Vec<_>>(),
                        ),
                        Ok(_) => proto::err(id, codes::NOT_FOUND, "no decision with that request id", None),
                        Err(e) => proto::err(id, codes::NOT_FOUND, format!("{e:#}"), None),
                    },
                    Err(e) => proto::err(id, codes::INVALID_PARAMS, e, None),
                }
            }
            other => proto::err(id, codes::METHOD_NOT_FOUND, format!("unknown method {other}"), None),
        }
    }

    async fn session(
        self: Arc<Self>,
        stream: UnixStream,
        id: Value,
        params: Value,
        fds: Vec<OwnedFd>,
        rest: Vec<u8>,
    ) -> anyhow::Result<()> {
        let (rd, mut wr) = stream.into_split();
        let params: StartParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                wr.write_all(&proto::to_line(&proto::err(id, codes::INVALID_PARAMS, e.to_string(), None))).await?;
                return Ok(());
            }
        };
        let mut running = match self.daemon.start(params, fds).await {
            Ok(r) => r,
            Err(f) => {
                let resp = proto::err(
                    id,
                    codes::LAUNCH_REFUSED,
                    f.message,
                    Some(json!({"reason": "launch_refused", "layers": f.layers})),
                );
                wr.write_all(&proto::to_line(&resp)).await?;
                return Ok(());
            }
        };
        wr.write_all(&proto::to_line(&proto::ok(id, &running.result))).await?;

        let mut child = running.take_child().expect("child present after start");
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let st = child.wait();
            let _ = tx.send(exited_from(st));
        });
        let mut lines = BufReader::new(tokio::io::AsyncReadExt::chain(std::io::Cursor::new(rest), rd)).lines();
        let mut client_gone = false;
        let exited = loop {
            tokio::select! {
                ex = &mut rx => break ex.unwrap_or_default(),
                line = lines.next_line(), if !client_gone => match line {
                    Ok(Some(l)) => {
                        if let Ok(r) = serde_json::from_str::<Request>(&l) {
                            match r.method.as_str() {
                                "session.signal" => {
                                    if let Some(sig) = r.params.get("signal").and_then(Value::as_str) {
                                        running.signal(sig);
                                    }
                                }
                                "session.stop" => running.signal("TERM"),
                                _ => {}
                            }
                        }
                    }
                    _ => {
                        // The CLI went away: the session goes with it.
                        client_gone = true;
                        unsafe { libc::kill(-(running.pid as i32), libc::SIGKILL) };
                    }
                },
            }
        };
        // Tear down and flush `session.stop` before reporting the exit, so the
        // record is complete by the time `broker run` returns.
        running.teardown(&self.daemon, &exited);
        if !client_gone {
            let _ = wr.write_all(&proto::to_line(&proto::notification("session.exited", &exited))).await;
        }
        Ok(())
    }
}

/// Read the first request line, collecting any `SCM_RIGHTS` descriptors.
async fn read_first(stream: &UnixStream) -> anyhow::Result<(Vec<u8>, Vec<OwnedFd>, Vec<u8>)> {
    let mut data = Vec::new();
    let mut fds = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(nl) = data.iter().position(|b| *b == b'\n') {
            let rest = data.split_off(nl + 1);
            data.pop();
            return Ok((data, fds, rest));
        }
        if data.len() > proto::MAX_LINE {
            anyhow::bail!("request line too long");
        }
        tokio::time::timeout_at(deadline, stream.readable()).await??;
        let mut buf = vec![0u8; 64 * 1024];
        match stream.try_io(Interest::READABLE, || proto::recv_with_fds(stream.as_raw_fd(), &mut buf)) {
            Ok((0, _)) => anyhow::bail!("client closed before sending a request"),
            Ok((n, mut f)) => {
                data.extend_from_slice(&buf[..n]);
                fds.append(&mut f);
                if fds.len() > 8 {
                    anyhow::bail!("too many file descriptors");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
