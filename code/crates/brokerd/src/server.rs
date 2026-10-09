//! The `ctl.sock` server: accept, check the peer's UID, dispatch.

use crate::proto::{self, Request, StartParams, codes};
use crate::session::Daemon;
use crate::session_util::exited_from;
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
                    // A held login keeps the daemon (and so the login) alive.
                    if self.daemon.busy_sessions() > 0
                        || self.open_conns.load(Ordering::SeqCst) > 0
                        || self.daemon.logins.held()
                    {
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
        // Sessions end with the daemon, on the record: never a sandbox left
        // running without its proxy and without `session.stop`.
        self.end_sessions(Duration::from_secs(10)).await;
        Ok(())
    }

    /// Kill every running session (again as starting ones register) until
    /// none is left or `grace` has passed; each session's task writes its
    /// `session.stop` as it tears down.
    async fn end_sessions(&self, grace: Duration) {
        let deadline = Instant::now() + grace;
        while self.daemon.busy_sessions() > 0 && Instant::now() < deadline {
            self.daemon.kill_all_sessions();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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
                if d.busy_sessions() > 0 {
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
            "audit.query" => match crate::audit_query::parse(&req.params) {
                Ok(q) => match d.recorder.query_filtered(&q) {
                    Ok(rows) => proto::ok(
                        id,
                        rows.into_iter()
                            .map(|e| json!({"seq": e.seq, "hash": e.hash.to_hex(), "event": e.event}))
                            .collect::<Vec<_>>(),
                    ),
                    Err(e) => proto::err(id, codes::NOT_FOUND, format!("{e:#}"), None),
                },
                Err(e) => proto::err(id, codes::INVALID_PARAMS, e, None),
            },
            "login.start" => match crate::login::start(d).await {
                Ok(v) => proto::ok(id, v),
                Err(e) => proto::err(id, codes::INVALID_PARAMS, e, None),
            },
            "login.wait" => {
                let lid = req.params.get("login_id").and_then(Value::as_str).unwrap_or_default();
                match crate::login::wait(d, lid).await {
                    Ok(v) => proto::ok(id, v),
                    Err(e) => proto::err(id, codes::INVALID_PARAMS, e, None),
                }
            }
            "login.status" => proto::ok(id, crate::login::status(d)),
            "approval.list" => proto::ok(id, crate::approvals::list_json(d)),
            "approval.grant" => match crate::approvals::grant_json(d, &req.params) {
                Ok(v) => proto::ok(id, v),
                Err(e) => proto::err(id, codes::NOT_FOUND, e, None),
            },
            "login.logout" => proto::ok(id, json!({ "signed_out": crate::login::logout(d) })),
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
                // A refused start is on record however it was refused (I9).
                let message = format!("invalid session.start parameters: {e}");
                self.daemon.refuse(&audit::SessionId::new(), "", &message, &[]);
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
        let mut input = BufReader::new(tokio::io::AsyncReadExt::chain(std::io::Cursor::new(rest), rd));
        let mut partial = Vec::new();
        let mut client_gone = false;
        let exited = loop {
            tokio::select! {
                ex = &mut rx => break ex.unwrap_or_default(),
                line = next_message(&mut input, &mut partial), if !client_gone => match line {
                    Some(l) => {
                        if let Ok(r) = serde_json::from_slice::<Request>(&l) {
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
                    None => {
                        // The CLI went away (or broke the protocol): the
                        // session goes with it.
                        client_gone = true;
                        running.kill_all();
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

/// Most bytes in one control message after `session.start` (signals and
/// `session.stop` are tiny); the first is bounded by `read_first`.
const MAX_MESSAGE: u64 = 64 * 1024;

/// The next newline-terminated message from the session's client, or `None`
/// at end of input, on an error, or past [`MAX_MESSAGE`]. Cancel-safe: a
/// message read in part stays in `partial` for the next call.
async fn next_message<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R, partial: &mut Vec<u8>) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    loop {
        let budget = (MAX_MESSAGE + 1).saturating_sub(partial.len() as u64);
        let n = (&mut *r).take(budget).read_until(b'\n', partial).await.ok()?;
        if partial.last() == Some(&b'\n') {
            return Some(std::mem::take(partial));
        }
        if n == 0 || partial.len() as u64 > MAX_MESSAGE {
            return None;
        }
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

#[cfg(test)]
mod review_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

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

    async fn send(server: &Arc<Server>, line: &str) -> String {
        let (mut client, conn) = UnixStream::pair().unwrap();
        client.write_all(line.as_bytes()).await.unwrap();
        server.clone().handle(conn).await.unwrap();
        let mut out = String::new();
        client.read_to_string(&mut out).await.unwrap();
        out
    }

    /// Review (I9 "launch refusal", Broker CLI and Daemon: "any error in
    /// Starting goes straight to Closed with a `launch_refused` audit
    /// event"; I2): a `session.start` the daemon refuses is on the record
    /// when its parameters parse (here: no stdio descriptors), but one
    /// whose parameters do not parse is answered INVALID_PARAMS in
    /// `Server::session` before `Daemon::start`, and no row records that a
    /// launch was asked for and refused.
    #[tokio::test]
    async fn review_every_refused_session_start_is_logged() {
        let d = tempfile::tempdir().unwrap();
        let dirs = crate::dirs::BrokerDirs::rooted(&d.path().canonicalize().unwrap());
        dirs.ensure().unwrap();
        let rec = Arc::new(audit::SqliteRecorder::open(&dirs.audit_db()).unwrap());
        let daemon = Arc::new(Daemon::new(
            dirs,
            rec.clone(),
            Arc::new(NoBackend),
            Arc::new(netguard::resolver::SystemResolver::new()),
            "/nonexistent/broker-sandbox-shim".into(),
        ));
        let server = Server::new(daemon, Duration::from_secs(60));
        let a = send(&server, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"session.start\",\"params\":{\"argv\":[\"claude\"],\"cwd\":\"/\"}}\n").await;
        let b = send(&server, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"session.start\",\"params\":{\"argv\":\"claude\",\"cwd\":\"/\"}}\n").await;
        assert!(a.contains("\"error\"") && b.contains("\"error\""), "both refused: {a} {b}");
        let q = audit::Query { kind: Some(audit::EventKind::LaunchRefused), limit: 10, ..Default::default() };
        let rows = rec.query_filtered(&q).unwrap();
        assert_eq!(
            rows.len(),
            2,
            "two session.start requests were refused, {} launch_refused row(s) on record; the unrecorded refusal \
             answered: {b}",
            rows.len()
        );
    }

    fn server() -> (tempfile::TempDir, Arc<Server>) {
        let d = tempfile::tempdir().unwrap();
        let dirs = crate::dirs::BrokerDirs::rooted(&d.path().canonicalize().unwrap());
        dirs.ensure().unwrap();
        let rec = Arc::new(audit::SqliteRecorder::open(&dirs.audit_db()).unwrap());
        let daemon = Arc::new(Daemon::new(
            dirs,
            rec,
            Arc::new(NoBackend),
            Arc::new(netguard::resolver::SystemResolver::new()),
            "/nonexistent/broker-sandbox-shim".into(),
        ));
        (d, Server::new(daemon, Duration::from_secs(60)))
    }

    /// Review note: `daemon.shutdown` raced a session still starting (only
    /// registered sessions were counted) and left its sandbox behind.
    #[tokio::test]
    async fn shutdown_waits_for_a_starting_session() {
        let (_d, server) = server();
        server.daemon.starting.fetch_add(1, Ordering::SeqCst);
        let r = send(&server, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"daemon.shutdown\"}\n").await;
        assert!(r.contains("sessions are running"), "{r}");
        server.daemon.starting.fetch_sub(1, Ordering::SeqCst);
        let r = send(&server, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"daemon.shutdown\"}\n").await;
        assert!(r.contains("stopping"), "{r}");
    }

    /// Review note: a daemon stopped by SIGTERM left running sandboxes
    /// without a proxy. On the way out it kills every session.
    #[tokio::test]
    async fn the_daemon_ends_its_sessions_when_it_stops() {
        use std::os::unix::process::CommandExt;
        let (d, server) = server();
        let mut c = std::process::Command::new("/bin/sleep");
        c.arg("30");
        // SAFETY: setsid is async-signal-safe (as the launcher starts a sandbox).
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let mut child = c.spawn().unwrap();
        server.daemon.sessions.lock().unwrap().insert("s1".into(), (child.id(), d.path().to_path_buf()));
        server.end_sessions(Duration::from_millis(300)).await;
        let ended = child.try_wait().unwrap().is_some() || {
            std::thread::sleep(Duration::from_millis(200));
            child.try_wait().unwrap().is_some()
        };
        let _ = child.kill();
        let _ = child.wait();
        assert!(ended, "a session's sandbox outlived the daemon");
    }

    /// Review note: messages after `session.start` had no size limit.
    #[tokio::test]
    async fn control_messages_are_bounded() {
        let mut big = vec![b'x'; MAX_MESSAGE as usize + 10];
        big.push(b'\n');
        let input = [b"{\"a\":1}\n".as_slice(), &big, b"{\"b\":2}\n"].concat();
        let mut r = BufReader::new(std::io::Cursor::new(input));
        let mut partial = Vec::new();
        assert_eq!(next_message(&mut r, &mut partial).await.as_deref(), Some(b"{\"a\":1}\n".as_slice()));
        assert_eq!(next_message(&mut r, &mut partial).await, None, "an oversized message ends the conversation");
        assert!(partial.len() as u64 <= MAX_MESSAGE + 1, "and was never buffered whole");
    }
}
