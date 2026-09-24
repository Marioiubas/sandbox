//! Session start, supervision and teardown (Request and Session Lifecycle,
//! steps 1, 2 and 6). Any failure while starting refuses the launch, writes
//! a `launch_refused` event naming what was missing, and never runs the agent.

use crate::dirs::{BrokerDirs, passwd_user};
use crate::pipeline::{self, PipelineCtx, Stats};
use crate::profiles;
use crate::proto::{Exited, StartParams, StartResult};
use crate::session_util::*;
use audit::{AuditEvent, EventKind, Reason, Recorder, SessionId, SqliteRecorder};
use launcher::{EgressEndpoint, FsInputs, LayerStatus, SandboxBackend, SandboxSpec};
use netguard::ingress::ChannelAuth;
use netguard::resolver::PolicyResolver;
use policy::{EgressPolicy, PolicyFile};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Every grant expires with its task (the `task-expiry` forbid).
pub const TASK_LIFETIME_SECS: i64 = 24 * 3600;

pub struct Daemon {
    pub dirs: BrokerDirs,
    pub recorder: Arc<SqliteRecorder>,
    pub backend: Arc<dyn SandboxBackend>,
    pub resolver: Arc<dyn PolicyResolver>,
    pub shim: PathBuf,
    pub sessions: Mutex<HashMap<String, u32>>,
    hash_cache: Mutex<HashMap<(PathBuf, u64, i64, u64), String>>,
}

impl Daemon {
    pub fn new(
        dirs: BrokerDirs,
        recorder: Arc<SqliteRecorder>,
        backend: Arc<dyn SandboxBackend>,
        resolver: Arc<dyn PolicyResolver>,
        shim: PathBuf,
    ) -> Self {
        Daemon {
            dirs,
            recorder,
            backend,
            resolver,
            shim,
            sessions: Mutex::new(HashMap::new()),
            hash_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn active_sessions(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }
}

#[derive(Debug)]
pub struct StartFailure {
    pub message: String,
    pub layers: Vec<LayerStatus>,
}

impl<E: std::fmt::Display> From<E> for StartFailure {
    fn from(e: E) -> Self {
        StartFailure { message: e.to_string(), layers: vec![] }
    }
}

pub struct Running {
    pub id: SessionId,
    pub result: StartResult,
    pub pid: u32,
    child: Option<std::process::Child>,
    accept: tokio::task::JoinHandle<()>,
    session_dir: PathBuf,
    session_tmp: PathBuf,
    placeholders: Vec<PathBuf>,
    stats: Arc<Stats>,
    recorder: Arc<SqliteRecorder>,
    backend_name: String,
    agent: String,
    enduser: String,
}

impl Daemon {
    fn hash_binary(&self, p: &Path) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(p).ok()?;
        let key = (p.to_path_buf(), m.ino(), m.mtime(), m.size());
        if let Some(h) = self.hash_cache.lock().ok()?.get(&key) {
            return Some(h.clone());
        }
        if m.size() > 1 << 30 {
            return None;
        }
        let mut f = std::fs::File::open(p).ok()?;
        let mut h = Sha256::new();
        std::io::copy(&mut f, &mut h).ok()?;
        let hex = hex::encode(h.finalize());
        self.hash_cache.lock().ok()?.insert(key, hex.clone());
        Some(hex)
    }
}

impl Daemon {
    fn refuse(&self, id: &SessionId, agent: &str, message: &str, layers: &[LayerStatus]) {
        let mut ev = AuditEvent::new(EventKind::LaunchRefused)
            .session(id)
            .deny(Reason::LaunchRefused, vec![])
            .detail("message", message)
            .detail("layers", serde_json::to_value(layers).unwrap_or_default());
        ev.agent = Some(agent.to_string());
        ev.sandbox = Some(self.backend.name().to_string());
        let _ = self.recorder.append(&ev);
    }

    pub async fn start(self: &Arc<Self>, params: StartParams, fds: Vec<OwnedFd>) -> Result<Running, StartFailure> {
        let id = SessionId::new();
        let argv0 = params.argv.first().cloned().unwrap_or_default();
        let r = self.start_inner(&id, params, fds).await;
        if let Err(f) = &r {
            self.refuse(&id, &argv0, &f.message, &f.layers);
        }
        r
    }

    async fn start_inner(
        self: &Arc<Self>,
        id: &SessionId,
        params: StartParams,
        fds: Vec<OwnedFd>,
    ) -> Result<Running, StartFailure> {
        if params.argv.is_empty() {
            return Err("no command given".into());
        }
        let stdio: [OwnedFd; 3] = fds.try_into().map_err(|_| "session.start needs exactly 3 file descriptors")?;
        let cwd = PathBuf::from(&params.cwd);
        if !cwd.is_absolute() {
            return Err("cwd must be absolute".into());
        }
        let cwd = cwd.canonicalize().map_err(|e| format!("cwd {}: {e}", params.cwd))?;
        let user = passwd_user()?;
        let home = user.dir.clone();

        // Policy: built-in profile + user layer (repo layers wait for M2's
        // hash approval and narrowing gate: I4, I5).
        let profile = match &params.profile {
            Some(p) => profiles::by_name(p)?,
            None => profiles::detect(&params.argv[0])?,
        };
        let user_policy = load_user_policy(&self.dirs)?;
        let scope = format!("profile:{}", profile.name);
        // `${repo_remote}` comes from the checkout's own config file, read
        // without running git; unresolved, rules that use it grant nothing.
        let repo_remote = origin_remote(&repo_root(&cwd));
        let mode = match params.mode.as_deref() {
            None | Some("enforce") => policy::cedar::Mode::Enforce,
            Some("record") => policy::cedar::Mode::Record,
            Some(m) => return Err(format!("unknown session mode {m:?}").into()),
        };
        let agent_path = resolve_command(&params.argv[0], params.env.get("PATH").map(String::as_str), &cwd);
        let agent_base = std::path::Path::new(&params.argv[0])
            .file_name()
            .map(|b| b.to_string_lossy().into_owned())
            .unwrap_or_else(|| params.argv[0].clone());
        // The principal of every decision: the Task, carrying user and agent.
        let session_info = policy::cedar::SessionInfo {
            session_id: id.to_string(),
            task_id: format!("task-{id}"),
            user: format!("local:{}", user.name),
            agent: agent_base,
            agent_sha256: agent_path.as_deref().and_then(|p| self.hash_binary(p)).unwrap_or_default(),
            repo: repo_remote.as_ref().map(|r| format!("{}/{}", r.owner(), r.name())).unwrap_or_default(),
            branch_prefix: "agent/".into(),
            expires_at: policy::cedar::entities::now_epoch() + TASK_LIFETIME_SECS,
            mode,
        };
        let compile_env = policy::CompileEnv {
            repo_remote,
            github_app_issuers: user_policy.issuers.github_app.keys().cloned().collect(),
            session: session_info,
        };
        let egress = EgressPolicy::compile_with(
            [(scope.as_str(), profile.egress.as_slice()), ("user", user_policy.egress.as_slice())],
            &compile_env,
        )?;
        let grants: Vec<String> =
            egress.grants().iter().map(|g| format!("{} {}:{:?}", g.id, g.pattern, g.ports)).collect();
        let mut warnings = Vec::new();
        if egress.is_empty() {
            warnings.push("no egress grants: every network request will be denied (empty lists deny)".into());
        }
        if compile_env.repo_remote.is_none()
            && egress.credentials().iter().any(|c| matches!(c.kind, policy::CredKind::GitHubApp { .. }))
        {
            warnings.push("no origin remote found: rules using ${repo_remote} grant nothing in this session".into());
        }

        // Session directories.
        let session_dir = self.dirs.sessions_dir().join(id.as_str());
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&session_dir)?;
        }
        #[cfg(target_os = "macos")]
        let platform_tmp = darwin_user_temp_dir();
        #[cfg(not(target_os = "macos"))]
        let platform_tmp: Option<PathBuf> = None;
        let tmp_base = platform_tmp.clone().unwrap_or_else(std::env::temp_dir);
        let session_tmp = tmp_base.join(format!("broker-{}", id.as_str()));
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&session_tmp)?;
        }
        let cleanup_dirs = |_: &str| {
            let _ = std::fs::remove_dir_all(&session_dir);
            let _ = std::fs::remove_dir_all(&session_tmp);
        };

        let result = self
            .launch(
                id,
                &params,
                &profile,
                &user_policy,
                egress,
                &cwd,
                &home,
                &user.name,
                &session_dir,
                &session_tmp,
                platform_tmp,
                stdio,
                grants,
                warnings,
            )
            .await;
        if result.is_err() {
            cleanup_dirs("refused");
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn launch(
        self: &Arc<Self>,
        id: &SessionId,
        params: &StartParams,
        profile: &policy::ProfileFile,
        user_policy: &PolicyFile,
        egress: EgressPolicy,
        cwd: &Path,
        home: &Path,
        username: &str,
        session_dir: &Path,
        session_tmp: &Path,
        platform_tmp: Option<PathBuf>,
        stdio: [OwnedFd; 3],
        grants: Vec<String>,
        warnings: Vec<String>,
    ) -> Result<Running, StartFailure> {
        // Filesystem policy.
        let mut extra_write = Vec::new();
        for s in &profile.agent.state_write {
            let p = expand_profile_path(s, home, cwd);
            if !p.exists() {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&p)?;
            }
            extra_write.push(p);
        }
        for w in profile.filesystem.write.iter().chain(&user_policy.filesystem.write) {
            extra_write.push(expand_home(w, home));
        }
        let path_var = params.env.get("PATH").cloned();
        let fs = launcher::fs_compile::compile(&FsInputs {
            home: home.to_path_buf(),
            repo: repo_root(cwd),
            session_tmp: session_tmp.to_path_buf(),
            platform_tmp,
            extra_write,
            extra_deny_read: profile
                .filesystem
                .deny_read
                .iter()
                .chain(&user_policy.filesystem.deny_read)
                .map(|p| expand_home(p, home))
                .collect(),
            agent_config_readonly: profile.agent.config_readonly.iter().map(|p| expand_home(p, home)).collect(),
            path_dirs: path_var.as_deref().unwrap_or("").split(':').map(PathBuf::from).collect(),
            broker_dirs: self.dirs.all(),
            install_dir: self.shim.parent().map(Path::to_path_buf),
        })?;

        let faults = launcher::injected_faults();
        if faults.iter().any(|f| f == "proxy") {
            return Err("egress proxy listener unavailable (fault injected)".into());
        }
        // Data channel: per-session UDS on Linux, loopback port + sentinel on macOS.
        let (egress_ep, listener, auth, proxy_url, socks_url) = if cfg!(target_os = "linux") {
            let sock = session_dir.join("data.sock");
            let l = tokio::net::UnixListener::bind(&sock)?;
            let port = launcher::backends::linux::BRIDGE_PORT;
            (
                EgressEndpoint::Uds { path: sock, bridge_port: port },
                Listener::Unix(l),
                ChannelAuth::Implicit,
                format!("http://127.0.0.1:{port}"),
                format!("socks5h://127.0.0.1:{port}"),
            )
        } else {
            let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
            let port = l.local_addr()?.port();
            let sentinel = new_sentinel();
            (
                EgressEndpoint::Loopback(port),
                Listener::Tcp(l),
                ChannelAuth::Sentinel(sentinel.clone().into_bytes()),
                format!("http://broker:{sentinel}@127.0.0.1:{port}"),
                format!("socks5h://broker:{sentinel}@127.0.0.1:{port}"),
            )
        };

        // Environment: allowlist + proxy variables + sentinel; never the host env (I1).
        let mut env = BTreeMap::new();
        for (k, v) in &params.env {
            let allowed = ENV_ALLOW.contains(&k.as_str()) || profile.agent.env_passthrough.contains(k);
            if allowed && !policy::config::env_name_is_secretish(k) {
                env.insert(k.clone(), v.clone());
            }
        }
        env.insert("HOME".into(), home.display().to_string());
        env.insert("USER".into(), username.to_string());
        env.insert("LOGNAME".into(), username.to_string());
        env.insert("TMPDIR".into(), session_tmp.display().to_string());
        for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            env.insert(k.into(), proxy_url.clone());
        }
        for k in ["ALL_PROXY", "all_proxy"] {
            env.insert(k.into(), socks_url.clone());
        }
        env.insert("NODE_USE_ENV_PROXY".into(), "1".into());
        env.insert("BROKER_SESSION".into(), id.to_string());
        // SSH remotes become brokerable HTTPS (Git Smart-HTTP Adapter).
        env.insert("GIT_CONFIG_COUNT".into(), "2".into());
        env.insert("GIT_CONFIG_KEY_0".into(), "url.https://github.com/.insteadOf".into());
        env.insert("GIT_CONFIG_VALUE_0".into(), "git@github.com:".into());
        env.insert("GIT_CONFIG_KEY_1".into(), "url.https://github.com/.insteadof".into());
        env.insert("GIT_CONFIG_VALUE_1".into(), "ssh://git@github.com/".into());

        // M1: session CA, trust bundle and credential sentinels (never secrets).
        let channel_sentinel = match &auth {
            ChannelAuth::Sentinel(b) => Some(b.clone()),
            _ => None,
        };
        let l7 = crate::session_l7::setup(
            id,
            &egress,
            user_policy,
            &self.dirs,
            home,
            self.resolver.clone(),
            session_tmp,
            channel_sentinel,
        )
        .map_err(|e| format!("L7 setup: {e:#}"))?;
        for (k, v) in &l7.env {
            env.insert(k.clone(), v.clone());
        }

        let tty = tty_path(&stdio);
        let agent_path = resolve_command(&params.argv[0], path_var.as_deref(), cwd);
        let agent_sha = agent_path.as_deref().and_then(|p| self.hash_binary(p));
        let spec = SandboxSpec {
            session: id.to_string(),
            argv: params.argv.iter().map(Into::into).collect(),
            cwd: cwd.to_path_buf(),
            env,
            fs: fs.clone(),
            egress: egress_ep.clone(),
            ca_bundle: Some(l7.bundle.bundle_file.clone()),
            stdio,
            tty_path: tty,
            session_dir: session_dir.to_path_buf(),
            shim: self.shim.clone(),
        };

        // Start the data plane before the agent, so its first request has a
        // listener (I2); then launch, which verifies the layers from inside.
        let enduser = format!("local:{username}");
        let stats = Arc::new(Stats::default());
        let egress_mode = egress.mode().as_str();
        let ctx = Arc::new(PipelineCtx {
            session: id.clone(),
            enduser: enduser.clone(),
            agent: params.argv[0].clone(),
            sandbox: self.backend.name().to_string(),
            policy: Arc::new(egress),
            resolver: self.resolver.clone(),
            recorder: self.recorder.clone() as Arc<dyn Recorder>,
            auth,
            stats: stats.clone(),
            connect_timeout: Duration::from_secs(10),
            sni_timeout: Duration::from_secs(15),
            l7: Some(l7.ctx.clone()),
        });
        // Write-ahead (I9): the session is on record before the agent can run;
        // if the log cannot take it, the agent never starts (I2).
        let egress_desc = match &egress_ep {
            EgressEndpoint::Uds { path, bridge_port } => format!("uds {} via 127.0.0.1:{bridge_port}", path.display()),
            EgressEndpoint::Loopback(p) => format!("loopback 127.0.0.1:{p} (sentinel-authenticated)"),
            EgressEndpoint::Vsock(c, p) => format!("vsock {c}:{p}"),
        };
        let probe_layers = self.backend.probe().map(|r| r.layers).unwrap_or_default();
        let mut ev = AuditEvent::new(EventKind::SessionStart)
            .session(id)
            .detail("profile", profile.name.as_str())
            .detail("mode", egress_mode)
            .detail("argv0", params.argv[0].as_str())
            .detail("cwd", cwd.display().to_string())
            .detail("egress", egress_desc.as_str())
            .detail("grants", grants.clone())
            .detail("writable", fs.writable.iter().map(|p| p.display().to_string()).collect::<Vec<_>>())
            .detail("layers", serde_json::to_value(&probe_layers).unwrap_or_default())
            .detail("credentials", l7.credentials.clone())
            .detail("trust_bundle", tls::trust_bundle::describe(&l7.bundle));
        ev.enduser = Some(enduser.clone());
        ev.agent = Some(params.argv[0].clone());
        ev.agent_sha256 = agent_sha;
        ev.sandbox = Some(self.backend.name().to_string());
        ev.task = Some(format!("task-{}", id));
        if faults.iter().any(|f| f == "audit") || self.recorder.append(&ev).is_err() {
            return Err(StartFailure {
                message: "audit log unavailable; the session was not started".into(),
                layers: probe_layers,
            });
        }

        let accept = tokio::spawn(accept_loop(listener, ctx));
        let backend = self.backend.clone();
        let launched = tokio::task::spawn_blocking(move || backend.launch(spec)).await;
        let handle = match launched {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                accept.abort();
                let layers = match e.downcast_ref::<launcher::LaunchError>() {
                    Some(le) if !le.layers.is_empty() => le.layers.clone(),
                    _ => self.backend.probe().map(|r| r.layers).unwrap_or_default(),
                };
                return Err(StartFailure { message: format!("{e:#}"), layers });
            }
            Err(e) => {
                accept.abort();
                return Err(StartFailure { message: format!("launcher task failed: {e}"), layers: vec![] });
            }
        };

        // The layers as verified from inside the sandbox by the shim.
        let mut ready = AuditEvent::new(EventKind::SessionReady)
            .session(id)
            .detail("layers", serde_json::to_value(&handle.verified).unwrap_or_default());
        ready.enduser = Some(enduser.clone());
        ready.agent = Some(params.argv[0].clone());
        ready.sandbox = Some(self.backend.name().to_string());
        if self.recorder.append(&ready).is_err() {
            // I9: no audit, no session.
            let mut child = handle.child;
            unsafe { libc::kill(-(handle.pid as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            accept.abort();
            return Err(StartFailure { message: "audit log unavailable".into(), layers: handle.verified });
        }
        if let Ok(mut s) = self.sessions.lock() {
            s.insert(id.to_string(), handle.pid);
        }
        let result = StartResult {
            session_id: id.to_string(),
            backend: self.backend.name().to_string(),
            profile: profile.name.clone(),
            egress: egress_desc,
            grants,
            layers: handle.verified.clone(),
            warnings,
        };
        Ok(Running {
            id: id.clone(),
            result,
            pid: handle.pid,
            child: Some(handle.child),
            accept,
            session_dir: session_dir.to_path_buf(),
            session_tmp: session_tmp.to_path_buf(),
            placeholders: handle.placeholders,
            stats,
            recorder: self.recorder.clone(),
            backend_name: self.backend.name().to_string(),
            agent: params.argv[0].clone(),
            enduser,
        })
    }
}

enum Listener {
    Unix(tokio::net::UnixListener),
    Tcp(tokio::net::TcpListener),
}

async fn accept_loop(l: Listener, ctx: Arc<PipelineCtx>) {
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
