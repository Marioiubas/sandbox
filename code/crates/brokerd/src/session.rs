//! Session start, supervision and teardown (Request and Session Lifecycle,
//! steps 1, 2 and 6). Any failure while starting refuses the launch, writes
//! a `launch_refused` event naming what was missing, and never runs the agent.

use crate::dirs::{BrokerDirs, passwd_user};
use crate::pipeline::{PipelineCtx, Stats};
use crate::proto::{StartParams, StartResult};
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

mod assemble;
mod launch;
mod mcp_launch;
mod running;

pub use mcp_launch::McpProcess;

use assemble::Assembled;
use running::{Listener, accept_loop};

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
    /// Identity token issuers' key sets (M3 CI identity).
    pub jwks: crate::identity::JwksCache,
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
            jwks: Default::default(),
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

        // Identity: a verified token names the session; an unverifiable one
        // refuses it (never a silent fall-back to the local user).
        let identity = match params.identity_token.as_ref().filter(|t| !t.0.is_empty()) {
            None => None,
            Some(t) => {
                let user_policy = load_user_policy(&self.dirs)?;
                let mut roots = Vec::new();
                for r in &user_policy.tls.extra_roots {
                    let p = if r.starts_with('/') { PathBuf::from(r) } else { self.dirs.config_dir.join(r) };
                    roots.extend(tls::trust_bundle::load_pem_certs(&p)?);
                }
                let id = crate::identity::verify(&self.jwks, &self.dirs, &user_policy, &roots, &t.0)
                    .await
                    .map_err(|e| format!("identity token rejected: {e}"))?;
                Some(id)
            }
        };
        let assembled = self.assemble_policy(id, &params, &cwd, &user.name, identity)?;
        self.start_assembled(id, params, cwd, &home, &user.name, assembled, stdio).await
    }

    /// Launch a session whose policy layers are already assembled.
    #[allow(clippy::too_many_arguments)]
    async fn start_assembled(
        self: &Arc<Self>,
        id: &SessionId,
        params: StartParams,
        cwd: PathBuf,
        home: &Path,
        username: &str,
        assembled: Assembled,
        stdio: [OwnedFd; 3],
    ) -> Result<Running, StartFailure> {
        let Assembled { profile, user_policy, egress, shadow, grants, warnings, identity } = assembled;

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
                home,
                username,
                &session_dir,
                &session_tmp,
                platform_tmp,
                stdio,
                grants,
                warnings,
                shadow,
                identity,
            )
            .await;
        if result.is_err() {
            cleanup_dirs("refused");
        }
        result
    }
}
