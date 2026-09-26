//! L1 conformance harness.
//!
//! Each probe runs in a fresh `broker run` session with its own
//! `BROKER_HOME` (so its own brokerd and audit log), inside a throwaway git
//! repository. Probes are deterministic (see `conformance-probe`); every
//! out-of-policy probe has an in-policy control, and every deny must also be
//! found in the audit log with a reason.
//!
//! The broker binaries must be built first: `cargo build --workspace --bins`.

pub mod m1;

use audit::{AuditEvent, DecisionResult, Reason, SqliteRecorder};
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub struct Bins {
    pub broker: PathBuf,
    pub probe: PathBuf,
}

pub fn bins() -> Bins {
    let exe = std::env::current_exe().expect("test exe");
    let dir = exe.parent().and_then(Path::parent).expect("target dir").to_path_buf();
    let broker = dir.join("broker");
    for b in ["broker", "brokerd", "broker-sandbox-shim", "conformance-probe"] {
        assert!(dir.join(b).is_file(), "{} missing: run `cargo build --workspace --bins` first", dir.join(b).display());
    }
    Bins { broker, probe: dir.join("conformance-probe") }
}

#[derive(Debug)]
pub struct ProbeResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl ProbeResult {
    pub fn allowed(&self) -> bool {
        self.code == 0
    }
    pub fn denied(&self) -> bool {
        self.code == 10
    }
}

impl From<Output> for ProbeResult {
    fn from(o: Output) -> Self {
        ProbeResult {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }
}

pub struct Harness {
    pub home: tempfile::TempDir,
    pub repo: tempfile::TempDir,
    pub bins: Bins,
    pub daemon_env: Vec<(String, String)>,
}

/// Short-path directory outside the per-user temp dir (Unix socket path
/// limits; macOS sandboxes may write the per-user temp dir).
fn short_tmp(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new().prefix(prefix).tempdir_in("/tmp").expect("tempdir in /tmp")
}

impl Harness {
    pub fn new(config: &str) -> Self {
        Self::with_daemon_env(config, &[])
    }

    /// `daemon_env` reaches brokerd because `broker run` starts it on demand.
    pub fn with_daemon_env(config: &str, daemon_env: &[(&str, &str)]) -> Self {
        Self::custom(config, daemon_env, init_repo)
    }

    /// As `with_daemon_env`, with `init` preparing the session repository.
    pub fn custom(config: &str, daemon_env: &[(&str, &str)], init: impl FnOnce(&Path)) -> Self {
        let home = short_tmp("bkc.");
        std::fs::create_dir_all(home.path().join("config")).unwrap();
        std::fs::write(home.path().join("config/broker.toml"), config).unwrap();
        // Outside the macOS per-user temp dir, which sandboxes may write (ADR-016).
        let repo = short_tmp("repo.");
        init(repo.path());
        Harness {
            home,
            repo,
            bins: bins(),
            daemon_env: daemon_env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    pub fn repo_path(&self) -> PathBuf {
        self.repo.path().canonicalize().unwrap()
    }

    fn base_cmd(&self, profile: Option<&str>, argv: &[String], env: &[(&str, &str)]) -> Command {
        let mut c = Command::new(&self.bins.broker);
        c.arg("run");
        if let Some(p) = profile {
            c.arg("--profile").arg(p);
        }
        c.arg("--").args(argv);
        c.current_dir(self.repo.path())
            .env("BROKER_HOME", self.home.path())
            .env("BROKER_DAEMON_IDLE_SECS", "3")
            .stdin(Stdio::null());
        for (k, v) in &self.daemon_env {
            c.env(k, v);
        }
        for (k, v) in env {
            c.env(k, v);
        }
        c
    }

    /// Run `conformance-probe <args>` inside a session.
    pub fn probe(&self, args: &[&str]) -> ProbeResult {
        self.probe_with(None, args, &[])
    }

    pub fn probe_with(&self, profile: Option<&str>, args: &[&str], env: &[(&str, &str)]) -> ProbeResult {
        let mut argv = vec![self.bins.probe.display().to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        self.run_argv(profile, &argv, env)
    }

    pub fn run_argv(&self, profile: Option<&str>, argv: &[String], env: &[(&str, &str)]) -> ProbeResult {
        let out = self.base_cmd(profile, argv, env).output().expect("broker run");
        ProbeResult::from(out)
    }

    pub fn spawn_probe(&self, args: &[&str]) -> std::process::Child {
        let mut argv = vec![self.bins.probe.display().to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        self.base_cmd(None, &argv, &[]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
    }

    /// Start a shell script inside a session without waiting for it.
    pub fn spawn_sh(&self, script: &str) -> std::process::Child {
        let argv = ["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
        self.base_cmd(None, &argv, &[]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap()
    }

    pub fn events(&self) -> Vec<AuditEvent> {
        let db = self.home.path().join("state/audit.db");
        match SqliteRecorder::open_read_only(&db) {
            Ok(r) => r.tail(1_000_000).map(|v| v.into_iter().map(|s| s.event).collect()).unwrap_or_default(),
            Err(_) => vec![],
        }
    }

    pub fn deny_reasons(&self) -> Vec<Reason> {
        self.events()
            .into_iter()
            .filter(|e| matches!(&e.decision, Some(d) if d.result == DecisionResult::Deny))
            .filter_map(|e| e.reason)
            .collect()
    }

    pub fn verify_audit(&self) -> Result<u64, audit::VerifyError> {
        SqliteRecorder::verify_path(&self.home.path().join("state/audit.db"))
    }

    pub fn audit_db(&self) -> PathBuf {
        self.home.path().join("state/audit.db")
    }

    pub fn config_dir(&self) -> PathBuf {
        self.home.path().join("config")
    }

    /// A `file:` secret in the broker config dir (mode 0600), outside
    /// every sandbox mount.
    pub fn write_secret(&self, name: &str, value: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        let p = self.config_dir().join(name);
        std::fs::write(&p, value).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Rewrite broker.toml (for fixtures whose ports are known late).
    pub fn set_config(&self, config: &str) {
        std::fs::write(self.config_dir().join("broker.toml"), config).unwrap();
    }

    /// Run a shell script inside a session.
    pub fn sh(&self, script: &str) -> ProbeResult {
        self.run_argv(None, &["/bin/sh".to_string(), "-c".to_string(), script.to_string()], &[])
    }

    /// Any `broker` subcommand on the host (not in a session).
    pub fn broker(&self, args: &[&str]) -> ProbeResult {
        let mut c = Command::new(&self.bins.broker);
        c.args(args)
            .current_dir(self.repo.path())
            .env("BROKER_HOME", self.home.path())
            .env("BROKER_DAEMON_IDLE_SECS", "3")
            .stdin(Stdio::null());
        for (k, v) in &self.daemon_env {
            c.env(k, v);
        }
        ProbeResult::from(c.output().expect("broker"))
    }

    /// `broker why <id>` on the host.
    pub fn why(&self, rid: &str) -> String {
        let out = Command::new(&self.bins.broker)
            .args(["why", rid])
            .env("BROKER_HOME", self.home.path())
            .output()
            .expect("broker why");
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    }

    /// Raw bytes of the audit database files (the canary check reads them).
    pub fn audit_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{suffix}", self.audit_db().display()));
            if let Ok(b) = std::fs::read(p) {
                v.extend(b);
            }
        }
        v
    }
}

/// Request IDs (`req-...`) mentioned in text, in order.
pub fn request_ids(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("req-") {
        let id: String = rest[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
        if id.len() > 8 && !out.contains(&id) {
            out.push(id.clone());
        }
        rest = &rest[i + 4..];
    }
    out
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = Command::new(&self.bins.broker)
            .args(["daemon", "stop"])
            .env("BROKER_HOME", self.home.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

pub fn init_repo(p: &Path) {
    let ok = Command::new("git")
        .args(["init", "-q", "."])
        .current_dir(p)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        for d in [".git/hooks", ".git/objects", ".git/refs/heads"] {
            std::fs::create_dir_all(p.join(d)).unwrap();
        }
        std::fs::write(p.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(p.join(".git/config"), "[core]\n\trepositoryformatversion = 0\n").unwrap();
    }
    std::fs::create_dir_all(p.join(".git/hooks")).unwrap();
    std::fs::write(p.join("README.md"), "probe repo\n").unwrap();
}

/// A TLS-ish upstream: reads the first bytes and answers `UPSTREAM-OK`.
pub struct Upstream {
    pub port: u16,
    pub accepts: Arc<AtomicUsize>,
}

impl Upstream {
    pub fn start() -> Upstream {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let a = accepts.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                a.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = s.read(&mut buf)
                        && n > 0
                    {
                        let _ = s.write_all(b"UPSTREAM-OK");
                    }
                });
            }
        });
        Upstream { port, accepts }
    }
}

/// Host-side listeners that count anything that reaches them: a probe that
/// "failed" is only a pass if the host service also saw nothing.
pub struct HostTcp {
    pub port: u16,
    pub accepts: Arc<AtomicUsize>,
}

impl HostTcp {
    pub fn start() -> HostTcp {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let a = accepts.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                a.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
        });
        HostTcp { port, accepts }
    }
}

pub struct HostUdp {
    pub port: u16,
    pub datagrams: Arc<AtomicUsize>,
}

impl HostUdp {
    pub fn start() -> HostUdp {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap().port();
        let datagrams = Arc::new(AtomicUsize::new(0));
        let d = datagrams.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while s.recv_from(&mut buf).is_ok() {
                d.fetch_add(1, Ordering::SeqCst);
            }
        });
        HostUdp { port, datagrams }
    }
}

pub struct HostUnix {
    pub path: PathBuf,
    pub accepts: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

impl HostUnix {
    /// A stand-in for docker.sock or any other host service socket.
    pub fn start() -> HostUnix {
        let dir = short_tmp("bku.");
        let path = dir.path().join("docker.sock");
        let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let a = accepts.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                a.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
        });
        HostUnix { path, accepts, _dir: dir }
    }
}

/// A config that grants the local upstream as `allowed.test` (pinned to
/// loopback, which must be granted explicitly) plus any extra TOML.
pub fn config_with_upstream(port: u16, extra: &str) -> String {
    format!(
        "version = 1\n\n[[egress]]\nid = \"upstream\"\nhost = \"allowed.test\"\nports = [{port}]\naddrs = [\"127.0.0.1\"]\nallow_addr_classes = [\"loopback\"]\n\n{extra}"
    )
}

/// Is the cvc5 solver for the formal gates runnable? With
/// `BROKER_REQUIRE_SOLVER` set (CI), a missing solver fails the test.
pub fn solver() -> bool {
    let path = std::env::var("CVC5").unwrap_or_else(|_| "cvc5".into());
    let ok = Command::new(&path).arg("--version").output().is_ok_and(|o| o.status.success());
    if !ok && std::env::var_os("BROKER_REQUIRE_SOLVER").is_some() {
        panic!("cvc5 not runnable ({path}) but BROKER_REQUIRE_SOLVER is set");
    }
    if !ok {
        eprintln!("skipping the formal gates: cvc5 not runnable ({path})");
    }
    ok
}
