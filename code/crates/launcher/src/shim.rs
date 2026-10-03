//! The in-sandbox shim (`broker-sandbox-shim`).
//!
//! It runs as the first process inside the sandbox, applies the inner layers
//! (Linux: `PR_SET_NO_NEW_PRIVS`, the TCP→UDS bridge, Landlock, seccomp),
//! then **verifies from inside** that forbidden reads, writes and connects
//! fail, reports a status line to brokerd over an inherited pipe, and only
//! then `exec`s the agent. Any failure exits 125 before the agent's first
//! instruction (I2).
//!
//! The spec travels as base64url JSON in argv. It contains paths and ports
//! only, never a secret (I1).
//!
//! Linux (ADR-043): the seccomp deny filter returns `USER_NOTIF`; the shim
//! sends its listener to brokerd over [`NOTIFY_FD`] (a socket connected
//! before seccomp exists), closes both, and refuses to exec the agent unless
//! both are verifiably closed. The agent never holds the listener.

use crate::LayerStatus;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

pub const SHIM_EXIT_REFUSED: i32 = 125;
/// The status pipe's fd number inside the sandbox.
pub const STATUS_FD: i32 = 3;
/// Linux: the shim's end of the seccomp notify channel to brokerd (ADR-043).
pub const NOTIFY_FD: i32 = 4;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verify {
    /// Paths whose open-for-read must fail.
    pub deny_read: Vec<PathBuf>,
    /// Directories in which creating a file must fail.
    pub deny_create_in: Vec<PathBuf>,
    /// Addresses a TCP connect to must be refused by the sandbox (not by the peer).
    pub forbidden_connect: Vec<SocketAddr>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinuxShim {
    pub bridge_port: u16,
    pub data_sock: PathBuf,
    pub writable: Vec<PathBuf>,
    pub deny_read: Vec<PathBuf>,
    /// [`NOTIFY_FD`] is open: hand the seccomp listener to brokerd (ADR-043).
    #[serde(default)]
    pub seccomp_notify: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimSpec {
    pub v: u32,
    pub verify: Verify,
    pub linux: Option<LinuxShim>,
    /// Injected faults (tests only; can only cause a refusal).
    #[serde(default)]
    pub faults: Vec<String>,
}

impl ShimSpec {
    fn fault(&self, step: &str) -> bool {
        self.faults.iter().any(|f| f == step)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimStatus {
    pub ok: bool,
    pub layers: Vec<LayerStatus>,
    pub error: Option<String>,
}

impl ShimSpec {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("spec serialises");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    }

    pub fn decode(s: &str) -> anyhow::Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?;
        let spec: ShimSpec = serde_json::from_slice(&bytes)?;
        if spec.v != 1 {
            anyhow::bail!("unsupported shim spec version {}", spec.v);
        }
        Ok(spec)
    }
}

/// Parse `--spec <b64> -- <argv...>`.
pub fn parse_args(args: &[OsString]) -> anyhow::Result<(ShimSpec, Vec<OsString>)> {
    let mut it = args.iter();
    match (it.next().and_then(|s| s.to_str()), it.next().and_then(|s| s.to_str())) {
        (Some("--spec"), Some(b64)) => {
            let spec = ShimSpec::decode(b64)?;
            if it.next().and_then(|s| s.to_str()) != Some("--") {
                anyhow::bail!("expected -- before the agent command");
            }
            let argv: Vec<OsString> = it.cloned().collect();
            if argv.is_empty() {
                anyhow::bail!("no agent command");
            }
            Ok((spec, argv))
        }
        _ => anyhow::bail!("usage: broker-sandbox-shim --spec <spec> -- <command...> (internal; started by brokerd)"),
    }
}

fn layer(name: &str, required: bool, ok: bool, detail: impl Into<String>) -> LayerStatus {
    LayerStatus { name: name.into(), required, ok, detail: detail.into() }
}

fn write_status(st: &ShimStatus) {
    use std::os::fd::FromRawFd;
    // SAFETY: fd 3 is the status pipe set up by the launcher; if it is not
    // open the write fails and the launcher treats the missing status as a refusal.
    let mut f = unsafe { std::fs::File::from_raw_fd(STATUS_FD) };
    let mut line = serde_json::to_vec(st).unwrap_or_default();
    line.push(b'\n');
    let _ = f.write_all(&line);
    drop(f); // closes the pipe so brokerd sees EOF
}

fn refuse(mut layers: Vec<LayerStatus>, error: String) -> ! {
    layers.push(layer("shim", true, false, error.clone()));
    write_status(&ShimStatus { ok: false, layers, error: Some(error.clone()) });
    eprintln!("broker: sandbox refused to start: {error}");
    std::process::exit(SHIM_EXIT_REFUSED);
}

/// Entry point of the shim binary.
pub fn main_with_args(args: Vec<OsString>) -> ! {
    let (spec, argv) = match parse_args(&args) {
        Ok(v) => v,
        Err(e) => refuse(vec![], format!("bad shim arguments: {e}")),
    };
    let mut layers = Vec::new();
    for step in [
        "shim",
        "no_new_privs",
        "bridge",
        "landlock_fs",
        "seccomp",
        "verify_deny_read",
        "verify_deny_write",
        "verify_egress",
    ] {
        if spec.fault(step) {
            refuse(layers, format!("{step}: fault injected"));
        }
    }

    // Descriptors that must be closed before the agent runs (Linux: the
    // seccomp listener and the channel it went to brokerd over).
    #[allow(unused_mut)]
    let mut closed: Vec<i32> = Vec::new();
    #[cfg(target_os = "linux")]
    if let Some(l) = &spec.linux {
        match crate::backends::linux::inner::apply(l, &mut layers) {
            Ok(c) => closed = c,
            Err(e) => refuse(layers, format!("{e:#}")),
        }
    }
    #[cfg(not(target_os = "linux"))]
    if spec.linux.is_some() {
        refuse(layers, "linux layers requested on a non-Linux host".into());
    }

    if let Err(e) = verify(&spec.verify, &mut layers) {
        refuse(layers, format!("{e:#}"));
    }
    // Checked again last, after every check above has opened and closed its
    // own descriptors: the agent inherits whatever is open at exec.
    if let Some(fd) = closed.iter().find(|fd| !fd_closed(**fd)) {
        refuse(layers, format!("fd {fd} (the seccomp listener or its channel) is still open before exec"));
    }
    write_status(&ShimStatus { ok: true, layers, error: None });
    exec(&argv)
}

/// `fd` is not open in this process: `fcntl(F_GETFD)` fails with EBADF.
pub fn fd_closed(fd: i32) -> bool {
    // SAFETY: F_GETFD only reads the descriptor's flags.
    let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
}

fn exec(argv: &[OsString]) -> ! {
    use std::os::unix::process::CommandExt;
    let err = std::process::Command::new(&argv[0]).args(&argv[1..]).exec();
    eprintln!("broker: cannot execute {}: {err}", argv[0].to_string_lossy());
    std::process::exit(127);
}

/// Errno values that mean "the sandbox refused", as opposed to "a peer answered".
fn sandbox_refused(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EPERM)
            | Some(libc::EACCES)
            | Some(libc::ENETUNREACH)
            | Some(libc::EHOSTUNREACH)
            | Some(libc::EADDRNOTAVAIL)
            | Some(libc::EAFNOSUPPORT)
    )
}

pub fn verify(v: &Verify, layers: &mut Vec<LayerStatus>) -> anyhow::Result<()> {
    for p in &v.deny_read {
        if std::fs::File::open(p).is_ok() {
            layers.push(layer("verify_deny_read", true, false, p.display().to_string()));
            anyhow::bail!("could read denied path {}", p.display());
        }
    }
    layers.push(layer("verify_deny_read", true, true, format!("{} paths", v.deny_read.len())));
    for d in &v.deny_create_in {
        let probe = d.join(format!(".broker-verify-{}", std::process::id()));
        let r = std::fs::OpenOptions::new().write(true).create_new(true).open(&probe);
        if r.is_ok() {
            let _ = std::fs::remove_file(&probe);
            layers.push(layer("verify_deny_write", true, false, d.display().to_string()));
            anyhow::bail!("could create a file in protected directory {}", d.display());
        }
    }
    layers.push(layer("verify_deny_write", true, true, format!("{} dirs", v.deny_create_in.len())));
    for a in &v.forbidden_connect {
        match std::net::TcpStream::connect_timeout(a, std::time::Duration::from_millis(1500)) {
            Ok(_) => {
                layers.push(layer("verify_egress", true, false, a.to_string()));
                anyhow::bail!("direct connect to {a} succeeded");
            }
            Err(e) if sandbox_refused(&e) => {}
            Err(e) => {
                layers.push(layer("verify_egress", true, false, format!("{a}: {e}")));
                anyhow::bail!("direct connect to {a} reached the network stack ({e})");
            }
        }
    }
    layers.push(layer("verify_egress", true, true, format!("{} addresses refused", v.forbidden_connect.len())));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_round_trip_and_args() {
        let spec = ShimSpec {
            v: 1,
            verify: Verify { deny_read: vec!["/x".into()], ..Default::default() },
            linux: Some(LinuxShim { bridge_port: 3128, ..Default::default() }),
            ..Default::default()
        };
        let args: Vec<OsString> = ["--spec", &spec.encode(), "--", "claude", "--dangerously-skip-permissions"]
            .iter()
            .map(OsString::from)
            .collect();
        let (s, argv) = parse_args(&args).unwrap();
        assert_eq!(s, spec);
        assert_eq!(argv, vec![OsString::from("claude"), OsString::from("--dangerously-skip-permissions")]);
        assert!(parse_args(&[OsString::from("--spec")]).is_err());
        let no_cmd: Vec<OsString> = ["--spec", &spec.encode(), "--"].iter().map(OsString::from).collect();
        assert!(parse_args(&no_cmd).is_err());
    }

    #[test]
    fn verify_detects_a_readable_path() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("canary");
        std::fs::write(&f, "x").unwrap();
        let mut layers = vec![];
        let v = Verify { deny_read: vec![f], ..Default::default() };
        assert!(verify(&v, &mut layers).is_err(), "outside a sandbox the canary is readable");
        let mut layers = vec![];
        let v = Verify { deny_create_in: vec![d.path().to_path_buf()], ..Default::default() };
        assert!(verify(&v, &mut layers).is_err());
        assert!(std::fs::read_dir(d.path()).unwrap().count() == 1, "probe file removed");
    }

    #[test]
    fn fd_closed_tells_open_from_closed() {
        use std::os::fd::AsRawFd;
        let f = tempfile::tempfile().unwrap();
        // Far above what other test threads open meanwhile (they get the
        // lowest free numbers), so the closed number is not reused at once.
        // SAFETY: duplicating a descriptor we own.
        let raw = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 700) };
        assert!(raw >= 700, "{}", std::io::Error::last_os_error());
        assert!(!fd_closed(raw), "an open descriptor");
        // SAFETY: we own raw.
        unsafe { libc::close(raw) };
        assert!(fd_closed(raw), "a closed descriptor");
        assert!(fd_closed(-1));
    }

    #[test]
    fn older_specs_decode_without_the_notify_flag() {
        let json = br#"{"v":1,"verify":{"deny_read":[],"deny_create_in":[],"forbidden_connect":[]},
            "linux":{"bridge_port":3128,"data_sock":"/s","writable":[],"deny_read":[]}}"#;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let spec = ShimSpec::decode(&b64).unwrap();
        assert!(!spec.linux.unwrap().seccomp_notify, "no channel unless the launcher opened one");
    }

    proptest::proptest! {
        /// Decoding is total, and what decodes re-encodes to the same spec.
        #[test]
        fn spec_decoding_is_total(s in "\\PC{0,300}", args in proptest::collection::vec("\\PC{0,20}", 0..5)) {
            if let Ok(spec) = ShimSpec::decode(&s) {
                proptest::prop_assert_eq!(ShimSpec::decode(&spec.encode()).unwrap(), spec);
            }
            let args: Vec<OsString> = args.into_iter().map(OsString::from).collect();
            if let Ok((_, argv)) = parse_args(&args) {
                proptest::prop_assert!(!argv.is_empty());
            }
        }
    }
}
