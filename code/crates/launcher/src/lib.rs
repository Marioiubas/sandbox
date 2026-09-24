//! launcher: the kernel-backed half of the product (trust boundary TB2) and
//! the network topology that makes the broker the only way out (TB3).
//!
//! Backends implement [`SandboxBackend`]. `probe()` reports every layer;
//! `launch()` refuses to start the agent if any required layer is missing,
//! and the in-sandbox shim verifies the layers *after* applying them and
//! before `exec` (I2). Required layers come from the backend, never from
//! options or flags (I8).

pub mod backends;
pub mod fs_compile;
pub mod shim;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::path::PathBuf;

pub use fs_compile::{CompiledFsPolicy, FsInputs};

/// Isolation backend. Must fail closed.
pub trait SandboxBackend: Send + Sync {
    /// `"macos-seatbelt"` | `"linux-native"` | `"container"` | `"vm"`.
    fn name(&self) -> &'static str;
    /// Report every layer, required or optional, without side effects.
    fn probe(&self) -> anyhow::Result<BackendReport>;
    /// Start `spec.argv` inside the sandbox, or return `Err` without the
    /// agent ever executing.
    fn launch(&self, spec: SandboxSpec) -> anyhow::Result<SandboxHandle>;
}

/// The only network route a sandbox gets. There is deliberately no variant
/// for "host network".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressEndpoint {
    /// Linux: a per-session Unix socket owned by brokerd, reached through the
    /// in-namespace bridge listening on `bridge_port` (loopback of an empty netns).
    Uds { path: PathBuf, bridge_port: u16 },
    /// macOS: a per-session loopback port; connections must carry the sentinel.
    Loopback(u16),
    /// VM hard tier (phase 2).
    Vsock(u32, u32),
}

pub struct SandboxSpec {
    pub session: String,
    pub argv: Vec<OsString>,
    pub cwd: PathBuf,
    /// Allowlisted variables, proxy variables and sentinels only (I1). The
    /// host environment is never inherited.
    pub env: BTreeMap<String, String>,
    pub fs: CompiledFsPolicy,
    pub egress: EgressEndpoint,
    /// Per-session CA merged with public roots (M1). Unused in M0.
    pub ca_bundle: Option<PathBuf>,
    /// The agent's stdin, stdout, stderr (passed from the CLI).
    pub stdio: [OwnedFd; 3],
    /// Absolute path of the terminal device on stdin, if any (macOS rule).
    pub tty_path: Option<PathBuf>,
    /// Per-session directory outside every sandbox mount (profiles, status).
    pub session_dir: PathBuf,
    /// Absolute path of `broker-sandbox-shim`; must be outside writable mounts (I5).
    pub shim: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerStatus {
    pub name: String,
    pub required: bool,
    pub ok: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendReport {
    pub backend: String,
    pub layers: Vec<LayerStatus>,
    pub landlock_abi: Option<u8>,
    pub userns_allowed: Option<bool>,
    pub vz_available: Option<bool>,
}

impl BackendReport {
    /// Every required layer that is not OK.
    pub fn missing_required(&self) -> Vec<&LayerStatus> {
        self.layers.iter().filter(|l| l.required && !l.ok).collect()
    }

    pub fn ok(&self) -> bool {
        self.missing_required().is_empty()
    }
}

/// A refused launch, with the layer report from inside the sandbox when the
/// shim got far enough to write one.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct LaunchError {
    pub message: String,
    pub layers: Vec<LayerStatus>,
}

/// A running sandbox.
pub struct SandboxHandle {
    pub pid: u32,
    pub child: std::process::Child,
    /// Layer status as verified from inside the sandbox by the shim.
    pub verified: Vec<LayerStatus>,
    /// Paths created as placeholders for protected names; removed on teardown
    /// if still empty.
    pub placeholders: Vec<PathBuf>,
}

/// Fault injection for the fail-closed tests (I2): `BROKER_FAULT_INJECT` is a
/// comma-separated list of layer or step names to treat as failed. It can
/// only make a launch fail, never succeed, so it cannot weaken isolation (I8).
pub fn injected_faults() -> Vec<String> {
    std::env::var("BROKER_FAULT_INJECT")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

/// Mark injected layers as failed in a probe report.
pub fn apply_faults(report: &mut BackendReport) {
    let faults = injected_faults();
    for l in &mut report.layers {
        if faults.iter().any(|f| f == &l.name) {
            l.ok = false;
            l.detail = format!("fault injected ({})", l.detail);
        }
    }
}

/// The backend for this host, or an error naming why none is usable.
pub fn host_backend() -> Box<dyn SandboxBackend> {
    #[cfg(target_os = "macos")]
    {
        Box::new(backends::seatbelt::SeatbeltBackend::default())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(backends::linux::LinuxBackend::default())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Box::new(backends::unsupported::Unsupported)
    }
}

/// Locate `broker-sandbox-shim` next to the running executable.
pub fn default_shim_path() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| anyhow::anyhow!("executable has no parent directory"))?;
    let shim = dir.join("broker-sandbox-shim");
    if !shim.is_file() {
        anyhow::bail!("broker-sandbox-shim not found next to {}", exe.display());
    }
    Ok(shim.canonicalize()?)
}
