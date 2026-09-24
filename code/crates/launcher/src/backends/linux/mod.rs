//! `linux-native`: bubblewrap with an empty network namespace, a TCP→UDS
//! bridge to brokerd, Landlock, seccomp and `PR_SET_NO_NEW_PRIVS`.
//!
//! The bwrap argument builder is platform-independent (golden-tested on
//! every host); probing, launching and the inner layers are Linux-only.

pub mod bwrap;
#[cfg(target_os = "linux")]
pub mod inner;

use crate::{BackendReport, LayerStatus, SandboxBackend, SandboxHandle, SandboxSpec};
use std::path::PathBuf;

/// Where a root-owned bwrap is expected. Never looked up on PATH: a writable
/// PATH directory must not be able to substitute the sandbox binary.
pub const BWRAP_CANDIDATES: &[&str] = &["/usr/bin/bwrap", "/usr/local/bin/bwrap"];

/// The bridge port inside the sandbox's private network namespace.
pub const BRIDGE_PORT: u16 = 3128;

pub struct LinuxBackend {
    pub bwrap: Option<PathBuf>,
}

impl Default for LinuxBackend {
    fn default() -> Self {
        LinuxBackend { bwrap: BWRAP_CANDIDATES.iter().map(PathBuf::from).find(|p| p.is_file()) }
    }
}

#[allow(dead_code)]
fn layer(name: &str, required: bool, ok: bool, detail: impl Into<String>) -> LayerStatus {
    LayerStatus { name: name.into(), required, ok, detail: detail.into() }
}

impl SandboxBackend for LinuxBackend {
    fn name(&self) -> &'static str {
        "linux-native"
    }

    #[cfg(not(target_os = "linux"))]
    fn probe(&self) -> anyhow::Result<BackendReport> {
        Ok(BackendReport {
            backend: self.name().into(),
            layers: vec![layer("linux", true, false, "linux-native runs only on Linux")],
            ..Default::default()
        })
    }

    #[cfg(target_os = "linux")]
    fn probe(&self) -> anyhow::Result<BackendReport> {
        Ok(inner::probe(self))
    }

    #[cfg(not(target_os = "linux"))]
    fn launch(&self, _spec: SandboxSpec) -> anyhow::Result<SandboxHandle> {
        anyhow::bail!("linux-native runs only on Linux")
    }

    #[cfg(target_os = "linux")]
    fn launch(&self, spec: SandboxSpec) -> anyhow::Result<SandboxHandle> {
        inner::launch(self, spec)
    }
}
