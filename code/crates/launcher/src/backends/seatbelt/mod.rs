//! `macos-seatbelt`: generated SBPL applied with `/usr/bin/sandbox-exec`.

pub mod sbpl;

use crate::backends::spawn::spawn_with_status;
use crate::shim::{ShimSpec, Verify};
use crate::{BackendReport, EgressEndpoint, LayerStatus, SandboxBackend, SandboxHandle, SandboxSpec};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

pub struct SeatbeltBackend {
    /// Pinned absolute path; never looked up on PATH.
    pub sandbox_exec: PathBuf,
}

impl Default for SeatbeltBackend {
    fn default() -> Self {
        SeatbeltBackend { sandbox_exec: PathBuf::from(SANDBOX_EXEC) }
    }
}

fn layer(name: &str, required: bool, ok: bool, detail: impl Into<String>) -> LayerStatus {
    LayerStatus { name: name.into(), required, ok, detail: detail.into() }
}

impl SeatbeltBackend {
    /// Apply a tiny profile that denies reading a canary file and check the
    /// denial actually happens (fail closed if Seatbelt silently no-ops).
    fn canary_check(&self) -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("broker-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let canary = dir.join("canary").canonicalize().unwrap_or_else(|_| dir.join("canary"));
        let result = (|| {
            std::fs::write(&canary, "canary").map_err(|e| e.to_string())?;
            let canary = canary.canonicalize().map_err(|e| e.to_string())?;
            let q = sbpl::quote(&canary).ok_or("unrepresentable temp path")?;
            let profile = format!("(version 1)(allow default)(deny file-read* (literal {q}))");
            let out = Command::new(&self.sandbox_exec)
                .arg("-p")
                .arg(profile)
                .arg("/bin/cat")
                .arg(&canary)
                .env_clear()
                .output()
                .map_err(|e| format!("cannot run {}: {e}", self.sandbox_exec.display()))?;
            if out.status.success() || String::from_utf8_lossy(&out.stdout).contains("canary") {
                return Err("a Seatbelt deny rule was not enforced".into());
            }
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }
}

impl SandboxBackend for SeatbeltBackend {
    fn name(&self) -> &'static str {
        "macos-seatbelt"
    }

    fn probe(&self) -> anyhow::Result<BackendReport> {
        let mut layers = Vec::new();
        let present = self.sandbox_exec.is_file();
        layers.push(layer(
            "sandbox-exec",
            true,
            present,
            if present {
                self.sandbox_exec.display().to_string()
            } else {
                format!("{} not found", self.sandbox_exec.display())
            },
        ));
        if present {
            match self.canary_check() {
                Ok(()) => layers.push(layer("seatbelt", true, true, "deny rule enforced on a canary read")),
                Err(e) => layers.push(layer("seatbelt", true, false, e)),
            }
        }
        layers.push(layer(
            "loopback-egress",
            true,
            true,
            "network-outbound only to the session port (verified at launch)",
        ));
        let mut r =
            BackendReport { backend: self.name().into(), layers, vz_available: Some(false), ..Default::default() };
        crate::apply_faults(&mut r);
        Ok(r)
    }

    fn launch(&self, spec: SandboxSpec) -> anyhow::Result<SandboxHandle> {
        let report = self.probe()?;
        if let Some(l) = report.missing_required().first() {
            anyhow::bail!("required layer {} unavailable: {}", l.name, l.detail);
        }
        let EgressEndpoint::Loopback(port) = spec.egress else {
            anyhow::bail!("macos-seatbelt requires a loopback egress endpoint");
        };
        check_outside_writable(&spec.shim, &spec.fs.writable)?;
        let profile =
            sbpl::generate(&sbpl::SbplInputs { fs: &spec.fs, broker_port: port, tty: spec.tty_path.as_deref() })
                .map_err(|e| anyhow::anyhow!("cannot generate SBPL: {e}"))?;
        let profile_path = spec.session_dir.join("sandbox.sb");
        std::fs::write(&profile_path, &profile)?;

        // Verification from inside: the session canary and ~/.ssh must be
        // unreadable, protected dirs uncreatable, and any address other
        // than the broker port refused by Seatbelt itself (EPERM), not by a peer.
        let canary = spec.session_dir.join("canary");
        std::fs::write(&canary, "broker-canary")?;
        let mut deny_read = vec![canary];
        deny_read.extend(spec.fs.deny_read.iter().filter(|p| p.is_file()).take(4).cloned());
        let mut deny_create_in: Vec<PathBuf> =
            spec.fs.deny_write.iter().filter(|p| p.is_dir()).take(6).cloned().collect();
        if let Some(h) = std::env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_dir()) {
            deny_create_in.push(h);
        }
        let other_port = if port == u16::MAX { port - 1 } else { port + 1 };
        let verify = Verify {
            deny_read,
            deny_create_in,
            forbidden_connect: vec![
                SocketAddr::from(([1, 1, 1, 1], 443)),
                SocketAddr::from(([169, 254, 169, 254], 80)),
                SocketAddr::from(([127, 0, 0, 1], other_port)),
            ],
        };
        let shim_spec = ShimSpec { v: 1, verify, linux: None, faults: crate::injected_faults() };

        let mut cmd = Command::new(&self.sandbox_exec);
        cmd.arg("-f").arg(&profile_path).arg(&spec.shim).arg("--spec").arg(shim_spec.encode()).arg("--");
        cmd.args(&spec.argv);
        cmd.env_clear().envs(&spec.env).current_dir(&spec.cwd);
        let (child, status) = spawn_with_status(cmd, spec.stdio, Duration::from_secs(15))?;
        let mut verified = report.layers;
        verified.extend(status.layers);
        Ok(SandboxHandle { pid: child.id(), child, verified, placeholders: vec![] })
    }
}

/// The shim (and the broker binaries next to it) must not be writable from
/// inside, or the agent could replace the program that applies its own
/// sandbox next time (I5).
pub(crate) fn check_outside_writable(shim: &Path, writable: &[PathBuf]) -> anyhow::Result<()> {
    let shim = shim.canonicalize()?;
    if let Some(w) = writable.iter().find(|w| shim.starts_with(w)) {
        anyhow::bail!("the sandbox shim {} is inside writable root {} (I5)", shim.display(), w.display());
    }
    Ok(())
}
