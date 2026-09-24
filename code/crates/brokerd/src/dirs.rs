//! Where the broker keeps configuration, state (audit DB) and runtime
//! sockets. All three are outside every sandbox mount: masked and
//! write-denied in every profile (I5, I9).

use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerDirs {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub run_dir: PathBuf,
}

/// The user's home directory from the password database, never `$HOME`.
pub fn passwd_home() -> anyhow::Result<PathBuf> {
    let uid = nix::unistd::getuid();
    let user = nix::unistd::User::from_uid(uid)?.ok_or_else(|| anyhow::anyhow!("no passwd entry for uid {uid}"))?;
    Ok(user.dir)
}

pub fn passwd_user() -> anyhow::Result<nix::unistd::User> {
    let uid = nix::unistd::getuid();
    nix::unistd::User::from_uid(uid)?.ok_or_else(|| anyhow::anyhow!("no passwd entry for uid {uid}"))
}

impl BrokerDirs {
    /// `BROKER_HOME` roots everything in one directory (tests, CI); it
    /// changes where policy is read from, never whether isolation applies (I8).
    pub fn from_env() -> anyhow::Result<Self> {
        if let Some(h) = std::env::var_os("BROKER_HOME").filter(|h| !h.is_empty()) {
            let h = PathBuf::from(h);
            if !h.is_absolute() {
                anyhow::bail!("BROKER_HOME must be absolute");
            }
            return Ok(Self::rooted(&h));
        }
        let home = passwd_home()?;
        let config_dir = home.join(".config/broker");
        #[cfg(target_os = "macos")]
        let state_dir = home.join("Library/Application Support/broker");
        #[cfg(not(target_os = "macos"))]
        let state_dir = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".local/state"))
            .join("broker");
        #[cfg(target_os = "linux")]
        let run_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute() && p.is_dir())
            .map(|p| p.join("broker"))
            .unwrap_or_else(|| state_dir.join("run"));
        #[cfg(not(target_os = "linux"))]
        let run_dir = state_dir.join("run");
        Ok(BrokerDirs { config_dir, state_dir, run_dir })
    }

    pub fn rooted(h: &Path) -> Self {
        BrokerDirs { config_dir: h.join("config"), state_dir: h.join("state"), run_dir: h.join("run") }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("broker.toml")
    }
    pub fn audit_db(&self) -> PathBuf {
        self.state_dir.join("audit.db")
    }
    pub fn ctl_sock(&self) -> PathBuf {
        self.run_dir.join("ctl.sock")
    }
    pub fn log_file(&self) -> PathBuf {
        self.state_dir.join("brokerd.log")
    }
    pub fn sessions_dir(&self) -> PathBuf {
        self.run_dir.join("s")
    }
    pub fn all(&self) -> Vec<PathBuf> {
        vec![self.config_dir.clone(), self.state_dir.clone(), self.run_dir.clone()]
    }

    /// Create the directories with mode 0700.
    pub fn ensure(&self) -> anyhow::Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        for d in [&self.config_dir, &self.state_dir, &self.run_dir, &self.sessions_dir()] {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(d)?;
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}
