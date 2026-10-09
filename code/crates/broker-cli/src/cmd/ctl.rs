//! Talking to brokerd over `ctl.sock`, starting it on demand.

use brokerd::dirs::BrokerDirs;
use brokerd::proto::{self, Incoming, Request};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub fn dirs() -> anyhow::Result<BrokerDirs> {
    BrokerDirs::from_env()
}

fn brokerd_path() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let p = exe.with_file_name("brokerd");
    if !p.is_file() {
        anyhow::bail!("brokerd not found next to {}", exe.display());
    }
    Ok(p)
}

/// Connect to brokerd, only if the socket's server runs as this user: a
/// socket another user put in a shared `XDG_RUNTIME_DIR` or `BROKER_HOME`
/// would otherwise receive the terminal and the environment.
pub fn connect(d: &BrokerDirs) -> Option<UnixStream> {
    let s = UnixStream::connect(d.ctl_sock()).ok()?;
    if peer_is_me(&s) {
        Some(s)
    } else {
        eprintln!("broker: {} is served by another user's process; not using it", d.ctl_sock().display());
        None
    }
}

/// The peer of `s` runs with this process's user ID.
fn peer_is_me(s: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: getuid(2) cannot fail.
    let me = unsafe { libc::getuid() };
    #[cfg(target_os = "linux")]
    {
        // SAFETY: a ucred-sized buffer for SO_PEERCRED.
        let mut c: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut c).cast(), &mut len)
        };
        r == 0 && c.uid == me
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: getpeereid(3) writes two ids.
        unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) == 0 && uid == me }
    }
}

/// Connect, starting brokerd in the background if it is not running.
pub fn connect_or_start(d: &BrokerDirs) -> anyhow::Result<UnixStream> {
    if let Some(s) = connect(d) {
        return Ok(s);
    }
    d.ensure()?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(d.log_file())?;
    let mut cmd = std::process::Command::new(brokerd_path()?);
    cmd.stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log);
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    let mut child = cmd.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(s) = connect(d) {
            return Ok(s);
        }
        if let Ok(Some(st)) = child.try_wait() {
            let tail = std::fs::read_to_string(d.log_file()).unwrap_or_default();
            let last: Vec<&str> = tail.lines().rev().take(3).collect();
            anyhow::bail!("brokerd exited ({st}): {}", last.into_iter().rev().collect::<Vec<_>>().join(" | "));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    anyhow::bail!("brokerd did not come up within 10s (log: {})", d.log_file().display())
}

/// One request, one response.
pub fn call(d: &BrokerDirs, method: &str, params: serde_json::Value) -> anyhow::Result<Incoming> {
    let mut s = connect(d).ok_or_else(|| anyhow::anyhow!("brokerd is not running"))?;
    s.write_all(&proto::to_line(&Request::new(Some(1), method, params)))?;
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CLI accepts a server of its own user (another user's needs a
    /// second account; the check is `peer_is_me`).
    #[test]
    fn a_server_of_this_user_is_accepted() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.sock");
        let _l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        assert!(peer_is_me(&UnixStream::connect(&p).unwrap()));
    }
}
