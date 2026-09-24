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

pub fn connect(d: &BrokerDirs) -> Option<UnixStream> {
    UnixStream::connect(d.ctl_sock()).ok()
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
