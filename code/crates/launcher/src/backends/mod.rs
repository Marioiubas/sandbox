//! Sandbox backends and the spawn helper they share.

pub mod linux;
pub mod seatbelt;

pub mod container {
    //! Docker/Podman backend: phase 2 ([[Two-Tier Isolation Design]]).
    use crate::{BackendReport, LayerStatus, SandboxBackend, SandboxHandle, SandboxSpec};

    #[derive(Default)]
    pub struct ContainerBackend;

    impl SandboxBackend for ContainerBackend {
        fn name(&self) -> &'static str {
            "container"
        }
        fn probe(&self) -> anyhow::Result<BackendReport> {
            Ok(BackendReport {
                backend: "container".into(),
                layers: vec![LayerStatus {
                    name: "container-runtime".into(),
                    required: true,
                    ok: false,
                    detail: "container backend is phase 2".into(),
                }],
                ..Default::default()
            })
        }
        fn launch(&self, _spec: SandboxSpec) -> anyhow::Result<SandboxHandle> {
            anyhow::bail!("container backend is not available until phase 2")
        }
    }
}

pub mod vm {
    //! VM hard tier (Virtualization.framework, Cloud Hypervisor): phase 2.
    use crate::{BackendReport, LayerStatus, SandboxBackend, SandboxHandle, SandboxSpec};

    #[derive(Default)]
    pub struct VmBackend;

    impl SandboxBackend for VmBackend {
        fn name(&self) -> &'static str {
            "vm"
        }
        fn probe(&self) -> anyhow::Result<BackendReport> {
            Ok(BackendReport {
                backend: "vm".into(),
                layers: vec![LayerStatus {
                    name: "hypervisor".into(),
                    required: true,
                    ok: false,
                    detail: "vm backend is phase 2".into(),
                }],
                ..Default::default()
            })
        }
        fn launch(&self, _spec: SandboxSpec) -> anyhow::Result<SandboxHandle> {
            anyhow::bail!("vm backend is not available until phase 2")
        }
    }
}

pub mod unsupported {
    use crate::{BackendReport, LayerStatus, SandboxBackend, SandboxHandle, SandboxSpec};

    pub struct Unsupported;

    impl SandboxBackend for Unsupported {
        fn name(&self) -> &'static str {
            "unsupported"
        }
        fn probe(&self) -> anyhow::Result<BackendReport> {
            Ok(BackendReport {
                backend: "unsupported".into(),
                layers: vec![LayerStatus {
                    name: "os".into(),
                    required: true,
                    ok: false,
                    detail: format!("{} is not supported", std::env::consts::OS),
                }],
                ..Default::default()
            })
        }
        fn launch(&self, _spec: SandboxSpec) -> anyhow::Result<SandboxHandle> {
            anyhow::bail!("no sandbox backend for {}", std::env::consts::OS)
        }
    }
}

pub(crate) mod spawn {
    //! Spawn a sandbox command with the agent's stdio, a fresh session, only
    //! fds 0-3 open, and wait for the shim's status line on fd 3.

    use crate::shim::{STATUS_FD, ShimStatus};
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    fn pipe_high() -> std::io::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: plain pipe(2) into a two-element array.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut out = Vec::new();
        for fd in fds {
            // Move above the stdio/status range and set CLOEXEC.
            // SAFETY: fd is a valid descriptor we own.
            let hi = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
            unsafe { libc::close(fd) };
            if hi < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: hi is a fresh descriptor we own.
            out.push(unsafe { OwnedFd::from_raw_fd(hi) });
        }
        let w = out.pop().expect("two fds");
        let r = out.pop().expect("two fds");
        Ok((r, w))
    }

    fn max_fd() -> libc::c_int {
        let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: getrlimit writes into rl.
        let n = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 { rl.rlim_cur } else { 4096 };
        n.min(65_536) as libc::c_int
    }

    pub fn spawn_with_status(
        mut cmd: Command,
        stdio: [OwnedFd; 3],
        timeout: Duration,
    ) -> anyhow::Result<(Child, ShimStatus)> {
        let (r, w) = pipe_high()?;
        let wfd = w.as_raw_fd();
        let limit = max_fd();
        let [i, o, e] = stdio;
        cmd.stdin(Stdio::from(i)).stdout(Stdio::from(o)).stderr(Stdio::from(e));
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(wfd, STATUS_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // Nothing of brokerd's (sockets, audit DB) crosses into the sandbox.
                for fd in (STATUS_FD + 1)..limit {
                    libc::close(fd);
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn()?;
        drop(w);
        let status = read_status(r, timeout);
        match status {
            Some(st) if st.ok => Ok((child, st)),
            other => {
                // SAFETY: the child leads its own process group (setsid).
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                match other {
                    Some(st) => Err(crate::LaunchError {
                        message: format!(
                            "sandbox verification failed: {}",
                            st.error.clone().unwrap_or_else(|| "unknown".into())
                        ),
                        layers: st.layers,
                    }
                    .into()),
                    None => Err(crate::LaunchError {
                        message: "sandbox did not report readiness (a layer failed to start)".into(),
                        layers: vec![],
                    }
                    .into()),
                }
            }
        }
    }

    fn read_status(r: OwnedFd, timeout: Duration) -> Option<ShimStatus> {
        let deadline = Instant::now() + timeout;
        let mut f = std::fs::File::from(r);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let mut pfd = libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            // SAFETY: one pollfd.
            let n = unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(i32::MAX as u128) as i32) };
            if n <= 0 {
                if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return None;
            }
            match f.read(&mut chunk) {
                Ok(0) => break,
                Ok(k) => {
                    buf.extend_from_slice(&chunk[..k]);
                    if buf.len() > 256 * 1024 {
                        return None;
                    }
                    if buf.contains(&b'\n') {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        let line = buf.split(|b| *b == b'\n').next()?;
        serde_json::from_slice(line).ok()
    }
}
