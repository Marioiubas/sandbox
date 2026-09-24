//! Linux-only parts of `linux-native`: probe, launch, and the inner layers
//! the shim applies inside the namespace.

use super::bwrap::{BwrapInputs, args, read_allowlist};
use super::{BRIDGE_PORT, LinuxBackend, layer};
use crate::backends::seatbelt::check_outside_writable;
use crate::backends::spawn::spawn_with_status;
use crate::shim::{LinuxShim, ShimSpec, Verify};
use crate::{BackendReport, EgressEndpoint, LayerStatus, SandboxHandle, SandboxSpec};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Landlock ABI of the running kernel (0 = unsupported).
pub fn landlock_abi() -> u8 {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: the documented ABI probe: NULL attr, size 0, VERSION flag.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if v < 0 { 0 } else { v.min(255) as u8 }
}

fn seccomp_available() -> Result<String, String> {
    let arch = std::env::consts::ARCH;
    if arch != "x86_64" && arch != "aarch64" {
        return Err(format!("no verified seccomp filter for {arch}"));
    }
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    if !status.lines().any(|l| l.starts_with("Seccomp:")) {
        return Err("kernel lacks CONFIG_SECCOMP_FILTER".into());
    }
    Ok(format!("filter for {arch}"))
}

fn userns_test(bwrap: &Path) -> Result<(), String> {
    // The same namespaces and mounts a real launch uses, so `doctor` reports
    // what `run` will hit (for example a procfs that cannot be mounted
    // inside an unprivileged container).
    let out = Command::new(bwrap)
        .args([
            "--unshare-user",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-ipc",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--",
            "/bin/true",
        ])
        .env_clear()
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let mut msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if let Ok(v) = std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            && v.trim() == "1"
        {
            msg.push_str(" (Ubuntu AppArmor restricts unprivileged user namespaces; install the broker AppArmor profile for bwrap)");
        }
        Err(msg)
    }
}

pub fn probe(b: &LinuxBackend) -> BackendReport {
    let mut layers: Vec<LayerStatus> = Vec::new();
    let abi = landlock_abi();
    let mut userns = None;
    match &b.bwrap {
        Some(p) => {
            layers.push(layer("bwrap", true, true, p.display().to_string()));
            match userns_test(p) {
                Ok(()) => {
                    userns = Some(true);
                    layers.push(layer(
                        "userns+netns",
                        true,
                        true,
                        "unprivileged user, PID and empty network namespaces",
                    ));
                }
                Err(e) => {
                    userns = Some(false);
                    layers.push(layer("userns+netns", true, false, e));
                }
            }
        }
        None => layers.push(layer("bwrap", true, false, "bubblewrap not found in /usr/bin or /usr/local/bin")),
    }
    match seccomp_available() {
        Ok(d) => layers.push(layer("seccomp", true, true, d)),
        Err(e) => layers.push(layer("seccomp", true, false, e)),
    }
    layers.push(layer("no_new_privs", true, true, "prctl(PR_SET_NO_NEW_PRIVS)"));
    layers.push(layer(
        "landlock_fs",
        true,
        abi >= 1,
        if abi >= 1 { format!("ABI {abi}") } else { "Landlock unsupported by this kernel".into() },
    ));
    layers.push(layer(
        "landlock_net",
        false,
        abi >= 4,
        if abi >= 4 {
            format!("TCP connect limited to the bridge port (ABI {abi})")
        } else {
            format!("needs ABI 4, kernel has {abi}; the empty netns still applies")
        },
    ));
    let mut r = BackendReport {
        backend: "linux-native".into(),
        layers,
        landlock_abi: Some(abi),
        userns_allowed: userns,
        vz_available: None,
    };
    crate::apply_faults(&mut r);
    r
}

fn kind(p: &Path) -> Option<bool> {
    std::fs::symlink_metadata(p).ok().map(|m| m.is_dir())
}

pub fn launch(b: &LinuxBackend, spec: SandboxSpec) -> anyhow::Result<SandboxHandle> {
    let report = probe(b);
    if let Some(l) = report.missing_required().first() {
        anyhow::bail!("required layer {} unavailable: {}", l.name, l.detail);
    }
    let bwrap = b.bwrap.clone().ok_or_else(|| anyhow::anyhow!("bwrap missing"))?;
    let EgressEndpoint::Uds { path: data_sock, bridge_port } = &spec.egress else {
        anyhow::bail!("linux-native requires a UDS egress endpoint");
    };
    check_outside_writable(&spec.shim, &spec.fs.writable)?;
    let mut placeholders = Vec::new();
    for p in &spec.fs.missing_protected {
        if std::fs::create_dir(p).is_ok() {
            placeholders.push(p.clone());
        }
    }
    let canary = spec.session_dir.join("canary");
    std::fs::write(&canary, "broker-canary")?;
    let mut deny_read = vec![canary];
    deny_read.extend(spec.fs.deny_read.iter().filter(|p| p.is_file()).take(4).cloned());
    let mut deny_create_in: Vec<PathBuf> = spec
        .fs
        .deny_write
        .iter()
        .filter(|p| p.is_dir() && spec.fs.writable.iter().any(|w| p.starts_with(w)))
        .take(6)
        .cloned()
        .collect();
    if let Some(h) = std::env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_dir()) {
        deny_create_in.push(h);
    }
    let shim_spec = ShimSpec {
        v: 1,
        verify: Verify {
            deny_read,
            deny_create_in,
            forbidden_connect: vec![
                SocketAddr::from(([1, 1, 1, 1], 443)),
                SocketAddr::from(([169, 254, 169, 254], 80)),
            ],
        },
        linux: Some(LinuxShim {
            bridge_port: *bridge_port,
            data_sock: data_sock.clone(),
            writable: spec.fs.writable.clone(),
            deny_read: spec.fs.deny_read.clone(),
        }),
        faults: crate::injected_faults(),
    };
    let encoded = shim_spec.encode();
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let argv = args(&BwrapInputs {
        fs: &spec.fs,
        cwd: &spec.cwd,
        data_sock,
        runtime_dir: runtime.as_deref(),
        shim: &spec.shim,
        shim_spec: &encoded,
        argv: &spec.argv,
        exists: &kind,
    });
    let mut cmd = Command::new(&bwrap);
    cmd.args(&argv).env_clear().envs(&spec.env).current_dir("/");
    match spawn_with_status(cmd, spec.stdio, Duration::from_secs(15)) {
        Ok((child, status)) => {
            let mut verified = report.layers;
            verified.extend(status.layers);
            Ok(SandboxHandle { pid: child.id(), child, verified, placeholders })
        }
        Err(e) => {
            for p in &placeholders {
                let _ = std::fs::remove_dir(p);
            }
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// Inside the sandbox (called by the shim)
// ---------------------------------------------------------------------------

pub fn apply(l: &LinuxShim, layers: &mut Vec<LayerStatus>) -> anyhow::Result<()> {
    // 1. No new privileges: setuid binaries cannot regain what we drop.
    // SAFETY: plain prctl.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        layers.push(layer("no_new_privs", true, false, std::io::Error::last_os_error().to_string()));
        anyhow::bail!("PR_SET_NO_NEW_PRIVS failed");
    }
    layers.push(layer("no_new_privs", true, true, "set"));

    // 2. The bridge: loopback listener in the empty netns → brokerd's UDS.
    //    Started before seccomp forbids new AF_UNIX sockets (Codex order).
    bridge::start(l.bridge_port, &l.data_sock)?;
    layers.push(layer("bridge", true, true, format!("127.0.0.1:{} -> {}", l.bridge_port, l.data_sock.display())));

    // 3. Landlock.
    landlock_apply(l, layers)?;

    // 4. seccomp, last: after it, no new AF_UNIX sockets, no ptrace, no bpf...
    seccomp::apply()?;
    layers.push(layer(
        "seccomp",
        true,
        true,
        "AF_UNIX/raw/packet sockets, ptrace, bpf, keyctl, mount, namespaces, io_uring denied",
    ));

    // 5. Verify the seccomp layer from inside.
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        layers.push(layer("verify_seccomp", true, false, "socket(AF_UNIX) succeeded"));
        anyhow::bail!("seccomp did not block socket(AF_UNIX)");
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    if errno != Some(libc::EPERM) {
        layers.push(layer("verify_seccomp", true, false, format!("socket(AF_UNIX) errno {errno:?}")));
        anyhow::bail!("socket(AF_UNIX) failed with an unexpected errno");
    }
    layers.push(layer("verify_seccomp", true, true, "socket(AF_UNIX) = EPERM"));
    Ok(())
}

fn landlock_apply(l: &LinuxShim, layers: &mut Vec<LayerStatus>) -> anyhow::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, Scope,
    };
    let kernel_abi = landlock_abi();
    let abi = ABI::V9;
    let read_roots = read_allowlist(Path::new("/"), &l.deny_read);
    let mut write_roots: Vec<PathBuf> = l.writable.clone();
    write_roots.push("/tmp".into());
    write_roots.push("/dev".into());

    let mut ruleset =
        Ruleset::default().set_compatibility(CompatLevel::BestEffort).handle_access(AccessFs::from_all(abi))?;
    if kernel_abi >= 4 {
        ruleset = ruleset.handle_access(AccessNet::ConnectTcp)?;
    }
    if kernel_abi >= 6 {
        ruleset = ruleset.scope(Scope::AbstractUnixSocket | Scope::Signal)?;
    }
    let mut created = ruleset.create()?;
    // Listing directory names is allowed everywhere; file contents are not.
    created = created.add_rule(PathBeneath::new(PathFd::new("/")?, AccessFs::ReadDir))?;
    for p in &read_roots {
        if let Ok(fd) = PathFd::new(p) {
            let is_dir = std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false);
            let access =
                if is_dir { AccessFs::from_read(abi) } else { AccessFs::from_file(abi) & AccessFs::from_read(abi) };
            created = created.add_rule(PathBeneath::new(fd, access))?;
        }
    }
    for p in &write_roots {
        if let Ok(fd) = PathFd::new(p) {
            created = created.add_rule(PathBeneath::new(fd, AccessFs::from_all(abi)))?;
        }
    }
    if kernel_abi >= 4 {
        created = created.add_rule(NetPort::new(l.bridge_port, AccessNet::ConnectTcp))?;
    }
    let status = created.restrict_self()?;
    let fs_ok = status.ruleset != RulesetStatus::NotEnforced;
    layers.push(layer(
        "landlock_fs",
        true,
        fs_ok,
        format!(
            "kernel ABI {kernel_abi}, {:?}, {} read roots, {} write roots",
            status.ruleset,
            read_roots.len(),
            write_roots.len()
        ),
    ));
    if !fs_ok {
        anyhow::bail!("Landlock filesystem rules were not enforced (kernel ABI {kernel_abi})");
    }
    layers.push(layer(
        "landlock_net",
        false,
        kernel_abi >= 4,
        if kernel_abi >= 4 {
            format!("connect only to port {}", l.bridge_port)
        } else {
            "not available below ABI 4".into()
        },
    ));
    let _ = BRIDGE_PORT;
    Ok(())
}

mod bridge {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    /// Bind in this process (so the port is ready before the agent starts),
    /// then double-fork so the bridge is reparented to the namespace's init
    /// and never shows up in the agent's wait().
    pub fn start(port: u16, sock: &Path) -> anyhow::Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        // SAFETY: single-threaded at this point (the shim has not started threads).
        match unsafe { libc::fork() } {
            -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                // SAFETY: fork in the intermediate child.
                match unsafe { libc::fork() } {
                    0 => {
                        // Non-dumpable: the agent (same uid) cannot read our memory via /proc.
                        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
                        serve(listener, sock);
                        unsafe { libc::_exit(0) };
                    }
                    _ => unsafe { libc::_exit(0) },
                }
            }
            pid => {
                let mut st = 0;
                // SAFETY: reap the intermediate child.
                unsafe { libc::waitpid(pid, &mut st, 0) };
                drop(listener);
                Ok(())
            }
        }
    }

    fn copy(mut from: impl Read, mut to: impl Write) {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    }

    fn serve(listener: TcpListener, sock: &Path) {
        for conn in listener.incoming() {
            let Ok(tcp) = conn else { continue };
            let sock = sock.to_path_buf();
            std::thread::spawn(move || {
                let Ok(uds) = UnixStream::connect(&sock) else { return };
                let (Ok(tcp_r), Ok(uds_r)) = (tcp.try_clone(), uds.try_clone()) else { return };
                let up = std::thread::spawn(move || {
                    copy(tcp_r, &uds);
                    let _ = uds.shutdown(Shutdown::Write);
                });
                copy(uds_r, &tcp);
                let _ = tcp.shutdown(Shutdown::Write);
                let _ = up.join();
            });
        }
        unsafe { libc::_exit(0) }
    }
}

pub mod seccomp {
    //! The seccomp filters (see the seccomp-bpf note and ADR-016).
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as Cond,
        SeccompFilter, SeccompRule, TargetArch,
    };
    use std::collections::BTreeMap;

    fn arch() -> anyhow::Result<TargetArch> {
        Ok(std::env::consts::ARCH.try_into()?)
    }

    fn eq(arg: u8, v: u64) -> Cond {
        Cond::new(arg, Len::Dword, Op::Eq, v).expect("valid condition")
    }

    fn bits(arg: u8, mask: u64) -> Cond {
        Cond::new(arg, Len::Qword, Op::MaskedEq(mask), mask).expect("valid condition")
    }

    /// Syscalls denied outright with EPERM.
    pub fn denied_syscalls() -> Vec<i64> {
        vec![
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_open_by_handle_at,
            libc::SYS_kexec_load,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_userfaultfd,
            libc::SYS_fanotify_init,
        ]
    }

    pub fn build() -> anyhow::Result<Vec<BpfProgram>> {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        for s in denied_syscalls() {
            rules.insert(s, vec![]);
        }
        // socket(): no new AF_UNIX (ctl.sock, docker.sock and every other
        // host socket stay unreachable), no packet sockets, no raw sockets.
        // socketpair(AF_UNIX) stays allowed: an anonymous pair cannot reach
        // a named socket, and Node's child_process needs it (ADR-016).
        let sock_type_mask = 0xf;
        rules.insert(
            libc::SYS_socket,
            vec![
                SeccompRule::new(vec![eq(0, libc::AF_UNIX as u64)])?,
                SeccompRule::new(vec![eq(0, libc::AF_PACKET as u64)])?,
                SeccompRule::new(vec![
                    eq(0, libc::AF_INET as u64),
                    Cond::new(1, Len::Dword, Op::MaskedEq(sock_type_mask), libc::SOCK_RAW as u64)?,
                ])?,
                SeccompRule::new(vec![
                    eq(0, libc::AF_INET6 as u64),
                    Cond::new(1, Len::Dword, Op::MaskedEq(sock_type_mask), libc::SOCK_RAW as u64)?,
                ])?,
            ],
        );
        // No new namespaces via clone flags.
        let ns = [
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWNS,
            libc::CLONE_NEWNET,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWCGROUP,
        ];
        rules.insert(
            libc::SYS_clone,
            ns.iter().map(|f| SeccompRule::new(vec![bits(0, *f as u64)])).collect::<Result<_, _>>()?,
        );
        // Terminal input injection into the user's shell.
        rules.insert(
            libc::SYS_ioctl,
            vec![SeccompRule::new(vec![eq(1, libc::TIOCSTI)])?, SeccompRule::new(vec![eq(1, libc::TIOCLINUX)])?],
        );
        let eperm: BpfProgram =
            SeccompFilter::new(rules, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM as u32), arch()?)?
                .try_into()?;
        // clone3 passes flags in memory the filter cannot read: ENOSYS makes
        // libc fall back to clone(), which the filter above can inspect.
        let mut c3: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        c3.insert(libc::SYS_clone3, vec![]);
        let enosys: BpfProgram =
            SeccompFilter::new(c3, SeccompAction::Allow, SeccompAction::Errno(libc::ENOSYS as u32), arch()?)?
                .try_into()?;
        #[allow(unused_mut)]
        let mut progs = vec![eperm, enosys];
        #[cfg(target_arch = "x86_64")]
        progs.push(x32_filter());
        Ok(progs)
    }

    /// x86_64 only: refuse the x32 ABI (syscall numbers with bit 30 set),
    /// which would otherwise bypass rules keyed on x86_64 numbers.
    #[cfg(target_arch = "x86_64")]
    fn x32_filter() -> BpfProgram {
        use seccompiler::sock_filter;
        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_JGE_K: u16 = 0x35;
        const BPF_RET_K: u16 = 0x06;
        const X32_BIT: u32 = 0x4000_0000;
        const RET_ALLOW: u32 = 0x7fff_0000;
        let ret_errno = 0x0005_0000 | libc::ENOSYS as u32;
        vec![
            sock_filter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 0 }, // seccomp_data.nr
            sock_filter { code: BPF_JGE_K, jt: 0, jf: 1, k: X32_BIT },
            sock_filter { code: BPF_RET_K, jt: 0, jf: 0, k: ret_errno },
            sock_filter { code: BPF_RET_K, jt: 0, jf: 0, k: RET_ALLOW },
        ]
    }

    pub fn apply() -> anyhow::Result<()> {
        for p in build()? {
            seccompiler::apply_filter(&p)?;
        }
        Ok(())
    }
}
