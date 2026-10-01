//! The seccomp listener's way from the shim to brokerd, and brokerd's
//! answers (ADR-043).
//!
//! **Shim.** [`install_listener`] installs the deny filter with
//! `SECCOMP_FILTER_FLAG_NEW_LISTENER`; [`hand_over`] sends the listener with
//! SCM_RIGHTS over the inherited channel ([`NOTIFY_FD`], a socket connected
//! before seccomp exists, with no name anywhere in the filesystem), closes
//! both and checks that both are closed. The agent never holds either.
//!
//! **brokerd.** [`channel`] and [`spawn_feed`]: one thread per session takes
//! exactly one descriptor, checks that it is a seccomp listener, closes the
//! channel, then answers one notification at a time with `-EPERM` (never
//! `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, never a success value) and queues a
//! [`SeccompDenial`] made of the syscall number and plain register
//! arguments. Nothing is read through the caller's pointers, so no answer
//! and no record depends on memory the sandbox can change.
//!
//! **Fail closed.** Once the listener is closed (brokerd stopped, died or
//! never took it), the kernel fails every pending and later notified
//! syscall with ENOSYS; it never runs one.

use super::seccomp::Installed;
use super::syscalls::describe;
use crate::backends::linux::layer;
use crate::shim::{NOTIFY_FD, fd_closed};
use crate::{LayerStatus, SeccompDenial, SeccompFeed, SeccompStop};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};

// The structs the kernel copies; checked against its own sizes at run time.
const _: () = assert!(std::mem::size_of::<libc::seccomp_data>() == 64);
const _: () = assert!(std::mem::size_of::<libc::seccomp_notif>() == 80);
const _: () = assert!(std::mem::size_of::<libc::seccomp_notif_resp>() == 24);

/// The one byte that travels with the listener.
const TAG: u8 = b'L';
/// How often the serving thread looks at its stop flag.
const TICK: Duration = Duration::from_millis(250);
/// Most queued denials; past this a denial is still answered, not queued
/// (a session's rows are capped far below it).
const FEED_CAPACITY: usize = 4096;
/// What `/proc/self/fd/N` names a seccomp listener.
const LISTENER_LINK: &str = "anon_inode:seccomp notify";

fn seccomp(op: libc::c_uint, flags: libc::c_ulong, arg: *const libc::c_void) -> libc::c_long {
    // SAFETY: seccomp(2); every caller passes the argument type `op` expects.
    unsafe { libc::syscall(libc::SYS_seccomp, op, flags, arg) }
}

/// The kernel's sizes of the notification structs.
fn sizes() -> io::Result<libc::seccomp_notif_sizes> {
    // SAFETY: a plain struct of three u16, zero is valid.
    let mut s: libc::seccomp_notif_sizes = unsafe { std::mem::zeroed() };
    let p = &mut s as *mut libc::seccomp_notif_sizes as *const libc::c_void;
    if seccomp(libc::SECCOMP_GET_NOTIF_SIZES, 0, p) != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(s)
}

/// Whether this kernel can notify (`broker doctor`); installs nothing.
pub fn available() -> Result<String, String> {
    let action: u32 = libc::SECCOMP_RET_USER_NOTIF;
    if seccomp(libc::SECCOMP_GET_ACTION_AVAIL, 0, (&action as *const u32).cast()) != 0 {
        return Err(format!(
            "SECCOMP_RET_USER_NOTIF unavailable ({}): refused syscalls fail with EPERM, unrecorded",
            io::Error::last_os_error()
        ));
    }
    let s = sizes().map_err(|e| format!("SECCOMP_GET_NOTIF_SIZES: {e}"))?;
    Ok(format!("refused syscalls answered by brokerd and recorded (notif {} bytes)", s.seccomp_notif))
}

// ---------------------------------------------------------------------------
// In the shim
// ---------------------------------------------------------------------------

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const seccompiler::sock_filter,
}

/// Install `prog` and return its listener (O_CLOEXEC). With
/// `WAIT_KILLABLE_RECV` (Linux 5.19+) a caller whose notification brokerd
/// has received is no longer interrupted by ordinary signals (Go's
/// preemption signals would otherwise restart it again and again); older
/// kernels reject the flag with EINVAL and get the filter without it.
pub fn install_listener(prog: &seccompiler::BpfProgram) -> io::Result<OwnedFd> {
    let len = u16::try_from(prog.len()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let fprog = SockFprog { len, filter: prog.as_ptr() };
    let mut last = io::Error::from_raw_os_error(libc::EINVAL);
    for flags in [
        libc::SECCOMP_FILTER_FLAG_NEW_LISTENER | libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
        libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
    ] {
        let fd = seccomp(libc::SECCOMP_SET_MODE_FILTER, flags, (&fprog as *const SockFprog).cast());
        if fd >= 0 {
            // SAFETY: a fresh descriptor we own.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) });
        }
        last = io::Error::last_os_error();
        if last.raw_os_error() != Some(libc::EINVAL) {
            break;
        }
    }
    Err(last)
}

/// Send `fd` over the connected Unix socket `sock` (SCM_RIGHTS, one tag
/// byte). Stack buffers only: also used between fork and exit in tests.
pub fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    let tag = [TAG];
    let mut iov = libc::iovec { iov_base: tag.as_ptr() as *mut libc::c_void, iov_len: 1 };
    let mut control = [0u64; 4];
    // SAFETY: CMSG_* compute sizes and walk `control`, which we own and
    // which is large enough (checked); msghdr is plain data.
    unsafe {
        let space = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        if space > std::mem::size_of_val(&control) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<RawFd>(), fd);
        loop {
            let n = libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL);
            if n == 1 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if n < 0 && e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(if n < 0 { e } else { io::ErrorKind::WriteZero.into() });
        }
    }
}

/// Hand the listener to brokerd, close it and the channel, and refuse if
/// either is still open. Returns both numbers for the shim's last check
/// before exec. Without a listener (old kernel), the deny filter returns
/// EPERM in the kernel and nothing is recorded: the layer says so.
pub fn hand_over(installed: Installed, channel: bool, layers: &mut Vec<LayerStatus>) -> anyhow::Result<Vec<i32>> {
    let mut closed = Vec::new();
    let (ok, detail) = match installed {
        Installed::Notify(listener) => {
            let fd = listener.as_raw_fd();
            if let Err(e) = send_fd(NOTIFY_FD, fd) {
                // Dropping the listener on return fails every notified
                // syscall with ENOSYS; the launch is refused regardless.
                layers.push(layer("seccomp_notify", false, false, format!("sending the listener to brokerd: {e}")));
                anyhow::bail!("could not hand the seccomp listener to brokerd: {e}");
            }
            drop(listener);
            closed.push(fd);
            (true, "refused syscalls answered EPERM by brokerd and recorded (USER_NOTIF)".to_string())
        }
        Installed::Errno(why) => {
            let why = match why {
                Some(e) => format!("the kernel gave no listener ({e})"),
                None => "no channel to brokerd".to_string(),
            };
            (false, format!("not recorded: {why}; refused syscalls fail with EPERM in the kernel"))
        }
    };
    if channel {
        // SAFETY: NOTIFY_FD is the channel the launcher opened for the shim.
        unsafe { libc::close(NOTIFY_FD) };
        closed.push(NOTIFY_FD);
    }
    if let Some(fd) = closed.iter().find(|fd| !fd_closed(**fd)) {
        layers.push(layer("seccomp_notify", false, false, format!("fd {fd} still open")));
        anyhow::bail!("fd {fd} (the seccomp listener or its channel) is still open");
    }
    layers.push(layer("seccomp_notify", false, ok, detail));
    Ok(closed)
}

// ---------------------------------------------------------------------------
// In brokerd
// ---------------------------------------------------------------------------

/// A connected pair for one launch: (brokerd's end, the sandbox's end).
pub fn channel() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: socketpair(2) into a two-element array.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: two fresh descriptors we own.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Serve the listener that arrives on `ours` within `wait`, on a thread of
/// its own. `take: false` (fault injection) closes it unserved, as if
/// brokerd had not taken it. If the thread cannot start, `ours` closes with
/// it and the listener in flight with that: the shim's check then gets
/// ENOSYS and the launch is refused.
pub fn spawn_feed(ours: OwnedFd, wait: Duration, take: bool) -> SeccompFeed {
    let (tx, rx) = std::sync::mpsc::sync_channel(FEED_CAPACITY);
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let _ = std::thread::Builder::new().name("seccomp-notify".into()).spawn(move || {
        let Some(listener) = receive_listener(&ours, wait, &flag) else { return };
        drop(ours); // exactly one descriptor, then the channel is closed
        if take {
            serve(&listener, &tx, &flag);
        }
    });
    SeccompFeed { denials: rx, stop: SeccompStop(stop) }
}

enum Ready {
    In,
    Idle,
    Gone,
}

fn poll_in(fd: RawFd, timeout: Duration) -> Ready {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: one pollfd.
    let n = unsafe { libc::poll(&mut p, 1, timeout.as_millis().min(i32::MAX as u128) as i32) };
    if n < 0 {
        return if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted { Ready::Idle } else { Ready::Gone };
    }
    if n == 0 {
        Ready::Idle
    } else if p.revents & libc::POLLIN != 0 {
        Ready::In
    } else {
        // POLLHUP: every task under the filter has exited (or the peer closed).
        Ready::Gone
    }
}

fn receive_listener(sock: &OwnedFd, wait: Duration, stop: &AtomicBool) -> Option<OwnedFd> {
    let deadline = Instant::now() + wait;
    loop {
        if stop.load(Ordering::SeqCst) {
            return None;
        }
        let left = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())?;
        match poll_in(sock.as_raw_fd(), left.min(TICK)) {
            Ready::Idle => continue,
            Ready::Gone => return None,
            Ready::In => {}
        }
        let fd = recv_fd(sock.as_raw_fd()).ok()??;
        return is_listener(&fd).then_some(fd);
    }
}

/// One message carrying exactly one descriptor and the tag byte; anything
/// else (EOF, no descriptor, several, a truncated control message) is
/// `None`, and every descriptor that arrived is closed.
fn recv_fd(sock: RawFd) -> io::Result<Option<OwnedFd>> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    let mut control = [0u64; 8];
    let mut fds: Vec<OwnedFd> = Vec::new();
    // SAFETY: recvmsg into buffers we own; the CMSG_* walk stays within
    // msg_controllen as the kernel set it; each descriptor is taken once.
    let (n, flags) = unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control) as _;
        let n = loop {
            let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break n;
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let bytes = ((*c).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                let data = libc::CMSG_DATA(c).cast::<RawFd>();
                for i in 0..bytes / std::mem::size_of::<RawFd>() {
                    fds.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
        (n, msg.msg_flags)
    };
    if n != 1 || byte[0] != TAG || flags & libc::MSG_CTRUNC != 0 || fds.len() != 1 {
        return Ok(None);
    }
    Ok(fds.pop())
}

/// A seccomp listener answers NOTIF_ID_VALID for an unknown id with ENOENT
/// (any other file: ENOTTY or EINVAL), and where /proc is mounted its link
/// names it.
fn is_listener(fd: &OwnedFd) -> bool {
    let id: u64 = 0;
    // SAFETY: ID_VALID reads one u64.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &id as *const u64) };
    let enoent = r == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT);
    let link = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()));
    enoent && link.map(|l| l.as_os_str() == LISTENER_LINK).unwrap_or(true)
}

/// The caller's `comm`, read while it is held in the syscall (advisory).
fn comm(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let raw = std::fs::read(format!("/proc/{pid}/comm")).ok()?;
    let s = String::from_utf8_lossy(&raw);
    Some(s.trim_end_matches('\n').chars().take(16).map(|c| if c.is_control() { '?' } else { c }).collect())
}

fn id_valid(fd: RawFd, id: u64) -> bool {
    // SAFETY: ID_VALID reads one u64.
    unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &id as *const u64) == 0 }
}

/// One notification at a time: answer `-EPERM`, then queue the record.
/// Returns when stopped, when every task under the filter has exited, or
/// on an error from the listener; the listener closes with the caller's
/// drop, after which the kernel answers ENOSYS itself.
fn serve(listener: &OwnedFd, tx: &SyncSender<SeccompDenial>, stop: &AtomicBool) {
    let fd = listener.as_raw_fd();
    let Ok(sizes) = sizes() else { return };
    // The kernel copies its own struct sizes: buffers at least that large.
    let words = |kernel: u16, ours: usize| (kernel as usize).max(ours).div_ceil(8);
    let mut req = vec![0u64; words(sizes.seccomp_notif, std::mem::size_of::<libc::seccomp_notif>())];
    let mut resp = vec![0u64; words(sizes.seccomp_notif_resp, std::mem::size_of::<libc::seccomp_notif_resp>())];
    while !stop.load(Ordering::SeqCst) {
        match poll_in(fd, TICK) {
            Ready::Idle => continue,
            Ready::Gone => return,
            Ready::In => {}
        }
        req.fill(0); // the kernel requires a zeroed request
        // SAFETY: req is at least the kernel's seccomp_notif size, u64-aligned.
        if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_RECV, req.as_mut_ptr()) } != 0 {
            match io::Error::last_os_error().raw_os_error() {
                // ENOENT: the caller was interrupted or killed before we took it.
                Some(libc::EINTR) | Some(libc::ENOENT) => continue,
                _ => return,
            }
        }
        // SAFETY: the kernel wrote a seccomp_notif at the start of req.
        let n: libc::seccomp_notif = unsafe { std::ptr::read(req.as_ptr().cast()) };
        // The pid is valid while the caller is held; ID_VALID afterwards
        // proves the comm read was of that caller, not a reused pid.
        let process = comm(n.pid).filter(|_| id_valid(fd, n.id));
        resp.fill(0);
        let answer = libc::seccomp_notif_resp { id: n.id, val: 0, error: -libc::EPERM, flags: 0 };
        // SAFETY: resp is at least the kernel's seccomp_notif_resp size.
        unsafe {
            std::ptr::write(resp.as_mut_ptr().cast(), answer);
            // ENOENT: the caller was interrupted meanwhile (it is notified
            // again when the call restarts) or killed.
            libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_SEND, resp.as_mut_ptr());
        }
        let nr = i64::from(n.data.nr);
        let (syscall, args) = describe(nr, &n.data.args);
        // A full queue loses the record, never the answer.
        let _ = tx.try_send(SeccompDenial { pid: n.pid, process, nr, syscall, args });
    }
}

#[cfg(test)]
#[path = "notify_tests.rs"]
mod tests;
