//! The kernel's side of ADR-043, in forked children (which run only raw
//! syscalls on memory allocated before the fork, then `_exit`): the deny
//! filter with a listener refuses every listed syscall with ENOSYS when no
//! one serves the listener, with EPERM when brokerd's loop does (each one
//! recorded with its plain arguments), and with ENOSYS again once brokerd
//! stops mid-session. A second listener on the chain falls back to EPERM,
//! which outranks the first filter's USER_NOTIF.

use super::*;
use crate::backends::linux::inner::seccomp::{
    CLONE_NS_FLAGS, Installed, denied_syscalls, enosys_filters, eperm_filter, fixed_filter, install, notify_filter,
};
use std::io::Read;

/// A refused syscall with arguments under which, were it not refused, it
/// would fail some other way or do nothing that outlives the child.
fn probes() -> Vec<(i64, [u64; 6])> {
    let sock = |d: i32, t: i32| (libc::SYS_socket, [d as u64, t as u64, 0, 0, 0, 0]);
    let mut v = vec![
        sock(libc::AF_UNIX, libc::SOCK_STREAM),
        sock(libc::AF_PACKET, libc::SOCK_RAW),
        sock(libc::AF_INET, libc::SOCK_RAW),
        sock(libc::AF_INET6, libc::SOCK_RAW),
        (libc::SYS_ioctl, [u32::MAX as u64, libc::TIOCSTI, 0, 0, 0, 0]),
        (libc::SYS_ioctl, [u32::MAX as u64, libc::TIOCLINUX, 0, 0, 0, 0]),
    ];
    v.extend(CLONE_NS_FLAGS.iter().map(|f| (libc::SYS_clone, [(*f | libc::SIGCHLD) as u64, 0, 0, 0, 0, 0])));
    v.extend(denied_syscalls().into_iter().map(|nr| (nr, [u64::MAX; 6])));
    v
}

/// Each probe's errno (0: it was not refused). Raw syscalls only.
fn run_probes(probes: &[(i64, [u64; 6])], out: &mut [i32]) {
    for (i, (nr, a)) in probes.iter().enumerate() {
        // SAFETY: the probes' arguments are plain values or invalid pointers.
        let rc = unsafe { libc::syscall(*nr, a[0], a[1], a[2], a[3], a[4], a[5]) };
        if *nr == libc::SYS_clone && rc == 0 {
            // A clone that was not refused: the new process leaves at once.
            unsafe { libc::_exit(0) };
        }
        out[i] = if rc < 0 { io::Error::last_os_error().raw_os_error().unwrap_or(-1) } else { 0 };
    }
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut f = [0 as RawFd; 2];
    // SAFETY: pipe2 into a two-element array.
    assert_eq!(unsafe { libc::pipe2(f.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: two fresh descriptors we own.
    unsafe { (OwnedFd::from_raw_fd(f[0]), OwnedFd::from_raw_fd(f[1])) }
}

fn write_i32s(fd: RawFd, v: &[i32]) {
    // SAFETY: writes the bytes of a slice we own.
    unsafe { libc::write(fd, v.as_ptr().cast(), std::mem::size_of_val(v)) };
}

/// Read `n` i32s within 20 s (a child stuck in a syscall fails the test
/// instead of hanging it).
fn read_i32s(fd: &OwnedFd, n: usize, child: libc::pid_t) -> Vec<i32> {
    let mut buf = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut f = std::fs::File::from(fd.try_clone().unwrap());
    while buf.len() < n * 4 {
        let left = deadline.saturating_duration_since(Instant::now());
        if matches!(poll_in(fd.as_raw_fd(), left), Ready::Idle) || left.is_zero() {
            // SAFETY: plain kill of our own child.
            unsafe { libc::kill(child, libc::SIGKILL) };
            panic!("child {child} gave {} of {} results in 20 s", buf.len() / 4, n);
        }
        let mut chunk = [0u8; 256];
        let k = f.read(&mut chunk[..(n * 4 - buf.len()).min(256)]).unwrap();
        assert!(k > 0, "child {child} closed its results early (exit {})", wait(child));
        buf.extend_from_slice(&chunk[..k]);
    }
    buf.chunks(4).map(|c| i32::from_ne_bytes(c.try_into().unwrap())).collect()
}

fn wait(pid: libc::pid_t) -> i32 {
    let mut st = 0;
    // SAFETY: waitpid on our own child.
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 128 + libc::WTERMSIG(st) }
}

fn no_new_privs_or_exit() {
    // SAFETY: plain prctl; _exit in a forked child.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            libc::_exit(2);
        }
    }
}

#[test]
fn this_kernel_can_notify() {
    // Every supported CI kernel (5.0+) can; ADR-043 keeps EPERM otherwise.
    available().unwrap();
}

/// brokerd absent: the listener is closed and no syscall the deny filter
/// lists runs; each fails with ENOSYS (not some other errno, which would
/// mean the filter let it through to the kernel's own checks).
#[test]
fn unserved_listener_fails_every_refused_syscall_with_enosys() {
    let (enosys, notify, eperm) = (enosys_filters().unwrap(), notify_filter().unwrap(), eperm_filter().unwrap());
    let probes = probes();
    let mut results = vec![0i32; probes.len()];
    let (r, w) = pipe();
    // SAFETY: the child runs raw syscalls on memory allocated before the fork.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        drop(r);
        no_new_privs_or_exit();
        let Ok(Installed::Notify(listener)) = install(&enosys, Some(&notify), &eperm, &fixed_filter().unwrap()) else {
            unsafe { libc::_exit(3) }
        };
        drop(listener); // no one will ever answer
        run_probes(&probes, &mut results);
        write_i32s(w.as_raw_fd(), &results);
        unsafe { libc::_exit(0) }
    }
    drop(w);
    let got = read_i32s(&r, probes.len(), pid);
    assert_eq!(wait(pid), 0);
    for (p, e) in probes.iter().zip(&got) {
        assert_eq!(*e, libc::ENOSYS, "{p:?}");
    }
}

/// brokerd present: the listener crosses the channel, brokerd's loop
/// answers EPERM to every refused syscall and records each with its
/// syscall name and plain arguments; when brokerd stops (mid-session), the
/// same syscall fails with ENOSYS.
#[test]
fn served_listener_answers_eperm_records_each_and_fails_closed_after() {
    let (enosys, notify, eperm) = (enosys_filters().unwrap(), notify_filter().unwrap(), eperm_filter().unwrap());
    let probes = probes();
    let n = probes.len();
    let mut results = vec![0i32; n + 1];
    let (ours, theirs) = channel().unwrap();
    let (rr, rw) = pipe();
    let (gr, gw) = pipe();
    // SAFETY: as above.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        drop((ours, rr, gw));
        no_new_privs_or_exit();
        let Ok(Installed::Notify(listener)) = install(&enosys, Some(&notify), &eperm, &fixed_filter().unwrap()) else {
            unsafe { libc::_exit(3) }
        };
        if send_fd(theirs.as_raw_fd(), listener.as_raw_fd()).is_err() {
            unsafe { libc::_exit(4) }
        }
        drop((listener, theirs));
        run_probes(&probes, &mut results[..n]);
        write_i32s(rw.as_raw_fd(), &results[..n]);
        let mut go = [0u8; 1];
        // SAFETY: read one byte; the parent writes it once brokerd stopped.
        unsafe { libc::read(gr.as_raw_fd(), go.as_mut_ptr().cast(), 1) };
        run_probes(&probes[..1], &mut results[n..]);
        write_i32s(rw.as_raw_fd(), &results[n..]);
        unsafe { libc::_exit(0) }
    }
    drop((theirs, rw, gr));
    let feed = spawn_feed(ours, Duration::from_secs(10), true);
    let got = read_i32s(&rr, n, pid);
    for (p, e) in probes.iter().zip(&got) {
        assert_eq!(*e, libc::EPERM, "{p:?}");
    }
    let mut seen = Vec::new();
    while seen.len() < n {
        seen.push(feed.denials.recv_timeout(Duration::from_secs(5)).expect("one denial per refused syscall"));
    }
    for ((nr, args), d) in probes.iter().zip(&seen) {
        let (name, plain) = describe(*nr, args);
        assert_eq!((d.nr, d.syscall, &d.args), (*nr, name, &plain), "{d:?}");
        assert_eq!(d.pid, pid as u32);
        assert!(d.process.is_some(), "{d:?}");
    }
    assert_eq!(
        seen[0].args,
        vec![("domain", libc::AF_UNIX as u64), ("type", libc::SOCK_STREAM as u64), ("protocol", 0)]
    );
    // brokerd stops: the serving thread closes the listener and drops the
    // feed's sender, which ends the receiver.
    let SeccompFeed { denials, stop } = feed;
    drop(stop);
    loop {
        match denials.recv_timeout(Duration::from_secs(5)) {
            Ok(_) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(e) => panic!("the serving thread did not stop: {e}"),
        }
    }
    write_i32s(gw.as_raw_fd(), &[1]);
    let after = read_i32s(&rr, 1, pid);
    assert_eq!(after, vec![libc::ENOSYS], "socket(AF_UNIX) once brokerd is gone");
    assert_eq!(wait(pid), 0);
}

/// Another listener already on the chain (EBUSY): the deny filter goes in
/// with EPERM, and its ERRNO outranks the first filter's USER_NOTIF, so the
/// call fails at once instead of waiting on a listener no one serves.
#[test]
fn a_second_listener_falls_back_to_eperm_which_outranks_notify() {
    let (enosys, notify, eperm) = (enosys_filters().unwrap(), notify_filter().unwrap(), eperm_filter().unwrap());
    let probes = probes();
    let mut results = vec![0i32; probes.len() + 1];
    let (r, w) = pipe();
    // SAFETY: as above.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        drop(r);
        no_new_privs_or_exit();
        let Ok(first) = install_listener(&notify) else { unsafe { libc::_exit(3) } };
        let Ok(Installed::Errno(Some(e))) = install(&enosys, Some(&notify), &eperm, &fixed_filter().unwrap()) else {
            unsafe { libc::_exit(4) }
        };
        results[0] = e.raw_os_error().unwrap_or(-1);
        run_probes(&probes, &mut results[1..]);
        write_i32s(w.as_raw_fd(), &results);
        drop(first);
        unsafe { libc::_exit(0) }
    }
    drop(w);
    let got = read_i32s(&r, probes.len() + 1, pid);
    assert_eq!(wait(pid), 0);
    assert_eq!(got[0], libc::EBUSY, "one listener per filter chain");
    for (p, e) in probes.iter().zip(&got[1..]) {
        assert_eq!(*e, libc::EPERM, "{p:?}");
    }
}
