//! Killing a session's processes at teardown, including those that left
//! its process group.
//!
//! The sandbox root leads its own process group, but nothing stops a
//! process inside from calling `setsid()`: Seatbelt does not mediate it.
//! On Linux the sandbox is a PID namespace whose init takes every member
//! with it (`--unshare-pid --die-with-parent`), so the group kill is
//! enough. On macOS there is no such container. Members are found two ways
//! and stopped before anything is killed, because a stopped process cannot
//! fork:
//! - by sandbox: every process of this user under the session's own
//!   Seatbelt profile ([`in_session_sandbox`]), which also finds a process
//!   that double-forked and was reparented to launchd;
//! - by ancestry: the root's process group and every descendant of a
//!   member, by parent pid. This finds them while their parents live, even
//!   without the profile.
//!
//! See ADR-049.
//!
//! [`in_session_sandbox`]: crate::backends::seatbelt::in_session_sandbox

use std::path::Path;

/// Rounds of finding and stopping members before the kill. Each round only
/// adds processes forked before the previous round's stops landed.
#[cfg(target_os = "macos")]
const ROUNDS: usize = 32;

/// SIGKILL the session whose sandbox root is `root` (the leader of its
/// process group) and every process found to belong to it. `session_dir`
/// identifies the session's Seatbelt profile on macOS. Returns the pids
/// signalled besides the group.
pub fn kill_session(root: u32, session_dir: Option<&Path>) -> Vec<i32> {
    #[cfg(target_os = "macos")]
    {
        let held = stop_members(root as i32, session_dir);
        // SAFETY: plain kill(2); SIGKILL also ends a stopped process.
        unsafe { libc::kill(-(root as i32), libc::SIGKILL) };
        for &p in &held {
            unsafe { libc::kill(p, libc::SIGKILL) };
        }
        held
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = session_dir;
        // SAFETY: plain kill(2) on the group the sandbox leads.
        unsafe { libc::kill(-(root as i32), libc::SIGKILL) };
        Vec::new()
    }
}

#[cfg(target_os = "macos")]
struct Proc {
    pid: i32,
    ppid: i32,
    pgid: i32,
    uid: u32,
}

/// Every process the kernel lists that we may inspect.
#[cfg(target_os = "macos")]
fn processes() -> Vec<Proc> {
    use std::mem::size_of;
    // SAFETY: a null buffer asks for the count only.
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0 as libc::pid_t; n as usize + 256];
    let bytes = (pids.len() * size_of::<libc::pid_t>()) as libc::c_int;
    // SAFETY: the buffer holds `bytes` bytes; the result is a pid count.
    let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    pids.truncate(got.clamp(0, pids.len() as libc::c_int) as usize);
    pids.into_iter()
        .filter(|&pid| pid > 1)
        .filter_map(|pid| {
            // SAFETY: proc_bsdinfo is plain data; zeroed is a valid value.
            let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
            let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
            // SAFETY: the buffer is one proc_bsdinfo of `size` bytes.
            let r = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) };
            (r == size).then_some(Proc {
                pid,
                ppid: info.pbi_ppid as i32,
                pgid: info.pbi_pgid as i32,
                uid: info.pbi_uid,
            })
        })
        .collect()
}

/// SIGSTOP the session's processes until a round finds no new one.
#[cfg(target_os = "macos")]
fn stop_members(root: i32, session_dir: Option<&Path>) -> Vec<i32> {
    use std::collections::BTreeSet;
    let me = std::process::id() as i32;
    // SAFETY: getuid(2) cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut held: BTreeSet<i32> = BTreeSet::new();
    // SAFETY: plain kill(2) on the group the sandbox leads.
    unsafe { libc::kill(-root, libc::SIGSTOP) };
    for _ in 0..ROUNDS {
        let procs: Vec<Proc> = processes().into_iter().filter(|p| p.uid == uid && p.pid != me).collect();
        let mut members: BTreeSet<i32> = held.clone();
        for p in &procs {
            // The group's pgid cannot be reused while a member lives, so
            // matching it never names a stranger; the pid alone might.
            let sandboxed = session_dir.is_some_and(|d| crate::backends::seatbelt::in_session_sandbox(p.pid, d));
            if p.pgid == root || sandboxed {
                members.insert(p.pid);
            }
        }
        loop {
            let before = members.len();
            for p in &procs {
                if members.contains(&p.ppid) {
                    members.insert(p.pid);
                }
            }
            if members.len() == before {
                break;
            }
        }
        let new: Vec<i32> = members.difference(&held).copied().collect();
        if new.is_empty() {
            break;
        }
        for &p in &new {
            // SAFETY: plain kill(2).
            unsafe { libc::kill(p, libc::SIGSTOP) };
        }
        held.extend(new);
    }
    held.into_iter().collect()
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::backends::seatbelt::{CANARY, MARKER, in_session_sandbox, sbpl};
    use std::time::{Duration, Instant};

    fn alive(pid: i32) -> bool {
        // SAFETY: signal 0 probes only.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    fn wait_for(p: &Path) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !p.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::read_to_string(p).unwrap().trim().parse().unwrap()
    }

    /// TB2: a process under the session's profile that left the group and
    /// was reparented to launchd (setsid, then a double fork whose middle
    /// process exits) is still found and killed; a process under another
    /// session's profile, and one outside any sandbox, are not.
    #[test]
    fn a_daemonised_process_of_the_session_is_killed_and_no_other() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let mk = |n: &str| {
            let p = root.join(n);
            std::fs::create_dir_all(&p).unwrap();
            p
        };
        let (s1, s2, scratch) = (mk("s1"), mk("s2"), mk("scratch"));
        let profile = |dir: &Path| {
            std::fs::write(dir.join(MARKER), b"").unwrap();
            std::fs::write(dir.join(CANARY), b"c").unwrap();
            let fs = crate::CompiledFsPolicy {
                read_only_root: true,
                writable: vec![scratch.clone()],
                deny_read: vec![s1.clone(), s2.clone()],
                ..Default::default()
            };
            let marker = dir.join(MARKER);
            let p = sbpl::generate(&sbpl::SbplInputs {
                fs: &fs,
                broker_port: 1,
                tty: None,
                tag: None,
                marker: Some(&marker),
            })
            .unwrap();
            let f = dir.join("p.sb");
            std::fs::write(&f, p).unwrap();
            f
        };
        let spawn = |prof: Option<&Path>, out: &Path| {
            // Fork; the child calls setsid and forks the process that
            // writes its pid and sleeps; the middle one exits at once.
            let script = format!(
                "use POSIX; if (fork() == 0) {{ POSIX::setsid(); if (fork() == 0) {{ open(my $f, '>', '{0}.tmp'); \
                 print $f $$; close $f; rename('{0}.tmp', '{0}'); sleep 30; }} exit 0 }} sleep 30;",
                out.display()
            );
            let mut c = match prof {
                Some(p) => {
                    let mut c = std::process::Command::new(crate::backends::seatbelt::SANDBOX_EXEC);
                    c.arg("-f").arg(p).arg("/usr/bin/perl");
                    c
                }
                None => std::process::Command::new("/usr/bin/perl"),
            };
            use std::os::unix::process::CommandExt;
            c.arg("-e").arg(script);
            // SAFETY: setsid is async-signal-safe.
            unsafe {
                c.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
            c.spawn().unwrap()
        };
        let mut ours = spawn(Some(&profile(&s1)), &scratch.join("ours.pid"));
        let mut theirs = spawn(Some(&profile(&s2)), &scratch.join("theirs.pid"));
        let mut plain = spawn(None, &scratch.join("plain.pid"));
        let (o, t, p) = (
            wait_for(&scratch.join("ours.pid")),
            wait_for(&scratch.join("theirs.pid")),
            wait_for(&scratch.join("plain.pid")),
        );
        assert!(in_session_sandbox(o, &s1) && !in_session_sandbox(t, &s1) && !in_session_sandbox(p, &s1));
        assert!(in_session_sandbox(t, &s2));

        let killed = kill_session(ours.id(), Some(&s1));
        let _ = ours.wait();
        std::thread::sleep(Duration::from_millis(300));
        let (o_alive, t_alive, p_alive) = (alive(o), alive(t), alive(p));
        for (pid, child) in [(t, &mut theirs), (p, &mut plain)] {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
        }
        unsafe { libc::kill(o, libc::SIGKILL) };
        assert!(killed.contains(&o), "{killed:?} lacks {o}");
        assert!(!o_alive, "the session's daemonised process {o} survived teardown");
        assert!(t_alive && p_alive, "a process of another session or of no sandbox was killed");
    }
}
