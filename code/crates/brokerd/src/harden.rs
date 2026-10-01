//! Process hardening for the daemon, which holds minted credentials and the
//! keys that mint them: no core dumps, and on Linux not dumpable, so no other
//! process of the same user can read its memory through `/proc` or ptrace
//! (Risk Register R4). Sandboxes cannot reach brokerd at all (TB1); this
//! keeps a crash, or another process on the host, from copying its secrets.
//! Applied before anything is loaded; if it fails, the daemon does not start.

/// Disable core dumps and (Linux) make the process non-dumpable.
pub fn process() -> std::io::Result<()> {
    let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: plain syscall with a valid pointer to a local.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    // SAFETY: plain prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_core_dumps_and_not_dumpable() {
        super::process().unwrap();
        let mut r = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
        // SAFETY: valid pointer to a local.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut r) }, 0);
        assert_eq!((r.rlim_cur, r.rlim_max), (0, 0), "hard limit too, so it cannot be raised again");
        #[cfg(target_os = "linux")]
        // SAFETY: plain prctl.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    }
}
