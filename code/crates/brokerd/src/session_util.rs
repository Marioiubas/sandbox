//! Session helpers: environment allowlist, path variables, repository
//! discovery (never by running git), signal targets.

use crate::dirs::BrokerDirs;
use crate::proto::Exited;
use policy::{PolicyFile, RepoId};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// Non-secret variables copied from the client's environment.
pub const ENV_ALLOW: &[&str] = &[
    "PATH",
    "TERM",
    "COLORTERM",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_COLLATE",
    "LC_NUMERIC",
    "LC_TIME",
    "TZ",
    "NO_COLOR",
    "FORCE_COLOR",
    "CLICOLOR",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "EDITOR",
    "VISUAL",
    "PAGER",
    "COLUMNS",
    "LINES",
];

pub fn expand_home(p: &str, home: &Path) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(p),
    }
}

/// `cwd` with every non-alphanumeric byte replaced by `-` (the per-project
/// directory naming some agents use for scratch space).
pub fn cwd_slug(cwd: &Path) -> String {
    cwd.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect()
}

/// Profile path variables: `~/`, `${uid}` and `${cwd_slug}`. The result must
/// be absolute; the filesystem compiler rejects anything else.
pub fn expand_profile_path(p: &str, home: &Path, cwd: &Path) -> PathBuf {
    let uid = nix::unistd::getuid().as_raw().to_string();
    let s = p.replace("${uid}", &uid).replace("${cwd_slug}", &cwd_slug(cwd));
    expand_home(&s, home)
}

/// The nearest ancestor of `cwd` containing `.git`, else `cwd`. Never runs
/// git on the host: repo config can execute code (core.fsmonitor).
pub fn repo_root(cwd: &Path) -> PathBuf {
    let mut cur = Some(cwd);
    while let Some(d) = cur {
        if std::fs::symlink_metadata(d.join(".git")).is_ok() {
            return d.to_path_buf();
        }
        cur = d.parent();
    }
    cwd.to_path_buf()
}

pub fn new_sentinel() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS randomness");
    format!("bks1_{}", hex::encode(b))
}

pub fn resolve_command(argv0: &str, path: Option<&str>, cwd: &Path) -> Option<PathBuf> {
    if argv0.contains('/') {
        let p = if argv0.starts_with('/') { PathBuf::from(argv0) } else { cwd.join(argv0) };
        return p.canonicalize().ok();
    }
    for dir in path.unwrap_or("/usr/bin:/bin").split(':').filter(|d| d.starts_with('/')) {
        let p = Path::new(dir).join(argv0);
        if let Ok(m) = std::fs::metadata(&p) {
            use std::os::unix::fs::PermissionsExt;
            if m.is_file() && m.permissions().mode() & 0o111 != 0 {
                return p.canonicalize().ok();
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
pub fn darwin_user_temp_dir() -> Option<PathBuf> {
    let mut buf = vec![0u8; 1024];
    // SAFETY: confstr writes at most buf.len() bytes including the NUL.
    let n = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), buf.len()) };
    if n == 0 || n > buf.len() {
        return None;
    }
    buf.truncate(n - 1);
    String::from_utf8(buf).ok().map(PathBuf::from).and_then(|p| p.canonicalize().ok())
}

pub fn tty_path(fds: &[OwnedFd]) -> Option<PathBuf> {
    for fd in fds {
        let mut buf = [0u8; 256];
        // SAFETY: ttyname_r writes a NUL-terminated name into buf.
        let r = unsafe { libc::ttyname_r(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if r == 0 {
            let end = buf.iter().position(|b| *b == 0)?;
            return std::str::from_utf8(&buf[..end]).ok().map(PathBuf::from);
        }
    }
    None
}

pub fn load_user_policy(dirs: &BrokerDirs) -> anyhow::Result<PolicyFile> {
    let f = dirs.config_file();
    if f.exists() { policy::load_policy_file(&f) } else { Ok(PolicyFile { version: 1, ..Default::default() }) }
}

/// On Linux the child is bwrap; signals for the agent go to the process
/// whose innermost PID is 2 (bwrap's init is 1) among bwrap's descendants.
#[cfg(target_os = "linux")]
pub fn signal_target(root: u32) -> u32 {
    use std::collections::HashMap;
    let mut parent_of = HashMap::new();
    let mut inner_pid = HashMap::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for e in rd.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
            let Ok(st) = std::fs::read_to_string(format!("/proc/{pid}/status")) else { continue };
            for line in st.lines() {
                if let Some(v) = line.strip_prefix("PPid:") {
                    parent_of.insert(pid, v.trim().parse::<u32>().unwrap_or(0));
                }
                if let Some(v) = line.strip_prefix("NSpid:")
                    && let Some(last) = v.split_whitespace().last()
                {
                    inner_pid.insert(pid, last.parse::<u32>().unwrap_or(0));
                }
            }
        }
    }
    let descends = |mut p: u32| {
        for _ in 0..16 {
            match parent_of.get(&p) {
                Some(&pp) if pp == root => return true,
                Some(&pp) if pp > 1 => p = pp,
                _ => return false,
            }
        }
        false
    };
    inner_pid.iter().find(|(pid, inner)| **inner == 2 && descends(**pid)).map(|(p, _)| *p).unwrap_or(root)
}

#[cfg(not(target_os = "linux"))]
pub fn signal_target(root: u32) -> u32 {
    root
}

pub fn exited_from(status: std::io::Result<std::process::ExitStatus>) -> Exited {
    use std::os::unix::process::ExitStatusExt;
    match status {
        Ok(s) => Exited { code: s.code(), signal: s.signal() },
        Err(_) => Exited { code: None, signal: None },
    }
}

/// The `origin` remote of a checkout, read from its config file. The
/// sandbox's view of the repository names the repository the session may
/// push to; git is never run on the host to find it (core.fsmonitor and
/// friends execute code).
pub fn origin_remote(repo: &Path) -> Option<RepoId> {
    let dotgit = repo.join(".git");
    let meta = std::fs::symlink_metadata(&dotgit).ok()?;
    let gitdir = if meta.is_dir() {
        dotgit
    } else {
        let text = std::fs::read_to_string(&dotgit).ok()?;
        let p = PathBuf::from(text.trim().strip_prefix("gitdir:")?.trim());
        let p = if p.is_absolute() { p } else { repo.join(p) };
        match std::fs::read_to_string(p.join("commondir")) {
            Ok(c) => {
                let c = PathBuf::from(c.trim());
                if c.is_absolute() { c } else { p.join(c) }
            }
            Err(_) => p,
        }
    };
    let config = std::fs::read_to_string(gitdir.join("config")).ok()?;
    let mut in_origin = false;
    for line in config.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_origin = l == "[remote \"origin\"]";
            continue;
        }
        if in_origin
            && let Some((k, v)) = l.split_once('=')
            && k.trim().eq_ignore_ascii_case("url")
        {
            return RepoId::from_remote_url(v.trim().trim_matches('"'));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn repo_root_walks_up() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path().canonicalize().unwrap();
        std::fs::create_dir_all(r.join("proj/.git")).unwrap();
        std::fs::create_dir_all(r.join("proj/src/deep")).unwrap();
        assert_eq!(repo_root(&r.join("proj/src/deep")), r.join("proj"));
        assert_eq!(repo_root(&r), r);
    }

    #[test]
    fn profile_path_variables() {
        // Matches the directory Claude Code 2.1.268 created for this cwd.
        assert_eq!(
            cwd_slug(Path::new("/private/tmp/claude-501/-Users-x/repo1")),
            "-private-tmp-claude-501--Users-x-repo1"
        );
        let p = expand_profile_path("/tmp/claude-${uid}/${cwd_slug}", Path::new("/home/u"), Path::new("/src/a.b"));
        let uid = nix::unistd::getuid().as_raw();
        assert_eq!(p, PathBuf::from(format!("/tmp/claude-{uid}/-src-a-b")));
        assert_eq!(
            expand_profile_path("~/.claude/projects", Path::new("/home/u"), Path::new("/x")),
            PathBuf::from("/home/u/.claude/projects")
        );
    }

    #[test]
    fn sentinel_shape() {
        let s = new_sentinel();
        assert!(s.starts_with("bks1_") && s.len() == 5 + 64);
        assert_ne!(s, new_sentinel());
    }

    #[test]
    fn env_allowlist_has_no_secrets() {
        for k in ENV_ALLOW {
            assert!(!policy::config::env_name_is_secretish(k), "{k}");
        }
    }
}
