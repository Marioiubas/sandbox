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
    use std::os::unix::fs::MetadataExt;
    let uid = nix::unistd::getuid().as_raw();
    let mut cur = Some(cwd);
    while let Some(d) = cur {
        if let Ok(m) = std::fs::symlink_metadata(d.join(".git")) {
            // A repository another user owns is not this user's task
            // repository (as git refuses it since CVE-2022-24765).
            return if m.uid() == uid { d.to_path_buf() } else { cwd.to_path_buf() };
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

    /// Review (I5, I4): `${repo_remote}` names the session's task repository
    /// (push rules, GitHub verbs' default `repos`, GitHub App token repos).
    /// It is read from the nearest `.git` above the session's directory. A
    /// session rooted at `web/` can write `web/sub/.git` (the launcher
    /// protects `.git` only at the writable root; launcher
    /// `fs_compile::tests::review_nested_repositories_cannot_grow_hooks_or_config`)
    /// and a gitdir it controls. When the user later starts a session from
    /// `web/sub` (a package of a monorepo), that file chooses the task
    /// repository: any repository the user's GitHub App installation covers.
    #[test]
    fn review_a_gitdir_planted_below_the_root_does_not_choose_the_task_repository() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let (home, tmp) = (root.join("home"), root.join("tmp/s1"));
        let web = home.join("src/web");
        std::fs::create_dir_all(web.join(".git")).unwrap();
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(web.join(".git/config"), "[remote \"origin\"]\n\turl = https://github.com/acme/web.git\n")
            .unwrap();
        // The filesystem policy of an earlier session rooted at `web`.
        let fs = launcher::fs_compile::compile(&launcher::fs_compile::FsInputs {
            home: home.clone(),
            repo: web.clone(),
            session_tmp: tmp,
            ..Default::default()
        })
        .unwrap();
        // What that session writes (ordinary files below its root).
        let planted = [web.join("sub/.git"), web.join("sub/.cache/g/config")];
        std::fs::create_dir_all(web.join("sub/.cache/g")).unwrap();
        std::fs::write(&planted[0], "gitdir: .cache/g\n").unwrap();
        std::fs::write(&planted[1], "[remote \"origin\"]\n\turl = https://github.com/acme/prod-infra.git\n").unwrap();
        // A later session started from `web/sub`.
        let task = origin_remote(&repo_root(&web.join("sub")));
        let writable: Vec<&PathBuf> = planted.iter().filter(|p| fs.is_writable(p)).collect();
        assert!(
            !(task == RepoId::parse("github.com/acme/prod-infra") && writable.len() == planted.len()),
            "the task repository of a session started in web/sub ({task:?}) was chosen by files an earlier session \
             could write: {writable:?}"
        );
    }

    /// Review (I5, I4; the planted-gitdir case above, ADR-046): the
    /// nested-repository rule covers only the session's repository root.
    /// On macOS the per-user temp dir (`DARWIN_USER_TEMP_DIR`, the `$TMPDIR`
    /// that `mktemp -d` uses) is a writable root of every session
    /// (ADR-016), and below its own top level nothing stops a session from
    /// creating `<T>/<dir>/.git/config`. `repo_root` takes the nearest
    /// `.git` above the cwd without asking who made it (git itself refuses
    /// a repository it does not own since CVE-2022-24765), so a later
    /// session the user starts in that scratch directory gets its task
    /// repository (`${repo_remote}`: push rules, GitHub verbs, GitHub App
    /// token repos) from a file an earlier agent wrote.
    #[test]
    fn review_a_gitdir_planted_in_the_shared_temp_dir_does_not_choose_the_task_repository() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let (home, tmp, platform_tmp) = (root.join("home"), root.join("T/broker-s1"), root.join("T"));
        let web = home.join("src/web");
        std::fs::create_dir_all(web.join(".git")).unwrap();
        std::fs::create_dir_all(&tmp).unwrap();
        // The filesystem policy of an earlier session, as `launch` compiles it on macOS.
        let fs = launcher::fs_compile::compile(&launcher::fs_compile::FsInputs {
            home: home.clone(),
            repo: web.clone(),
            session_tmp: tmp,
            platform_tmp: Some(platform_tmp.clone()),
            ..Default::default()
        })
        .unwrap();
        // What that session writes: a user's earlier scratch dir in $TMPDIR gains a gitdir.
        let scratch = platform_tmp.join("tmp.Qx81");
        let planted = [scratch.join(".git"), scratch.join(".git/config")];
        std::fs::create_dir_all(&planted[0]).unwrap();
        std::fs::write(&planted[1], "[remote \"origin\"]\n\turl = https://github.com/acme/prod-infra.git\n").unwrap();
        // A later session the user starts there.
        let task = origin_remote(&repo_root(&scratch.join("proto")));
        let writable: Vec<&PathBuf> = planted.iter().filter(|p| fs.is_writable(p)).collect();
        assert!(
            !(task == RepoId::parse("github.com/acme/prod-infra") && writable.len() == planted.len()),
            "the task repository of a session started in {} ({task:?}) was chosen by files an earlier session could \
             write: {writable:?}",
            scratch.join("proto").display()
        );
    }

    #[test]
    fn env_allowlist_has_no_secrets() {
        for k in ENV_ALLOW {
            assert!(!policy::config::env_name_is_secretish(k), "{k}");
        }
    }
}
