//! Filesystem fixtures and assertions for categories 10 and I5.
//!
//! A filesystem probe of a path that does not exist fails with ENOENT
//! whether or not the sandbox protects it, so it proves nothing. Every path
//! probed here therefore exists on the host first, at a host path the
//! sandbox sees on every platform (never under /tmp, which is a private
//! tmpfs inside the Linux sandbox), and a probe passes only if the kernel
//! refused it (`conformance-probe` exit 10: EACCES, EPERM or EROFS). The few
//! other errnos a platform uses as its refusal are accepted by name, on that
//! platform only, where a test says so.

use crate::ProbeResult;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A directory at a real host path that the sandbox sees on every platform
/// and that no sandbox makes writable: under /var/tmp, because /tmp inside
/// the Linux sandbox is a private tmpfs where a host path is simply absent.
/// Short enough for the Unix socket paths of a `BROKER_HOME`.
pub fn host_tmp(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new().prefix(prefix).tempdir_in("/var/tmp").expect("tempdir in /var/tmp")
}

fn random_tag() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).unwrap();
    hex::encode(b)
}

/// A stand-in home directory with canary files, which brokerd protects like
/// the real home (`BROKER_TEST_PROTECT_HOME`; the real home keeps all of its
/// own rules). Tests probe these rather than the user's own `~/.ssh` and rc
/// files, which may be absent (CI runners) and must never be written by a
/// probe that unexpectedly succeeds.
pub struct CanaryHome {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
    before: FileState,
}

impl CanaryHome {
    pub const SSH_KEY: &'static str = ".ssh/id_ed25519";
    /// Agent configuration and files that run in the user's next shell or git.
    pub const CONFIG: &'static [&'static str] = &[".claude/settings.json", ".zshrc", ".bashrc", ".gitconfig"];
    /// Not protected: the in-policy control that the canary home is visible.
    pub const PLAIN: &'static str = "notes.txt";

    pub fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = host_tmp("bkh.");
        let path = dir.path().canonicalize().unwrap();
        let tag = random_tag();
        let files = [
            (Self::SSH_KEY, format!("broker-canary-ssh-key-{tag}\n")),
            (".claude/settings.json", format!("{{\"canary\": \"{tag}\"}}\n")),
            (".zshrc", format!("# broker canary {tag}\n")),
            (".bashrc", format!("# broker canary {tag}\n")),
            (".gitconfig", format!("[user]\n\tname = canary-{tag}\n")),
            (Self::PLAIN, "not a secret\n".to_string()),
        ];
        for (rel, body) in files {
            let p = path.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
        }
        std::fs::set_permissions(path.join(".ssh"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(path.join(Self::SSH_KEY), std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = FileState::of_tree(&path);
        CanaryHome { _dir: dir, path, before }
    }

    pub fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }

    /// Nothing under the canary home changed, appeared or disappeared.
    pub fn assert_unchanged(&self) {
        self.before.assert_same(&FileState::of_tree(&self.path), "canary home");
    }
}

impl Default for CanaryHome {
    fn default() -> Self {
        Self::new()
    }
}

/// Paths and a digest of their content (`None`: absent), to show that the
/// host files a session probed are exactly as they were.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileState(BTreeMap<PathBuf, Option<String>>);

fn digest(p: &Path) -> Option<String> {
    std::fs::read(p).ok().map(|b| hex::encode(ring::digest::digest(&ring::digest::SHA256, &b)))
}

impl FileState {
    pub fn of(paths: &[PathBuf]) -> Self {
        FileState(paths.iter().map(|p| (p.clone(), digest(p))).collect())
    }

    /// Every entry under `dir` (directories as present, files by digest).
    pub fn of_tree(dir: &Path) -> Self {
        fn walk(d: &Path, out: &mut BTreeMap<PathBuf, Option<String>>) {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(d).unwrap().map(|e| e.unwrap().path()).collect();
            entries.sort();
            for p in entries {
                let m = std::fs::symlink_metadata(&p).unwrap();
                if m.is_dir() {
                    out.insert(p.clone(), Some("dir".into()));
                    walk(&p, out);
                } else {
                    out.insert(p.clone(), Some(digest(&p).unwrap_or_else(|| "unreadable".into())));
                }
            }
        }
        let mut m = BTreeMap::new();
        walk(dir, &mut m);
        FileState(m)
    }

    pub fn assert_same(&self, now: &FileState, what: &str) {
        for (p, v) in &self.0 {
            assert_eq!(now.0.get(p).unwrap_or(&None), v, "{what}: {} changed on the host", p.display());
        }
        if let Some(p) = now.0.keys().find(|p| !self.0.contains_key(*p)) {
            panic!("{what}: {} appeared on the host", p.display());
        }
    }
}

fn describe(r: &ProbeResult) -> String {
    format!("code {} stdout={} stderr={}", r.code, r.stdout.trim(), r.stderr.trim())
}

/// The kernel refused the operation (EACCES, EPERM or EROFS). An error on
/// a missing path is inconclusive and fails this assertion.
pub fn assert_fs_denied(r: &ProbeResult, what: &str) {
    assert!(r.denied(), "{what}: expected DENIED (EACCES/EPERM/EROFS), got {}", describe(r));
}

/// As `assert_fs_denied`, also accepting, on Linux only, the named errnos
/// that are that platform's refusal for this operation: EXDEV (a rename or
/// link across a read-only bind mount, or Landlock refusing to reparent),
/// EBUSY (a rename of a bind mountpoint).
pub fn assert_denied_or(r: &ProbeResult, what: &str, linux: &[&str]) {
    let platform = cfg!(target_os = "linux") && r.inconclusive() && r.errno().is_some_and(|e| linux.contains(&e));
    assert!(
        r.denied() || platform,
        "{what}: expected DENIED (EACCES/EPERM/EROFS{}), got {}",
        if cfg!(target_os = "linux") && !linux.is_empty() { format!(" or {}", linux.join("/")) } else { String::new() },
        describe(r)
    );
}

/// A read of `host`, a file that exists on the host, was refused. On Linux
/// the backend masks denied directories with an empty read-only tmpfs, so
/// there the refusal surfaces as ENOENT: accepted only because `host` exists
/// on the host, so the sandbox's view hides it.
pub fn assert_read_denied(r: &ProbeResult, host: &Path, what: &str) {
    assert!(host.is_file(), "{what}: fixture {} must exist on the host", host.display());
    assert_denied_or(r, what, &["ENOENT"]);
}
