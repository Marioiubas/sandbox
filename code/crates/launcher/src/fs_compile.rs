//! One filesystem model compiled to every backend.
//!
//! Output lists are absolute, symlink-resolved paths (SBPL matches real
//! paths; bwrap binds real paths). The mandatory deny-write list is code,
//! not configuration (I5): no policy layer can remove an entry.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, Default)]
pub struct FsInputs {
    pub home: PathBuf,
    /// The project root the agent works in (always writable).
    pub repo: PathBuf,
    /// Per-session scratch directory (always writable).
    pub session_tmp: PathBuf,
    /// macOS: the per-user temp dir (`DARWIN_USER_TEMP_DIR`), writable
    /// because Apple toolchain shims reset `TMPDIR` to it (ADR-016).
    pub platform_tmp: Option<PathBuf>,
    /// Extra writable roots from user policy and profile agent state.
    pub extra_write: Vec<PathBuf>,
    /// Extra deny-read paths from user policy.
    pub extra_deny_read: Vec<PathBuf>,
    /// Agent configuration that must stay read-only (profile).
    pub agent_config_readonly: Vec<PathBuf>,
    /// Directories on the user's PATH.
    pub path_dirs: Vec<PathBuf>,
    /// Broker config, state and runtime dirs: never readable or writable.
    pub broker_dirs: Vec<PathBuf>,
    /// Directory holding the broker binaries: never writable.
    pub install_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledFsPolicy {
    pub read_only_root: bool,
    /// `${repo}`, `${tmp}` and granted state dirs.
    pub writable: Vec<PathBuf>,
    /// Secret paths: unreadable (and therefore unwritable).
    pub deny_read: Vec<PathBuf>,
    /// Mandatory list (I5) plus policy; wins over `writable`. Covers the
    /// path and everything beneath it.
    pub deny_write: Vec<PathBuf>,
    /// Directory *entries* that may not be renamed, removed or replaced
    /// while their contents stay writable (`${repo}/.git`: renaming it and
    /// planting a `gitdir:` file would make the old hooks writable).
    pub deny_entry: Vec<PathBuf>,
    /// Protected names inside writable roots that do not exist yet; the
    /// Linux backend creates empty read-only placeholders for them.
    pub missing_protected: Vec<PathBuf>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FsError {
    #[error("path is not absolute: {0}")]
    NotAbsolute(PathBuf),
    #[error("path contains '..': {0}")]
    DotDot(PathBuf),
    #[error("refusing to make {0} writable: it is /, $HOME or an ancestor of $HOME; run from a project directory")]
    WritableTooBroad(PathBuf),
    #[error("refusing to make {writable} writable: it overlaps broker state {broker}")]
    OverlapsBroker { writable: PathBuf, broker: PathBuf },
    #[error("refusing to launch: the broker binaries in {0} are inside a writable mount (I5)")]
    InstallDirWritable(PathBuf),
    #[error("writable root does not exist: {0}")]
    MissingWritable(PathBuf),
}

/// Home-relative credential stores denied by default (I1).
pub const DEFAULT_DENY_READ: &[&str] = &[
    ".ssh",
    ".aws",
    ".config/gh",
    ".netrc",
    ".docker/config.json",
    ".gnupg",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".config/gcloud",
    ".azure",
    ".kube",
    ".cargo/credentials.toml",
    ".cargo/credentials",
    ".config/hub",
    ".password-store",
    ".terraform.d/credentials.tfrc.json",
    // Coding agents' own login tokens (M1: brokered, never read in-sandbox).
    ".claude/.credentials.json",
    ".codex/auth.json",
    ".gemini/oauth_creds.json",
    ".local/share/keyrings",
    ".mozilla",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Microsoft Edge",
    "Library/Application Support/Arc",
];

/// Home-relative files that execute in the user's next unsandboxed shell or
/// git command (I5). Always read-only.
pub const HOME_DENY_WRITE: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".config/fish",
    ".gitconfig",
    ".config/git",
    ".ssh",
];

/// Names protected inside every writable root (I5): repository git
/// configuration that becomes code execution outside the sandbox, agent
/// settings and MCP manifests, direnv files and repo broker policy.
pub const ROOT_DENY_WRITE: &[&str] = &[
    ".git/hooks",
    ".git/config",
    ".claude",
    ".mcp.json",
    ".codex",
    ".cursor",
    ".gemini",
    ".vscode",
    ".idea",
    ".envrc",
    ".broker",
];

/// Entries protected inside every writable root whose contents stay writable.
pub const ROOT_DENY_ENTRY: &[&str] = &[".git"];

fn check_abs(p: &Path) -> Result<(), FsError> {
    if !p.is_absolute() {
        return Err(FsError::NotAbsolute(p.to_path_buf()));
    }
    if p.components().any(|c| c == Component::ParentDir) {
        return Err(FsError::DotDot(p.to_path_buf()));
    }
    Ok(())
}

/// Resolve symlinks for the longest existing prefix; keep the rest literal.
pub fn resolve(p: &Path) -> Result<PathBuf, FsError> {
    check_abs(p)?;
    let mut existing = p.to_path_buf();
    let mut rest = Vec::new();
    loop {
        if let Ok(c) = existing.canonicalize() {
            let mut out = c;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return Ok(out);
        }
        match (existing.file_name().map(|f| f.to_os_string()), existing.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                existing = parent.to_path_buf();
            }
            _ => return Ok(p.to_path_buf()),
        }
    }
}

fn within(p: &Path, root: &Path) -> bool {
    p.starts_with(root)
}

/// Parse a `.git` *file* (worktree or submodule) and return the gitdir it names.
fn gitdir_from_file(repo: &Path, dotgit: &Path) -> Option<PathBuf> {
    let meta = std::fs::symlink_metadata(dotgit).ok()?;
    if !meta.is_file() || meta.len() > 4096 {
        return None;
    }
    let text = std::fs::read_to_string(dotgit).ok()?;
    let line = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let p = PathBuf::from(line);
    let p = if p.is_absolute() { p } else { repo.join(p) };
    // Normalise `..` lexically, then resolve symlinks.
    let mut norm = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                norm.pop();
            }
            Component::CurDir => {}
            other => norm.push(other),
        }
    }
    resolve(&norm).ok()
}

pub fn compile(i: &FsInputs) -> Result<CompiledFsPolicy, FsError> {
    let home = resolve(&i.home)?;
    let mut writable: BTreeSet<PathBuf> = BTreeSet::new();
    let mut base_roots = vec![&i.repo, &i.session_tmp];
    base_roots.extend(i.platform_tmp.iter());
    for w in base_roots.into_iter().chain(i.extra_write.iter()) {
        let r = resolve(w)?;
        if !r.exists() {
            return Err(FsError::MissingWritable(r));
        }
        if r == Path::new("/") || home.starts_with(&r) {
            return Err(FsError::WritableTooBroad(r));
        }
        writable.insert(r);
    }
    let mut broker = BTreeSet::new();
    for b in &i.broker_dirs {
        let b = resolve(b)?;
        for w in &writable {
            if within(&b, w) || within(w, &b) {
                return Err(FsError::OverlapsBroker { writable: w.clone(), broker: b.clone() });
            }
        }
        broker.insert(b);
    }
    if let Some(inst) = &i.install_dir {
        let inst = resolve(inst)?;
        if writable.iter().any(|w| within(&inst, w)) {
            return Err(FsError::InstallDirWritable(inst));
        }
        broker.insert(inst);
    }

    let mut deny_read: BTreeSet<PathBuf> = DEFAULT_DENY_READ.iter().map(|r| home.join(r)).collect();
    for d in &i.extra_deny_read {
        deny_read.insert(resolve(d)?);
    }
    for b in &i.broker_dirs {
        deny_read.insert(resolve(b)?);
    }

    let mut deny_write: BTreeSet<PathBuf> = HOME_DENY_WRITE.iter().map(|r| home.join(r)).collect();
    deny_write.extend(broker.iter().cloned());
    let mut missing = BTreeSet::new();
    let mut deny_entry = BTreeSet::new();
    let repo = resolve(&i.repo)?;
    for w in &writable {
        for name in ROOT_DENY_ENTRY {
            deny_entry.insert(w.join(name));
        }
        for name in ROOT_DENY_WRITE {
            deny_write.insert(w.join(name));
        }
        if let Some(gd) = gitdir_from_file(w, &w.join(".git")) {
            deny_write.insert(w.join(".git"));
            deny_write.insert(gd.join("hooks"));
            deny_write.insert(gd.join("config"));
            if let Ok(common) = std::fs::read_to_string(gd.join("commondir")) {
                let c = gd.join(common.trim());
                if let Ok(c) = resolve(&normalise(&c)) {
                    deny_write.insert(c.join("hooks"));
                    deny_write.insert(c.join("config"));
                }
            }
        }
    }
    // Linux path rules only bind what exists, so every protected name that is
    // missing from the repository gets an empty read-only placeholder
    // directory (created before launch, removed at teardown): the agent can
    // neither create `.mcp.json` or `.envrc`, nor `git init` a `.git` with hooks.
    let absent = |p: &Path| std::fs::symlink_metadata(p).is_err();
    for name in ROOT_DENY_ENTRY.iter().chain(ROOT_DENY_WRITE) {
        let p = repo.join(name);
        let wanted = match *name {
            ".git/config" => false,
            ".git/hooks" => repo.join(".git").is_dir(),
            _ => true,
        };
        if wanted && absent(&p) {
            missing.insert(p);
        }
    }
    for c in &i.agent_config_readonly {
        deny_write.insert(resolve(c)?);
    }
    for p in &i.path_dirs {
        if p.is_absolute()
            && !p.components().any(|c| c == Component::ParentDir)
            && let Ok(r) = resolve(p)
            && writable.iter().any(|w| within(&r, w))
        {
            deny_write.insert(r);
        }
    }
    Ok(CompiledFsPolicy {
        read_only_root: true,
        writable: writable.into_iter().collect(),
        deny_read: deny_read.into_iter().collect(),
        deny_write: deny_write.into_iter().collect(),
        deny_entry: deny_entry.into_iter().collect(),
        missing_protected: missing.into_iter().collect(),
    })
}

fn normalise(p: &Path) -> PathBuf {
    let mut norm = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                norm.pop();
            }
            Component::CurDir => {}
            other => norm.push(other),
        }
    }
    norm
}

impl CompiledFsPolicy {
    /// True if `p` is writable under this policy (for tests and doctor).
    pub fn is_writable(&self, p: &Path) -> bool {
        self.writable.iter().any(|w| p.starts_with(w))
            && !self.deny_write.iter().any(|d| p.starts_with(d))
            && !self.deny_entry.iter().any(|d| p == d)
            && !self.deny_read.iter().any(|d| p.starts_with(d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fx {
        _d: tempfile::TempDir,
        home: PathBuf,
        repo: PathBuf,
        tmp: PathBuf,
        state: PathBuf,
    }

    fn fixture() -> Fx {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let home = root.join("home");
        let repo = home.join("src/web");
        let tmp = root.join("tmp/s1");
        let state = home.join(".local/state/broker");
        for p in [&repo.join(".git/hooks"), &tmp, &state] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(repo.join(".git/config"), "[core]\n").unwrap();
        Fx { _d: d, home, repo, tmp, state }
    }

    fn inputs(f: &Fx) -> FsInputs {
        FsInputs {
            home: f.home.clone(),
            repo: f.repo.clone(),
            session_tmp: f.tmp.clone(),
            broker_dirs: vec![f.state.clone()],
            ..Default::default()
        }
    }

    #[test]
    fn mandatory_lists_present() {
        let f = fixture();
        let c = compile(&inputs(&f)).unwrap();
        assert_eq!(c.writable, vec![f.repo.clone(), f.tmp.clone()]);
        assert!(c.deny_entry.contains(&f.repo.join(".git")));
        for n in [".git/hooks", ".git/config", ".claude", ".mcp.json", ".vscode", ".envrc"] {
            assert!(c.deny_write.contains(&f.repo.join(n)), "{n}");
        }
        assert!(c.deny_read.contains(&f.home.join(".ssh")));
        assert!(c.deny_read.contains(&f.state));
        assert!(c.deny_write.contains(&f.state));
        assert!(c.missing_protected.contains(&f.repo.join(".claude")));
        assert!(c.missing_protected.contains(&f.repo.join(".mcp.json")), "missing files get placeholders too");
        assert!(c.missing_protected.contains(&f.repo.join(".envrc")));
        assert!(!c.missing_protected.contains(&f.repo.join(".git/config")));
        assert!(!c.missing_protected.contains(&f.repo.join(".git")), ".git exists");
        assert!(!c.missing_protected.iter().any(|p| p.starts_with(&f.tmp)), "placeholders only in the repo");
        assert!(!c.missing_protected.contains(&f.repo.join(".git/hooks")));
        assert!(!c.is_writable(&f.repo.join(".git/hooks/pre-commit")));
        assert!(!c.is_writable(&f.repo.join(".git")));
        assert!(c.is_writable(&f.repo.join(".git/objects/ab")));
        assert!(c.is_writable(&f.repo.join("src/main.rs")));
        assert!(!c.is_writable(&f.home.join(".zshrc")));
    }

    #[test]
    fn refuses_home_root_and_broker_overlap() {
        let f = fixture();
        let mut i = inputs(&f);
        i.repo = f.home.clone();
        assert!(matches!(compile(&i), Err(FsError::WritableTooBroad(_))));
        let mut i = inputs(&f);
        i.repo = PathBuf::from("/");
        assert!(matches!(compile(&i), Err(FsError::WritableTooBroad(_))));
        let mut i = inputs(&f);
        i.extra_write = vec![f.home.join(".local")];
        assert!(matches!(compile(&i), Err(FsError::OverlapsBroker { .. })));
        let mut i = inputs(&f);
        i.install_dir = Some(f.repo.join("target/debug"));
        std::fs::create_dir_all(f.repo.join("target/debug")).unwrap();
        assert!(matches!(compile(&i), Err(FsError::InstallDirWritable(_))));
        let mut i = inputs(&f);
        i.extra_write = vec![PathBuf::from("relative")];
        assert!(matches!(compile(&i), Err(FsError::NotAbsolute(_))));
        let mut i = inputs(&f);
        i.extra_write = vec![f.repo.join("../..")];
        assert!(matches!(compile(&i), Err(FsError::DotDot(_))));
    }

    #[test]
    fn path_dirs_inside_writable_are_protected() {
        let f = fixture();
        std::fs::create_dir_all(f.repo.join("bin")).unwrap();
        let mut i = inputs(&f);
        i.path_dirs = vec![f.repo.join("bin"), PathBuf::from("/usr/bin"), PathBuf::from("rel")];
        let c = compile(&i).unwrap();
        assert!(c.deny_write.contains(&f.repo.join("bin")));
        assert!(!c.deny_write.contains(&PathBuf::from("/usr/bin")));
    }

    #[test]
    fn worktree_gitdir_is_protected() {
        let f = fixture();
        let wt = f.home.join("src/wt");
        std::fs::create_dir_all(&wt).unwrap();
        let gd = f.repo.join(".git/worktrees/wt");
        std::fs::create_dir_all(&gd).unwrap();
        std::fs::write(gd.join("commondir"), "../..\n").unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", gd.display())).unwrap();
        let mut i = inputs(&f);
        i.repo = wt.clone();
        let c = compile(&i).unwrap();
        assert!(c.deny_write.contains(&gd.join("hooks")));
        assert!(c.deny_write.contains(&f.repo.join(".git/hooks")));
        assert!(c.deny_write.contains(&f.repo.join(".git/config")));
        assert!(c.deny_write.contains(&wt.join(".git")));
    }

    proptest::proptest! {
        /// For random extra grants, no mandatory deny path ever becomes writable.
        #[test]
        fn mandatory_never_writable(extra in proptest::collection::vec("[a-z]{1,6}", 0..4)) {
            let f = fixture();
            let mut i = inputs(&f);
            for e in &extra {
                let p = f.repo.join(e);
                std::fs::create_dir_all(&p).unwrap();
                i.extra_write.push(p);
            }
            let c = compile(&i).unwrap();
            for w in &c.writable {
                proptest::prop_assert!(!c.is_writable(&w.join(".git")));
                for n in ROOT_DENY_WRITE {
                    proptest::prop_assert!(!c.is_writable(&w.join(n)));
                    proptest::prop_assert!(!c.is_writable(&w.join(n).join("x")));
                }
            }
            proptest::prop_assert!(!c.is_writable(&f.state.join("audit.db")));
        }
    }
}
