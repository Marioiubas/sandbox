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
    /// Writable directories shared with other sessions where existing files
    /// must not change: files may be added, not modified or removed (macOS);
    /// the session gets a private empty directory there (Linux).
    pub create_only: Vec<PathBuf>,
    /// Further directories protected exactly like `home`, in addition to it
    /// (canary homes in the conformance suite; see
    /// `launcher::test_protected_homes`). Only ever adds rules.
    pub extra_homes: Vec<PathBuf>,
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
    /// Name prefixes in a directory every session may write (macOS:
    /// `DARWIN_USER_TEMP_DIR/broker-`, ADR-016). Writes beneath any path
    /// starting with one are denied except in this session's own writable
    /// roots, so sessions cannot write into each other's scratch (R16).
    #[serde(default)]
    pub shared_scratch: Vec<PathBuf>,
    /// Roots below which no `.git` may be written (the repository): a nested
    /// repository's config and hooks run in the user's next git command in
    /// the superproject. Enforced by pattern on macOS; on Linux only the
    /// ones that exist at launch are protected (ADR-046).
    #[serde(default)]
    pub nested_git: Vec<PathBuf>,
    /// Writable directories where existing files must not change (see
    /// `FsInputs::create_only`).
    #[serde(default)]
    pub create_only: Vec<PathBuf>,
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
    // Files and directories that make git read config and hooks from
    // elsewhere: `commondir` repoints the common dir (config, hooks),
    // `config.worktree` adds config, and `modules/`, `worktrees/` hold other
    // repositories' config and hooks (submodules, linked worktrees) that
    // the user's git runs in (ADR-046).
    ".git/commondir",
    ".git/config.worktree",
    ".git/modules",
    ".git/worktrees",
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

/// What a Linux placeholder for a missing protected name must contain to be
/// harmless to git: `commondir` naming the git directory itself (the same as
/// no `commondir`), an empty `config.worktree`; `None` means a directory.
pub fn placeholder_file(p: &Path) -> Option<&'static str> {
    match p.file_name()?.to_str()? {
        "commondir" if p.parent().is_some_and(|d| d.ends_with(".git")) => Some(".\n"),
        "config.worktree" if p.parent().is_some_and(|d| d.ends_with(".git")) => Some(""),
        _ => None,
    }
}

/// Teardown (ADR-046): a `.git` below `root` that was not there at launch
/// was made by the session; Linux cannot refuse its creation, so it is
/// renamed aside (`.git.broker-quarantine-<tag>`), never deleted, before
/// the user's git or a later session can read its config or hooks.
/// Returns the paths quarantined.
pub fn quarantine_new_nested_git(root: &Path, at_launch: &[PathBuf], tag: &str) -> Vec<PathBuf> {
    let mut moved = Vec::new();
    for g in nested_git(root).into_iter().filter(|g| !at_launch.contains(g)) {
        let to = g.with_file_name(format!(".git.broker-quarantine-{tag}"));
        if std::fs::symlink_metadata(&to).is_err() && std::fs::rename(&g, &to).is_ok() {
            moved.push(g);
        }
    }
    moved
}

/// Remove a placeholder made for `p` (at teardown): an empty directory, or a
/// file that still holds exactly the placeholder content.
pub fn remove_placeholder(p: &Path) {
    match placeholder_file(p) {
        Some(c) if std::fs::read_to_string(p).is_ok_and(|s| s == c) => {
            let _ = std::fs::remove_file(p);
        }
        Some(_) => {}
        None => {
            let _ = std::fs::remove_dir(p);
        }
    }
}

/// Existing `.git` entries below `root` (not `root/.git` itself): nested
/// repositories and submodule checkouts. Bounded walk, symlinks not followed.
pub fn nested_git(root: &Path) -> Vec<PathBuf> {
    const MAX_ENTRIES: usize = 200_000;
    let (mut found, mut seen, mut stack) = (Vec::new(), 0usize, vec![root.to_path_buf()]);
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            seen += 1;
            if seen > MAX_ENTRIES {
                return found;
            }
            let Ok(t) = e.file_type() else { continue };
            let path = e.path();
            if e.file_name() == ".git" {
                if dir != root {
                    found.push(path);
                }
            } else if t.is_dir() {
                stack.push(path);
            }
        }
    }
    found
}

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
    let homes = std::iter::once(&i.home).chain(&i.extra_homes).map(|h| resolve(h)).collect::<Result<Vec<_>, _>>()?;
    let mut writable: BTreeSet<PathBuf> = BTreeSet::new();
    let mut base_roots = vec![&i.repo, &i.session_tmp];
    base_roots.extend(i.platform_tmp.iter());
    for w in base_roots.into_iter().chain(i.extra_write.iter()) {
        let r = resolve(w)?;
        if !r.exists() {
            return Err(FsError::MissingWritable(r));
        }
        if r == Path::new("/") || homes.iter().any(|h| h.starts_with(&r)) {
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

    let under_homes = |rel: &'static [&'static str]| homes.iter().flat_map(move |h| rel.iter().map(move |r| h.join(r)));
    let mut deny_read: BTreeSet<PathBuf> = under_homes(DEFAULT_DENY_READ).collect();
    for d in &i.extra_deny_read {
        deny_read.insert(resolve(d)?);
    }
    for b in &i.broker_dirs {
        deny_read.insert(resolve(b)?);
    }

    let mut deny_write: BTreeSet<PathBuf> = under_homes(HOME_DENY_WRITE).collect();
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
        for name in ROOT_DENY_WRITE {
            // A protected name that is a symlink: its target too (SBPL and
            // bind mounts act on the resolved path).
            if std::fs::symlink_metadata(w.join(name)).is_ok_and(|m| m.file_type().is_symlink())
                && let Ok(t) = resolve(&w.join(name))
            {
                deny_write.insert(t);
            }
        }
        if let Some(gd) = gitdir_from_file(w, &w.join(".git")) {
            deny_write.insert(w.join(".git"));
            for n in ["hooks", "config", "commondir", "config.worktree", "modules", "worktrees"] {
                deny_write.insert(gd.join(n));
            }
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
            ".git/hooks" | ".git/commondir" | ".git/config.worktree" | ".git/modules" | ".git/worktrees" => {
                repo.join(".git").is_dir()
            }
            _ => true,
        };
        if wanted && absent(&p) {
            missing.insert(p);
        }
    }
    // Nested repositories that exist now (Linux can protect only these).
    for g in nested_git(&repo) {
        if let Some(gd) = gitdir_from_file(g.parent().unwrap_or(&repo), &g) {
            for n in ["hooks", "config", "commondir", "config.worktree"] {
                deny_write.insert(gd.join(n));
            }
        }
        deny_write.insert(g);
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
        shared_scratch: i.platform_tmp.iter().filter_map(|p| resolve(p).ok()).map(|p| p.join("broker-")).collect(),
        nested_git: vec![repo],
        create_only: i.create_only.iter().filter_map(|p| resolve(p).ok()).collect(),
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
            && !self.create_only.iter().any(|c| p.starts_with(c) && p != c)
            && !self
                .nested_git
                .iter()
                .any(|r| p.strip_prefix(r).is_ok_and(|rel| rel.components().skip(1).any(|c| c.as_os_str() == ".git")))
            && !self
                .shared_scratch
                .iter()
                .any(|s| text_prefix(p, s) && !self.writable.iter().any(|w| text_prefix(w, s) && p.starts_with(w)))
    }
}

/// `p` starts with `prefix` as text (`/T/broker-` covers `/T/broker-abc`).
pub fn text_prefix(p: &Path, prefix: &Path) -> bool {
    p.as_os_str().as_encoded_bytes().starts_with(prefix.as_os_str().as_encoded_bytes())
}

#[cfg(test)]
mod tests;
