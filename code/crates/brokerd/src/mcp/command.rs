//! A pinned server's command by content (MCP Guard, ADR-047). Right before
//! the server is started, the daemon hashes its executable (and, for a
//! `#!` script, the interpreter it names), every argument that names an
//! existing regular file (relative ones resolved against the server's
//! working directory) and, for `--flag=value`, a value that does. The pin
//! is part of the manifest the user approves; once approved, a different
//! pin refuses the start, so code the agent rewrote never runs with the
//! server's egress grants and credentials.
//!
//! A command that names any path (file or directory, existing or not)
//! inside a writable mount of the agent session is refused outright: the
//! agent could change it between the hash and the exec, or create it after
//! the check. What the hash cannot cover (modules an interpreter imports,
//! files beneath a directory argument) must therefore live outside the
//! agent's mounts too; the broker cannot see those, so this is documented
//! rather than enforced.

use launcher::fs_compile::CompiledFsPolicy;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

/// Largest file the pin hashes (larger refuses the start).
const MAX_FILE: u64 = 1 << 30;
/// Symbolic links followed resolving one path (as the kernel's ELOOP).
const MAX_LINKS: usize = 40;

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A path the command names is inside a writable mount of the agent
    /// session (`mcp_command_writable`).
    Writable(String),
    /// The command cannot be pinned (missing or unreadable executable, a
    /// file too large to hash): `mcp_launch_failed`.
    Unpinnable(String),
    /// The command's pin (here, as it is now) differs from the approved
    /// one (`mcp_manifest_changed`).
    Changed(Value),
}

impl Refusal {
    pub fn message(&self) -> String {
        match self {
            Refusal::Writable(m) | Refusal::Unpinnable(m) => m.clone(),
            Refusal::Changed(_) => "the server's command changed since its manifest was approved".into(),
        }
    }
}

/// What the daemon checks right before it starts a pinned server.
#[derive(Clone)]
pub struct Gate {
    /// The filesystem policy of the agent session the server is started
    /// for: nothing the command names may be writable in it.
    pub agent_fs: Arc<CompiledFsPolicy>,
    /// The approved command pin, if the approved manifest has one.
    pub approved: Option<Value>,
}

impl Gate {
    /// The command's pin now, if it may start.
    pub fn check(&self, argv: &[String], cwd: &Path) -> Result<Value, Refusal> {
        let now = pin(argv, cwd, &|p| self.agent_fs.is_writable(p))?;
        match &self.approved {
            Some(a) if *a != now => Err(Refusal::Changed(now)),
            _ => Ok(now),
        }
    }
}

/// The pin of `argv` started in `cwd`: `{"argv": [...], "files": {name:
/// digest}}`, where a name is the path as the command line names it.
/// `writable` says whether a resolved path is inside a writable mount of
/// the agent session.
pub fn pin(argv: &[String], cwd: &Path, writable: &dyn Fn(&Path) -> bool) -> Result<Value, Refusal> {
    let exe = argv
        .first()
        .filter(|a| a.starts_with('/'))
        .ok_or_else(|| Refusal::Unpinnable("the command must start with an absolute executable path".into()))?;
    let mut files = Map::new();
    let visit = |name: &str, files: &mut Map<String, Value>| -> Result<Option<PathBuf>, Refusal> {
        let p = if Path::new(name).is_absolute() { PathBuf::from(name) } else { cwd.join(name) };
        let (visited, real) = walk(&p);
        if let Some(w) = visited.iter().find(|v| writable(v)) {
            return Err(Refusal::Writable(format!(
                "{name:?} ({}) is inside a writable mount of the agent session",
                w.display()
            )));
        }
        let Some(real) = real.filter(|r| r.is_file()) else { return Ok(None) };
        files.insert(name.to_string(), hash(&real)?.into());
        Ok(Some(real))
    };
    let real = visit(exe, &mut files)?
        .ok_or_else(|| Refusal::Unpinnable(format!("the executable {exe:?} is not an existing regular file")))?;
    if let Some(interp) = shebang(&real) {
        visit(&interp, &mut files)?;
    }
    for a in &argv[1..] {
        visit(a, &mut files)?;
        if let Some((_, v)) = a.split_once('=').filter(|_| a.starts_with('-'))
            && !v.is_empty()
        {
            visit(v, &mut files)?;
        }
    }
    Ok(json!({"argv": argv, "files": files}))
}

fn hash(p: &Path) -> Result<String, Refusal> {
    let fail = |e: std::io::Error| Refusal::Unpinnable(format!("hashing {}: {e}", p.display()));
    let f = std::fs::File::open(p).map_err(fail)?;
    let m = f.metadata().map_err(fail)?;
    if m.len() > MAX_FILE {
        return Err(Refusal::Unpinnable(format!("{} is too large to pin ({} bytes)", p.display(), m.len())));
    }
    let mut h = Sha256::new();
    std::io::copy(&mut f.take(MAX_FILE + 1), &mut h).map_err(fail)?;
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}

/// The absolute interpreter a `#!` line names, if any.
fn shebang(p: &Path) -> Option<String> {
    let mut head = [0u8; 256];
    let n = std::fs::File::open(p).ok()?.read(&mut head).ok()?;
    let line = head[..n].strip_prefix(b"#!")?;
    let line = &line[..line.iter().position(|b| *b == b'\n').unwrap_or(line.len())];
    let interp = std::str::from_utf8(line).ok()?.split_whitespace().next()?;
    interp.starts_with('/').then(|| interp.to_string())
}

/// Every location resolving `p` passes through as the kernel would: each
/// symbolic link's own path (whoever can write it can retarget it) and the
/// final path, all with their directories resolved; and the final path if
/// it exists. A missing component ends the walk with the would-be path.
fn walk(p: &Path) -> (Vec<PathBuf>, Option<PathBuf>) {
    let mut todo: VecDeque<OsString> = VecDeque::new();
    push_front(&mut todo, p);
    let mut cur = PathBuf::from("/");
    let mut visited = Vec::new();
    let mut links = 0;
    while let Some(c) = todo.pop_front() {
        match c.to_str() {
            Some("..") => {
                cur.pop();
                continue;
            }
            Some("." | "") => continue,
            _ => {}
        }
        let next = cur.join(&c);
        match std::fs::symlink_metadata(&next) {
            Ok(m) if m.file_type().is_symlink() => {
                visited.push(next.clone());
                links += 1;
                if links > MAX_LINKS {
                    return (visited, None);
                }
                let Ok(target) = std::fs::read_link(&next) else { return (visited, None) };
                if target.is_absolute() {
                    cur = PathBuf::from("/");
                }
                push_front(&mut todo, &target);
            }
            Ok(_) => cur = next,
            Err(_) => {
                // The rest does not exist: where it would be created.
                cur = next;
                for rest in todo.drain(..) {
                    match rest.to_str() {
                        Some("..") => {
                            cur.pop();
                        }
                        Some("." | "") => {}
                        _ => cur.push(rest),
                    }
                }
                visited.push(cur);
                return (visited, None);
            }
        }
    }
    visited.push(cur.clone());
    (visited, Some(cur))
}

fn push_front(todo: &mut VecDeque<OsString>, p: &Path) {
    let parts: Vec<OsString> = p
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_os_string()),
            Component::ParentDir => Some("..".into()),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => None,
        })
        .collect();
    for part in parts.into_iter().rev() {
        todo.push_front(part);
    }
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod tests;
