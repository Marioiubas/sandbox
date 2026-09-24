//! bubblewrap argument generation and the Landlock read allowlist.
//!
//! Pure functions, golden-tested on every host.

use crate::CompiledFsPolicy;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub struct BwrapInputs<'a> {
    pub fs: &'a CompiledFsPolicy,
    pub cwd: &'a Path,
    /// brokerd's per-session socket, bound back in after the masks.
    pub data_sock: &'a Path,
    /// `$XDG_RUNTIME_DIR` (dbus, podman and other user sockets): masked.
    pub runtime_dir: Option<&'a Path>,
    pub shim: &'a Path,
    pub shim_spec: &'a str,
    pub argv: &'a [OsString],
    /// Paths that exist, for deciding dir-vs-file masks (injected for tests).
    pub exists: &'a dyn Fn(&Path) -> Option<bool>, // Some(true)=dir, Some(false)=file, None=missing
}

fn push(v: &mut Vec<OsString>, parts: &[&dyn AsRef<std::ffi::OsStr>]) {
    for p in parts {
        v.push(p.as_ref().to_os_string());
    }
}

pub fn args(i: &BwrapInputs) -> Vec<OsString> {
    let mut a: Vec<OsString> = Vec::new();
    // Namespaces: empty network namespace (loopback only), own PID, IPC, UTS.
    for f in [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
    ] {
        a.push(f.into());
    }
    push(&mut a, &[&"--ro-bind", &"/", &"/"]);
    push(&mut a, &[&"--dev", &"/dev"]);
    push(&mut a, &[&"--proc", &"/proc"]);
    push(&mut a, &[&"--tmpfs", &"/tmp"]);
    let mut remount = Vec::new();
    if let Some(rt) = i.runtime_dir
        && (i.exists)(rt) == Some(true)
    {
        push(&mut a, &[&"--tmpfs", &rt]);
        remount.push(rt.to_path_buf());
    }
    // Secrets and broker state: masked (dirs get an empty tmpfs, files /dev/null).
    for p in &i.fs.deny_read {
        if p.starts_with("/tmp") || i.runtime_dir.is_some_and(|rt| p.starts_with(rt)) {
            continue;
        }
        match (i.exists)(p) {
            Some(true) => {
                push(&mut a, &[&"--tmpfs", p]);
                remount.push(p.clone());
            }
            Some(false) => push(&mut a, &[&"--ro-bind", &"/dev/null", p]),
            None => {}
        }
    }
    // Writable roots, then the protected names inside them read-only again.
    for w in &i.fs.writable {
        push(&mut a, &[&"--bind", w, w]);
        let dotgit = w.join(".git");
        if (i.exists)(&dotgit) == Some(true) && !i.fs.missing_protected.contains(&dotgit) {
            // A mountpoint cannot be renamed or removed: protects the `.git`
            // entry itself while its contents stay writable (deny_entry).
            push(&mut a, &[&"--bind", &dotgit, &dotgit]);
        }
        for d in i.fs.deny_write.iter().filter(|d| d.starts_with(w) && d.as_path() != w.as_path()) {
            if (i.exists)(d).is_some() || i.fs.missing_protected.contains(d) {
                push(&mut a, &[&"--ro-bind", d, d]);
            }
        }
        // Placeholders for protected names that did not exist (for example a
        // `.git` in a directory that is not a repository): read-only, empty.
        for m in i.fs.missing_protected.iter().filter(|m| m.starts_with(w) && !i.fs.deny_write.contains(m)) {
            push(&mut a, &[&"--ro-bind", m, m]);
        }
    }
    // The only way out: brokerd's per-session socket.
    push(&mut a, &[&"--bind", &i.data_sock, &i.data_sock]);
    for r in &remount {
        push(&mut a, &[&"--remount-ro", r]);
    }
    push(&mut a, &[&"--chdir", &i.cwd]);
    a.push("--".into());
    a.push(i.shim.as_os_str().to_os_string());
    a.push("--spec".into());
    a.push(i.shim_spec.into());
    a.push("--".into());
    a.extend(i.argv.iter().cloned());
    a
}

/// Paths to grant Landlock read/execute on so that everything except
/// `deny` (and anything beneath it) is readable. Allowlist semantics: a
/// secret created later next to a denied path is not covered by any rule
/// unless its parent was granted wholesale, which only happens for
/// directories that contain no denied path.
pub fn read_allowlist(root: &Path, deny: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    expand(root, deny, &mut out, 0);
    out
}

fn expand(dir: &Path, deny: &[PathBuf], out: &mut Vec<PathBuf>, depth: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for p in entries {
        let resolved = p.canonicalize().unwrap_or_else(|_| p.clone());
        if deny.iter().any(|d| p.starts_with(d) || resolved.starts_with(d)) {
            continue; // denied, or a symlink into a denied path
        }
        if deny.iter().any(|d| d.starts_with(&p)) {
            let is_dir = std::fs::symlink_metadata(&p).map(|m| m.is_dir()).unwrap_or(false);
            if is_dir && depth < 32 {
                expand(&p, deny, out, depth + 1);
            }
            continue;
        }
        out.push(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn golden_order_and_contents() {
        let fs = CompiledFsPolicy {
            read_only_root: true,
            writable: vec!["/home/dev/src/web".into()],
            deny_read: vec!["/home/dev/.ssh".into(), "/home/dev/.netrc".into(), "/home/dev/.local/state/broker".into()],
            deny_write: vec![
                "/home/dev/src/web/.git/hooks".into(),
                "/home/dev/src/web/.git/config".into(),
                "/home/dev/src/web/.claude".into(),
                "/home/dev/.zshrc".into(),
            ],
            deny_entry: vec!["/home/dev/src/web/.git".into()],
            missing_protected: vec!["/home/dev/src/web/.claude".into()],
        };
        let dirs: BTreeSet<&str> = [
            "/home/dev/.ssh",
            "/home/dev/.local/state/broker",
            "/home/dev/src/web/.git",
            "/home/dev/src/web/.git/hooks",
            "/run/user/1000",
        ]
        .into();
        let files: BTreeSet<&str> = ["/home/dev/.netrc", "/home/dev/src/web/.git/config"].into();
        let exists = |p: &Path| {
            let s = p.to_str().unwrap();
            if dirs.contains(s) {
                Some(true)
            } else if files.contains(s) {
                Some(false)
            } else {
                None
            }
        };
        let argv = vec![OsString::from("claude")];
        let a = args(&BwrapInputs {
            fs: &fs,
            cwd: Path::new("/home/dev/src/web"),
            data_sock: Path::new("/home/dev/.local/state/broker/run/s/X/data.sock"),
            runtime_dir: Some(Path::new("/run/user/1000")),
            shim: Path::new("/usr/lib/broker/broker-sandbox-shim"),
            shim_spec: "SPEC",
            argv: &argv,
            exists: &exists,
        });
        let s: Vec<String> = a.iter().map(|x| x.to_string_lossy().into_owned()).collect();
        let joined = s.join(" ");
        assert!(joined.starts_with("--unshare-user --unshare-pid --unshare-net"));
        assert!(joined.contains("--ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /run/user/1000"));
        assert!(joined.contains("--tmpfs /home/dev/.ssh"));
        assert!(joined.contains("--ro-bind /dev/null /home/dev/.netrc"));
        assert!(joined.contains(
            "--bind /home/dev/src/web /home/dev/src/web --bind /home/dev/src/web/.git /home/dev/src/web/.git"
        ));
        assert!(joined.contains("--ro-bind /home/dev/src/web/.git/hooks /home/dev/src/web/.git/hooks"));
        assert!(joined.contains("--ro-bind /home/dev/src/web/.git/config /home/dev/src/web/.git/config"));
        assert!(joined.contains("--ro-bind /home/dev/src/web/.claude /home/dev/src/web/.claude"));
        assert!(!joined.contains(".zshrc"), "outside writable roots the ro root already protects it");
        // data sock bound after the masks, remounts at the very end
        let sock = joined.find("--bind /home/dev/.local/state/broker/run/s/X/data.sock").unwrap();
        let mask = joined.find("--tmpfs /home/dev/.local/state/broker").unwrap();
        let ro = joined.find("--remount-ro /home/dev/.local/state/broker").unwrap();
        assert!(mask < sock && sock < ro);
        assert!(joined.ends_with("-- /usr/lib/broker/broker-sandbox-shim --spec SPEC -- claude"));
        assert!(!joined.contains("--share-net"));
        assert!(!joined.contains("docker.sock"));
    }

    #[test]
    fn read_allowlist_excludes_denied_subtrees() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        for p in ["home/.ssh", "home/src/web", "home/.config/gh", "home/.config/other", "usr/bin"] {
            std::fs::create_dir_all(root.join(p)).unwrap();
        }
        std::fs::write(root.join("home/.ssh/id_ed25519"), "k").unwrap();
        std::fs::write(root.join("home/notes.txt"), "n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("home/.ssh"), root.join("home/sneaky")).unwrap();
        let deny = vec![root.join("home/.ssh"), root.join("home/.config/gh")];
        let got = read_allowlist(&root, &deny);
        assert!(got.contains(&root.join("usr")));
        assert!(got.contains(&root.join("home/src")));
        assert!(got.contains(&root.join("home/notes.txt")));
        assert!(got.contains(&root.join("home/.config/other")));
        assert!(!got.iter().any(|p| p.starts_with(root.join("home/.ssh"))));
        assert!(!got.contains(&root.join("home")));
        assert!(!got.contains(&root.join("home/.config")));
        assert!(!got.contains(&root.join("home/sneaky")), "symlink into a denied path is skipped");
    }
}
