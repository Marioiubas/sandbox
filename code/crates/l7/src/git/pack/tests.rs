use super::*;
use proptest::prelude::*;
use std::path::Path;
use std::process::{Command, Stdio};

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .expect("git on PATH");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn repo() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    git(d.path(), &["init", "-q", "-b", "main"]);
    d
}

fn commit(dir: &Path, file: &str, content: &str, msg: &str) -> String {
    std::fs::write(dir.join(file), content).unwrap();
    git(dir, &["add", file]);
    git(dir, &["commit", "-q", "-m", msg]);
    git(dir, &["rev-parse", "HEAD"])
}

/// What `git push` sends: a thin pack of `new` minus what `old` has.
fn pack(dir: &Path, new: &str, old: Option<&str>) -> Vec<u8> {
    let mut c = Command::new("git")
        .args(["pack-objects", "--stdout", "--revs", "--thin", "--delta-base-offset", "-q"])
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    let mut input = format!("{new}\n");
    if let Some(o) = old {
        input.push_str(&format!("^{o}\n"));
    }
    c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let out = c.wait_with_output().unwrap();
    assert!(out.status.success());
    out.stdout
}

#[test]
fn fast_forward_and_rewrite() {
    let d = repo();
    let a = commit(d.path(), "f", "1\n", "a");
    let b = commit(d.path(), "f", "2\n", "b");
    let c = commit(d.path(), "f", "3\n", "c");
    let g = commit_graph(&pack(d.path(), &c, Some(&a)), &Limits::default()).unwrap();
    assert_eq!(g.commits.len(), 2);
    assert_eq!(classify(&a, &c, Some(&g)), UpdateKind::FastForward);
    assert_eq!(classify(&b, &c, Some(&g)), UpdateKind::FastForward);

    // Rewrite: x branches from a; pushing x over c is not a fast-forward.
    git(d.path(), &["checkout", "-q", "-b", "side", &a]);
    let x = commit(d.path(), "g", "rewritten\n", "x");
    let gx = commit_graph(&pack(d.path(), &x, Some(&c)), &Limits::default()).unwrap();
    assert_eq!(classify(&c, &x, Some(&gx)), UpdateKind::Unknown);
    assert!(classify(&c, &x, Some(&gx)).is_force());
    // A merge whose first parent is the old tip is a fast-forward.
    git(d.path(), &["checkout", "-q", "main"]);
    git(d.path(), &["merge", "-q", "--no-ff", "-m", "merge", "side"]);
    let m = git(d.path(), &["rev-parse", "HEAD"]);
    let gm = commit_graph(&pack(d.path(), &m, Some(&c)), &Limits::default()).unwrap();
    assert_eq!(classify(&c, &m, Some(&gm)), UpdateKind::FastForward);
    // Creates and deletes need no pack.
    let z = "0".repeat(40);
    assert_eq!(classify(&z, &c, None), UpdateKind::Create);
    assert_eq!(classify(&c, &z, None), UpdateKind::Delete);
    assert!(UpdateKind::Delete.is_force());
    assert_eq!(classify(&a, &c, None), UpdateKind::Unknown, "no pack: cannot prove");
}

#[test]
fn deltified_commits_are_resolved() {
    let d = repo();
    let long: String = (0..400).map(|i| format!("line {i} of a long, repetitive commit message\n")).collect();
    let first = commit(d.path(), "f", "0\n", &long);
    for i in 1..30 {
        commit(d.path(), "f", &format!("{i}\n"), &format!("{long}tail {i}\n"));
    }
    let tip = git(d.path(), &["rev-parse", "HEAD"]);
    let p = pack(d.path(), &tip, Some(&first));
    let g = commit_graph(&p, &Limits::default()).unwrap();
    let want: std::collections::HashSet<String> =
        git(d.path(), &["rev-list", &tip, &format!("^{first}")]).lines().map(str::to_string).collect();
    let got: std::collections::HashSet<String> = g.commits.keys().map(hex::encode).collect();
    assert_eq!(got, want, "every pushed commit is found, deltified or not");
    assert_eq!(classify(&first, &tip, Some(&g)), UpdateKind::FastForward);
}

#[test]
fn corrupt_packs_are_errors() {
    let d = repo();
    let a = commit(d.path(), "f", "1\n", "a");
    let b = commit(d.path(), "f", "2\n", "b");
    let p = pack(d.path(), &b, Some(&a));
    assert!(commit_graph(&p, &Limits::default()).is_ok());
    let mut bad = p.clone();
    bad[20] ^= 0xff;
    assert_eq!(commit_graph(&bad, &Limits::default()).unwrap_err(), PackError::Checksum);
    assert_eq!(commit_graph(b"PACK", &Limits::default()).unwrap_err(), PackError::BadHeader);
    assert_eq!(commit_graph(&p[..p.len() - 1], &Limits::default()).unwrap_err(), PackError::Checksum);
    let tiny = Limits { max_objects: 1, ..Limits::default() };
    assert_eq!(commit_graph(&p, &tiny).unwrap_err(), PackError::Limit("too many objects"));
}

#[test]
fn delta_application() {
    let base = b"hello world";
    // src 11, dst 11: copy offset 0 size 6, then insert "there".
    let mut delta = vec![11u8, 11, 0x80 | 0x10, 6, 5];
    delta.extend_from_slice(b"there");
    assert_eq!(apply_delta(base, &delta, &Limits::default()).unwrap(), b"hello there");
    assert!(apply_delta(b"short", &delta, &Limits::default()).is_err(), "base size checked");
    assert!(apply_delta(base, &[11, 11, 0], &Limits::default()).is_err(), "reserved opcode");
    assert!(apply_delta(base, &[11, 3, 0x80 | 0x01 | 0x10, 200, 3], &Limits::default()).is_err(), "copy out of range");
}

proptest! {
    #[test]
    fn random_bytes_never_panic(mut b in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = commit_graph(&b, &Limits::default());
        if b.len() >= 32 {
            b[..4].copy_from_slice(b"PACK");
            b[4..8].copy_from_slice(&2u32.to_be_bytes());
            let n = b.len();
            let sum: [u8; 20] = Sha1::digest(&b[..n - 20]).into();
            b[n - 20..].copy_from_slice(&sum);
            let _ = commit_graph(&b, &Limits::default());
        }
    }

    #[test]
    fn random_deltas_never_panic(base in proptest::collection::vec(any::<u8>(), 0..64), delta in proptest::collection::vec(any::<u8>(), 0..64)) {
        let _ = apply_delta(&base, &delta, &Limits::default());
    }
}

/// Write `content` as a loose object of `ty` without git's format checks.
fn hash_literally(dir: &Path, ty: &str, content: &[u8]) -> String {
    use std::io::Write;
    let mut c = Command::new("git")
        .args(["hash-object", "-t", ty, "--literally", "-w", "--stdin"])
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(content).unwrap();
    let out = c.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A pack holding exactly the named objects (no traversal).
fn pack_exact(dir: &Path, oids: &[&str]) -> Vec<u8> {
    use std::io::Write;
    let mut c = Command::new("git")
        .args(["pack-objects", "--stdout", "-q"])
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(format!("{}\n", oids.join("\n")).as_bytes()).unwrap();
    let out = c.wait_with_output().unwrap();
    assert!(out.status.success());
    out.stdout
}

/// Force detection must read a commit's parents as git does. Invariant:
/// policy fidelity of `git.push` (a grant with `force = false`), and the
/// audit row's `update` (I9).
///
/// Attacker input: a push of `old -> new` to an allowed ref where `new` is
/// the commit `tree <T>\nparent <old>` with no trailing newline. The
/// broker's `commit_parents` reads `old` as a parent and classifies the
/// update as `fast_forward`; git stops parsing parents unless a line ends
/// in `\n`, so for git the commit has no parents and the update replaces
/// the branch's history. A server without `receive.fsckObjects` (git's
/// default) accepts the push and reports `(forced update)` (checked by
/// hand with git 2.50 against a default bare repository).
#[test]
fn review_force_detection_reads_parents_as_git_does() {
    let d = repo();
    let old = commit(d.path(), "f", "1\n", "a");
    let tree = git(d.path(), &["rev-parse", &format!("{old}^{{tree}}")]);
    let new = hash_literally(d.path(), "commit", format!("tree {tree}\nparent {old}").as_bytes());
    let git_says_ancestor = Command::new("git")
        .args(["merge-base", "--is-ancestor", &old, &new])
        .current_dir(d.path())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap()
        .success();
    assert!(!git_says_ancestor, "fixture: git reads no parent in this commit");
    let g = commit_graph(&pack_exact(d.path(), &[&new]), &Limits::default()).unwrap();
    let kind = classify(&old, &new, Some(&g));
    assert!(
        kind.is_force(),
        "git does not see {old} as an ancestor of {new}, so the update rewrites history, \
         but the broker classified it as {kind:?} (force = false)"
    );
}
