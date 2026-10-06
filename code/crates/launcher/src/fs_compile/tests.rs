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
fn extra_homes_only_add_rules() {
    let f = fixture();
    let base = compile(&inputs(&f)).unwrap();
    let canary = f.home.parent().unwrap().join("canary-home");
    let mut i = inputs(&f);
    i.extra_homes = vec![canary.clone()];
    let c = compile(&i).unwrap();
    assert_eq!((&c.writable, &c.deny_entry), (&base.writable, &base.deny_entry));
    assert!(base.deny_read.iter().all(|p| c.deny_read.contains(p)), "the real home keeps every rule");
    assert!(base.deny_write.iter().all(|p| c.deny_write.contains(p)), "the real home keeps every rule");
    assert!(c.deny_read.contains(&canary.join(".ssh")) && c.deny_write.contains(&canary.join(".zshrc")));
    i.extra_homes = vec![f.repo.join("h")];
    assert!(matches!(compile(&i), Err(FsError::WritableTooBroad(_))), "a protected home inside a writable root");
    i.extra_homes = vec![PathBuf::from("relative")];
    assert!(matches!(compile(&i), Err(FsError::NotAbsolute(_))));
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

/// R16 (macOS): the per-user temp dir is writable to every session
/// (ADR-016), but another session's `broker-*` scratch in it is not.
#[test]
fn other_sessions_scratch_in_the_shared_temp_dir_is_not_writable() {
    let f = fixture();
    let pt = f._d.path().join("T");
    let own = pt.join("broker-S1");
    let other = pt.join("broker-S2");
    for d in [&own, &other] {
        std::fs::create_dir_all(d).unwrap();
    }
    let mut i = inputs(&f);
    i.session_tmp = own.clone();
    i.platform_tmp = Some(pt.clone());
    let c = compile(&i).unwrap();
    let pt = pt.canonicalize().unwrap();
    assert_eq!(c.shared_scratch, vec![pt.join("broker-")]);
    assert!(c.is_writable(&pt.join("broker-S1/x")), "own scratch");
    assert!(!c.is_writable(&pt.join("broker-S2/x")), "another session's");
    assert!(!c.is_writable(&pt.join("broker-new")), "a new one");
    assert!(c.is_writable(&pt.join("xcrun_db")), "the rest of the shared dir (ADR-016)");
}

// ---- Review (configuration trust, I5): git control files outside the two
// protected names. Each test names the exact file a session can write and
// the user's next unsandboxed git command then trusts.

/// Review (I5): `.git/commondir` redirects the main repository's common
/// directory, which is where git reads `config` and `hooks` from (git's
/// `get_common_dir_noenv` honours it in any gitdir, not only in linked
/// worktrees). Verified with Apple Git 2.50.1: in a fresh repository,
/// writing `.git/commondir` = `x` and `.git/x/{config,objects->../objects,
/// refs->../refs}` with `core.fsmonitor = "touch PWNED"` makes a plain
/// `git status` run the command. The session may write `.git/commondir`
/// and `.git/x/` (only `.git/config`, `.git/hooks` and the `.git` entry are
/// protected), so `.git/config` and `.git/hooks` protect nothing.
#[test]
fn review_git_commondir_cannot_redirect_config_and_hooks() {
    let f = fixture();
    let c = compile(&inputs(&f)).unwrap();
    for p in [".git/commondir", ".git/x/config", ".git/x/hooks/pre-commit"] {
        assert!(
            !c.is_writable(&f.repo.join(p)),
            "{p} is writable: with `.git/commondir` pointing at `.git/x`, git reads the repository's config and \
             hooks from `.git/x`, so the agent replaces `.git/config` and `.git/hooks` (core.fsmonitor runs on the \
             user's next `git status`)"
        );
    }
}

/// Review (I5): a submodule's git directory lives in
/// `.git/modules/<name>/`, inside the writable `.git`. `git status` in the
/// superproject runs a child git in each populated submodule, which reads
/// that directory's `config` (verified with Apple Git 2.50.1:
/// `core.fsmonitor` in `.git/modules/lib/config` ran on the superproject's
/// `git status`). Its `config` and `hooks` are as authority-bearing as the
/// superproject's own.
#[test]
fn review_submodule_git_directories_are_protected() {
    let f = fixture();
    let gd = f.repo.join(".git/modules/lib");
    std::fs::create_dir_all(gd.join("hooks")).unwrap();
    std::fs::write(gd.join("config"), "[core]\n").unwrap();
    std::fs::create_dir_all(f.repo.join("lib")).unwrap();
    std::fs::write(f.repo.join("lib/.git"), format!("gitdir: {}\n", gd.display())).unwrap();
    let c = compile(&inputs(&f)).unwrap();
    for p in [gd.join("config"), gd.join("hooks/post-checkout"), f.repo.join("lib/.git")] {
        assert!(
            !c.is_writable(&p),
            "{} is writable: a submodule's config and hooks run in the user's next git command in the superproject",
            p.display()
        );
    }
}

/// Review (I5, ADR-019): the protected names are protected only at each
/// writable root, so the session can create a whole repository below it
/// (`git init sub`, or a `.git` file naming a gitdir it wrote) with its own
/// `config` and `hooks`. Verified with Apple Git 2.50.1: after `git init
/// sub` + `core.fsmonitor` in `sub/.git/config` + `git add sub` (a gitlink,
/// no `.gitmodules`), the superproject's next git command ran the command.
/// The same planted `.git` also makes brokerd's `repo_root`/`origin_remote`
/// read it for a later session started from `sub` (see brokerd
/// `session_util::tests::review_*`). ADR-019 states `git init` fails in the
/// sandbox; it fails only at the root.
#[test]
fn review_nested_repositories_cannot_grow_hooks_or_config() {
    let f = fixture();
    std::fs::create_dir_all(f.repo.join("sub")).unwrap();
    let c = compile(&inputs(&f)).unwrap();
    for p in ["sub/.git", "sub/.git/config", "sub/.git/hooks/pre-commit"] {
        assert!(
            !c.is_writable(&f.repo.join(p)),
            "{p} is writable: a nested repository's config and hooks run in the user's next unsandboxed git \
             command (it becomes a gitlink the superproject's `git status` descends into)"
        );
    }
}

/// Review (I5): the per-root protected names are added unresolved
/// (`w.join(name)`), while every other list is symlink-resolved and SBPL
/// matches the real path (module doc; verified with `sandbox-exec` on
/// macOS 26: `(deny file-write* (subpath "<repo>/.claude"))` with `.claude`
/// a symlink to `config/claude` does not stop a write to
/// `<repo>/.claude/settings.json`). A repository that keeps `.claude`
/// (or `.mcp.json`, `.vscode`, `.git/hooks` ...) as a symlink to another
/// directory in the checkout leaves the agent's own settings writable.
#[test]
fn review_a_symlinked_protected_name_protects_its_target() {
    let f = fixture();
    let real = f.repo.join("config/claude");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::write(real.join("settings.json"), "{}").unwrap();
    std::os::unix::fs::symlink("config/claude", f.repo.join(".claude")).unwrap();
    let c = compile(&inputs(&f)).unwrap();
    assert!(
        !c.is_writable(&real.join("settings.json")),
        "the real path behind the protected `.claude` symlink is writable; deny_write has only {:?}",
        c.deny_write.iter().filter(|p| p.starts_with(&f.repo)).collect::<Vec<_>>()
    );
}
