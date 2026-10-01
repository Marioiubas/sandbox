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
