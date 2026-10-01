//! Invariant tests that need real sessions: I1 (env canaries, partial until
//! M1), I2 (fail-closed launch), I5 (repo policy inert; broker state, config,
//! binaries and host agent config unwritable), I6 (bypass corpus
//! end to end), I8 (no flag disables isolation), I9 (audit outside, chained).

use audit::{EventKind, Reason};
use conformance::*;
use std::path::{Path, PathBuf};
use std::process::Command;

const AGENT_BYPASS_FLAGS: &[&str] = &[
    "--dangerously-skip-permissions",
    "--yolo",
    "--trust-all-tools",
    "--dangerously-bypass-approvals-and-sandbox",
    "--full-auto",
];

fn required_layers_ok(h: &Harness) -> bool {
    h.events().iter().filter(|e| e.kind == EventKind::SessionStart).all(|e| {
        e.detail
            .get("layers")
            .and_then(|l| l.as_array())
            .map(|ls| {
                !ls.is_empty()
                    && ls.iter().all(|l| {
                        !l.get("required").and_then(|v| v.as_bool()).unwrap_or(false)
                            || l.get("ok").and_then(|v| v.as_bool()).unwrap_or(false)
                    })
            })
            .unwrap_or(false)
    })
}

// ---------------------------------------------------------------- I2 ------

fn platform_faults() -> Vec<&'static str> {
    let mut f = vec!["shim", "verify_deny_read", "verify_deny_write", "verify_egress", "proxy", "audit"];
    if cfg!(target_os = "macos") {
        f.extend(["sandbox-exec", "seatbelt", "loopback-egress"]);
    } else {
        f.extend(["bwrap", "userns+netns", "seccomp", "no_new_privs", "landlock_fs", "bridge"]);
    }
    f
}

#[test]
fn i2_launch_refuses_when_any_layer_is_missing() {
    for fault in platform_faults() {
        let h = Harness::with_daemon_env("version = 1\n", &[("BROKER_FAULT_INJECT", fault)]);
        let marker = h.repo_path().join("AGENT-RAN");
        let r = h.probe(&["write-new", &marker.display().to_string()]);
        assert_ne!(r.code, 0, "fault {fault}: broker run must exit non-zero: {r:?}");
        assert_eq!(r.code, 125, "fault {fault}: {r:?}");
        assert!(!marker.exists(), "fault {fault}: the agent ran");
        assert!(r.stderr.contains("launch refused"), "fault {fault}: {}", r.stderr);
        let refused = h.events().into_iter().filter(|e| e.kind == EventKind::LaunchRefused).count();
        assert_eq!(refused, 1, "fault {fault}: one launch_refused event");
        // session.start is written ahead of the launch; session.ready (the
        // shim verified every layer) must never appear for a refused launch.
        assert!(h.events().iter().all(|e| e.kind != EventKind::SessionReady), "fault {fault}: no session.ready");
    }
}

#[test]
fn i2_missing_shim_refuses_launch() {
    let b = bins();
    let tmp = tempfile::Builder::new().prefix("bkb.").tempdir_in("/tmp").unwrap();
    for bin in ["broker", "brokerd"] {
        std::fs::copy(b.broker.with_file_name(bin), tmp.path().join(bin)).unwrap();
    }
    let h = Harness::new("version = 1\n");
    let marker = h.repo_path().join("AGENT-RAN");
    let out = Command::new(tmp.path().join("broker"))
        .args(["run", "--", &b.probe.display().to_string(), "write-new", &marker.display().to_string()])
        .current_dir(h.repo.path())
        .env("BROKER_HOME", h.home.path())
        .env("BROKER_DAEMON_IDLE_SECS", "3")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(125), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!marker.exists());
}

#[test]
fn i2_empty_policy_denies_everything() {
    let up = Upstream::start();
    let h = Harness::new("version = 1\n");
    let r = h.probe(&["proxy", "connect", "allowed.test", &up.port.to_string(), "allowed.test"]);
    assert!(r.denied(), "{r:?}");
    assert!(r.stderr.contains("no egress grants"), "the empty policy is announced: {}", r.stderr);
    assert!(h.deny_reasons().contains(&Reason::HostNotAllowed));
}

// ---------------------------------------------------------------- I5 ------

#[test]
fn i5_repository_policy_is_never_loaded_in_m0() {
    let up = Upstream::start();
    let h = Harness::new("version = 1\n");
    let repo = h.repo_path();
    std::fs::create_dir_all(repo.join(".broker")).unwrap();
    std::fs::write(repo.join(".broker/broker.toml"), config_with_upstream(up.port, "")).unwrap();
    let r = h.probe(&["proxy", "connect", "allowed.test", &up.port.to_string(), "allowed.test"]);
    assert!(r.denied(), "a repo-supplied grant must not widen policy: {r:?}");
    assert_eq!(up.accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// What a probe in the I5 batch must meet: allowed (a control), or refused,
/// with the extra errnos Linux may answer with instead (see the test).
enum Want {
    Allowed,
    Refused(Vec<&'static str>),
}

/// How the Linux sandbox shows a host file: through the read-only root, as
/// a direct child of a masked broker directory (an empty read-only tmpfs,
/// so a write there is EROFS), or further below one (its parent does not
/// exist in the mask, so ENOENT).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shown {
    Visible,
    MaskRoot,
    MaskNested,
}

#[test]
fn i5_broker_state_config_and_binaries_are_not_writable() {
    // Every target is a real host file created before the probes run, at a
    // host path the sandbox sees (BROKER_HOME, the binaries and the canary
    // home under /var/tmp, not in the Linux sandbox's private /tmp), and the
    // binaries are a private copy, so a probe that wrongly succeeds breaks
    // nothing else.
    let opts = Opts { canary_home: true, visible_state: true, private_install: true };
    let h = Harness::with_opts("version = 1\n", &[], init_repo, opts);
    let repo = h.repo_path();
    // Control; the first session also creates the state dir, audit DB and control socket.
    assert!(h.probe(&["write", &repo.join("control.txt").display().to_string()]).allowed());
    let home = h.home.path().canonicalize().unwrap();
    let (config, state, run) = (home.join("config"), home.join("state"), home.join("run"));
    h.write_secret("canary.pem", b"broker-canary-file-secret");
    std::fs::create_dir_all(state.join("mcp-manifests")).unwrap();
    for f in ["repo-policy-approvals.json", "mcp-approvals.json", "mcp-manifests/github.tools.json"] {
        std::fs::write(state.join(f), "{}\n").unwrap();
    }
    let (install, ch) = (h.install_dir(), h.canary_home());
    // (path, how the Linux sandbox shows it, a running executable there).
    use Shown::*;
    let mut targets = vec![
        (config.join("broker.toml"), MaskRoot, false),
        (config.join("canary.pem"), MaskRoot, false),
        (state.join("audit.db"), MaskRoot, false),
        (state.join("repo-policy-approvals.json"), MaskRoot, false),
        (state.join("mcp-approvals.json"), MaskRoot, false),
        (state.join("mcp-manifests/github.tools.json"), MaskNested, false),
    ];
    // On Linux all three run during a session (the shim as the network bridge).
    for b in ["broker", "brokerd", "broker-sandbox-shim"] {
        targets.push((install.join(b), Visible, cfg!(target_os = "linux")));
    }
    targets.extend(CanaryHome::CONFIG.iter().map(|p| (ch.join(p), Visible, false)));
    for (t, ..) in &targets {
        assert!(t.is_file(), "fixture: {} must exist on the host", t.display());
    }
    let fixed: Vec<PathBuf> = targets.iter().map(|t| t.0.clone()).filter(|p| !p.ends_with("audit.db")).collect();
    let before = FileState::of(&fixed);
    let ino = |p: &Path| std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(p).unwrap());
    let (db, ctl) = (state.join("audit.db"), run.join("ctl.sock"));
    let (db_ino, ctl_ino) = (ino(&db), ino(&ctl));

    // Linux answers some of these through its mount table and masks rather
    // than EACCES/EPERM/EROFS (accepted there only, by name): a rename from
    // the writable repository onto a read-only mount, or a link across one,
    // is EXDEV; a masked directory is an empty read-only tmpfs, so a link
    // (which needs its source) and anything below a subdirectory of the mask
    // meet ENOENT, for files that exist on the host (checked above); and the
    // kernel refuses to open a running executable for writing (ETXTBSY)
    // before it checks the mount, so there rename, unlink, replace and plant
    // carry the proof. macOS must answer every probe with EPERM or EACCES.
    let s = |p: &Path| p.display().to_string();
    let mut batch: Vec<(Vec<String>, Want, String)> = Vec::new();
    let mut add = |args: Vec<String>, want: Want| {
        let what = args.join(" ");
        batch.push((args, want, what));
    };
    let v = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    for (i, (t, shown, running)) in targets.iter().enumerate() {
        let t = s(t);
        let hidden = if *shown == MaskNested { vec!["ENOENT"] } else { vec![] };
        let with = |extra: &[&'static str]| Want::Refused(hidden.iter().chain(extra).copied().collect());
        let busy: &[&str] = if *running { &["ETXTBSY"] } else { &[] };
        let (repl, link, sym) =
            (repo.join(format!("repl-{i}")), repo.join(format!("link-{i}")), repo.join(format!("sym-{i}")));
        std::fs::write(&repl, "replacement\n").unwrap();
        add(v(&["write", &t]), with(busy));
        add(v(&["rename", &t, &format!("{t}.broker-probe")]), with(&[]));
        add(v(&["unlink", &t]), with(&[]));
        add(v(&["rename", &s(&repl), &t]), with(&["EXDEV"]));
        add(v(&["hardlink", &t, &s(&link)]), with(if *shown == Visible { &["EXDEV"] } else { &["EXDEV", "ENOENT"] }));
        add(v(&["symlink", &t, &s(&sym)]), Want::Allowed);
        add(v(&["write", &s(&sym)]), with(busy));
    }
    let repl = repo.join("repl-ctl");
    std::fs::write(&repl, "replacement\n").unwrap();
    add(v(&["rename", &s(&ctl), &format!("{}.broker-probe", s(&ctl))]), Want::Refused(vec![]));
    add(v(&["unlink", &s(&ctl)]), Want::Refused(vec![]));
    add(v(&["rename", &s(&repl), &s(&ctl)]), Want::Refused(vec!["EXDEV"]));
    // New files: planted policy, approvals, manifests, binaries, rc files.
    let planted = [
        config.join("planted.toml"),
        state.join("planted.json"),
        state.join("mcp-manifests/planted.tools.json"),
        run.join("planted"),
        install.join("planted"),
        ch.join(".zshenv"),
    ];
    for p in &planted {
        // `mcp-manifests/` exists on the host, but not inside the Linux mask.
        let hidden = if p.parent() == Some(&state.join("mcp-manifests")) { vec!["ENOENT"] } else { vec![] };
        add(v(&["write-new", &s(p)]), Want::Refused(hidden));
    }
    let args: Vec<Vec<String>> = batch.iter().map(|b| b.0.clone()).collect();
    for (r, (_, want, what)) in h.probe_batch(&args).iter().zip(&batch) {
        match want {
            Want::Allowed => assert!(r.allowed(), "control {what}: {r:?}"),
            Want::Refused(linux) => assert_denied_or(r, what, linux),
        }
    }

    // The host is untouched: same bytes, same audit DB and socket, nothing planted.
    before.assert_same(&FileState::of(&fixed), "broker config, state, binaries and host agent config");
    assert_eq!((ino(&db), ino(&ctl)), (db_ino, ctl_ino), "audit DB or control socket replaced");
    assert!(h.verify_audit().is_ok(), "audit chain intact");
    for (t, ..) in &targets {
        assert!(!PathBuf::from(format!("{}.broker-probe", t.display())).exists(), "{} renamed", t.display());
    }
    for p in &planted {
        assert!(!p.exists(), "{} planted", p.display());
    }
    ch.assert_unchanged();
    assert!((0..targets.len()).all(|i| !repo.join(format!("link-{i}")).exists()), "a hard link to a target exists");
    assert!(h.probe(&["write", &repo.join("control.txt").display().to_string()]).allowed(), "the broker still works");
}

// ---------------------------------------------------------------- I6 ------

#[derive(serde::Deserialize)]
struct Corpus {
    case: Vec<Case>,
}
#[derive(serde::Deserialize)]
struct Case {
    id: String,
    input: Option<String>,
    input_hex: Option<String>,
    reason: Reason,
    #[serde(default)]
    via: Vec<String>,
}

fn escape(b: &[u8]) -> String {
    let mut s = String::new();
    for &c in b {
        match c {
            b'\\' => s.push_str("\\\\"),
            0x21..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s
}

#[test]
fn i6_bypass_corpus_end_to_end() {
    let corpus: Corpus = toml::from_str(include_str!("../../bypass-corpus/hosts.toml")).unwrap();
    let h = Harness::new(
        "version = 1\n[[egress]]\nhost = \"api.github.com\"\n[[egress]]\nhost = \"*.google.com\"\n[[egress]]\nhost = \"dns.google\"\n",
    );
    let mut expected = Vec::new();
    for c in &corpus.case {
        let bytes = match (&c.input, &c.input_hex) {
            (Some(s), None) => s.as_bytes().to_vec(),
            (None, Some(x)) => hex::decode(x).unwrap(),
            _ => panic!("{}", c.id),
        };
        for mode in ["connect", "socks5"] {
            if !c.via.is_empty() && !c.via.iter().any(|v| v == mode) {
                continue;
            }
            // CR/LF and spaces cannot travel inside a CONNECT request line.
            if mode == "connect" && bytes.iter().any(|b| matches!(b, b'\r' | b'\n' | b' ')) {
                continue;
            }
            let r = h.probe(&["proxy", mode, &escape(&bytes), "443", "-"]);
            assert!(r.denied(), "corpus {} via {mode}: {r:?}", c.id);
            if mode == "connect" {
                assert!(
                    r.stdout.contains(&format!("reason={}", c.reason.as_str())),
                    "corpus {} via connect: {}",
                    c.id,
                    r.stdout
                );
            }
            expected.push(c.reason);
        }
    }
    let got = h.deny_reasons();
    assert_eq!(got.len(), expected.len(), "every corpus deny logged exactly once");
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
}

// ---------------------------------------------------------------- I8 ------

#[test]
fn i8_no_profile_flag_or_env_disables_isolation() {
    let h = Harness::new("version = 1\n[[egress]]\nhost = \"example.com\"\n");
    let profiles =
        [None, Some("default"), Some("claude-code"), Some("codex"), Some("gemini-cli"), Some("cursor-agent")];
    let mut sessions = 0;
    for profile in profiles {
        for flag in std::iter::once("").chain(AGENT_BYPASS_FLAGS.iter().copied()) {
            let mut args = vec!["tcp", "1.1.1.1", "443"];
            if !flag.is_empty() {
                args.push(flag);
            }
            let r = h.probe_with(profile, &args, &[]);
            assert!(r.denied(), "profile {profile:?} flag {flag}: direct egress {r:?}");
            sessions += 1;
        }
        let r = h.probe_with(
            profile,
            &["dns", "example.com"],
            &[("NO_PROXY", "*"), ("HTTPS_PROXY", ""), ("HTTP_PROXY", "")],
        );
        assert!(r.denied(), "profile {profile:?}: DNS with client proxy env cleared {r:?}");
        let r = h.probe_with(profile, &["env-has", "127.0.0.1"], &[("HTTPS_PROXY", "http://evil.example:8080")]);
        assert!(r.allowed(), "the sandbox always gets the broker's proxy, not the client's: {r:?}");
        let r = h.probe_with(profile, &["env-has", "evil.example"], &[("HTTPS_PROXY", "http://evil.example:8080")]);
        assert!(r.denied(), "client proxy variables never reach the sandbox: {r:?}");
        sessions += 3;
    }
    let starts = h.events().iter().filter(|e| e.kind == EventKind::SessionStart).count();
    assert_eq!(starts, sessions);
    assert!(required_layers_ok(&h), "every session started with all required layers");
}

#[test]
fn i8_unknown_profile_is_refused_not_ignored() {
    let h = Harness::new("version = 1\n");
    let r = h.probe_with(Some("no-such-profile"), &["tcp", "1.1.1.1", "443"], &[]);
    assert_eq!(r.code, 125, "{r:?}");
}

#[test]
fn i8_invalid_user_policy_refuses_launch() {
    // Unknown keys (for example an M1 credential table) are compile errors,
    // never silently ignored.
    let h = Harness::new("version = 1\n[[egress]]\nhost = \"example.com\"\ncredential = { kind = \"static\" }\n");
    let r = h.probe(&["tcp", "1.1.1.1", "443"]);
    assert_eq!(r.code, 125, "{r:?}");
    let h = Harness::new("version = 1\n[[egress]]\nhost = \"*\"\n");
    let r = h.probe(&["tcp", "1.1.1.1", "443"]);
    assert_eq!(r.code, 125, "catch-all grant refused: {r:?}");
}

// ---------------------------------------------------------------- I1 ------

/// Risk R4: the daemon that holds minted credentials writes no core dump and,
/// on Linux, is not dumpable, so another process of the same user cannot
/// read its environment or memory through /proc.
#[cfg(target_os = "linux")]
#[test]
fn i1_the_daemon_is_not_dumpable() {
    let h = Harness::new("version = 1\n");
    assert!(h.sh("echo ok").stdout.contains("ok"));
    let pid = std::fs::read_to_string(h.home.path().join("run/brokerd.pid")).unwrap();
    let pid = pid.trim();
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits.lines().find(|l| l.starts_with("Max core file size")).unwrap();
    assert_eq!(core.split_whitespace().skip(4).take(2).collect::<Vec<_>>(), ["0", "0"], "{core}");
    let e = std::fs::read(format!("/proc/{pid}/environ")).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
    // And from inside a session: no ptrace at all (seccomp), and the
    // daemon is not in the session's PID namespace.
    let r = h.probe(&["ptrace", pid]);
    assert!(r.denied(), "{r:?}");
    assert!(!h.probe(&["read", &format!("/proc/{pid}/environ")]).allowed());
}

#[test]
fn i1_host_secrets_in_the_client_environment_never_reach_the_sandbox() {
    let h = Harness::new("version = 1\n");
    let canary = "CANARY-7d1e2f0a9b";
    let env = [
        ("GITHUB_TOKEN", canary),
        ("AWS_SECRET_ACCESS_KEY", canary),
        ("ANTHROPIC_API_KEY", canary),
        ("SOME_UNLISTED_VAR", canary),
    ];
    let r = h.probe_with(None, &["env-scan", &hex::encode(canary)], &env);
    assert!(r.denied(), "canary visible inside the sandbox: {r:?}");
}

// ---------------------------------------------------------------- I9 ------

#[test]
fn i9_every_decision_is_chained_and_explainable() {
    // The audit DB at a host path the Linux sandbox sees (masked), not in its
    // private /tmp, so the write below meets the sandbox's refusal.
    let opts = Opts { visible_state: true, ..Default::default() };
    let h = Harness::with_opts("version = 1\n", &[], init_repo, opts);
    let r = h.probe(&["proxy", "connect", "evil.example", "443", "-"]);
    assert!(r.denied());
    let rid = r.stdout.split("request=").nth(1).map(|s| s.trim().to_string()).expect("request id in the deny");
    let out = Command::new(&h.bins.broker).args(["why", &rid]).env("BROKER_HOME", h.home.path()).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("host_not_allowed") && text.contains("evil.example"), "{text}");
    assert!(h.verify_audit().unwrap() >= 3);
    let out =
        Command::new(&h.bins.broker).args(["audit", "verify"]).env("BROKER_HOME", h.home.path()).output().unwrap();
    assert!(out.status.success());
    // The sandbox itself can neither read nor write the log.
    let db = h.audit_db().display().to_string();
    assert_read_denied(&h.probe(&["read", &db]), &h.audit_db(), "read the audit log");
    assert_fs_denied(&h.probe(&["write", &db]), "write the audit log");
    assert!(h.verify_audit().is_ok());
    // Attributed: every row of every session names who and what (I9).
    assert!(h.assert_attributed() >= 9);
}

// ---------------------------------------------------------------- I4 ------

fn policy_cmd(h: &Harness, action: &str) -> std::process::Output {
    Command::new(&h.bins.broker)
        .args(["policy", action])
        .current_dir(h.repo.path())
        .env("BROKER_HOME", h.home.path())
        .output()
        .unwrap()
}

#[test]
fn i4_repo_policy_only_narrows_and_needs_approval() {
    let up = Upstream::start();
    let p = up.port.to_string();
    let h = Harness::new(&config_with_upstream(up.port, ""));
    let reach = |h: &Harness| h.probe(&["proxy", "connect", "allowed.test", &p, "allowed.test"]);
    assert!(reach(&h).allowed(), "control: the user grant allows the upstream");
    // A repository policy that lists only another host (narrowing), and a
    // grant for a host the user never granted (a widening attempt).
    std::fs::create_dir_all(h.repo_path().join(".broker")).unwrap();
    std::fs::write(
        h.repo_path().join(".broker/broker.toml"),
        "version = 1\n[[egress]]\nhost = \"other.test\"\n[[egress]]\nhost = \"evil.test\"\nports = [443]\n",
    )
    .unwrap();
    // Not approved: ignored (and announced), so nothing changes yet.
    let r = reach(&h);
    assert!(r.allowed(), "{r:?}");
    assert!(r.stderr.contains("not approved"), "{}", r.stderr);
    let st = policy_cmd(&h, "status");
    assert!(String::from_utf8_lossy(&st.stdout).contains("not approved"));
    // Approved: it narrows the upstream away and still cannot widen.
    assert!(policy_cmd(&h, "approve").status.success());
    let r = reach(&h);
    assert!(r.denied(), "approved repo policy narrows: {r:?}");
    assert!(h.deny_reasons().contains(&Reason::RepoPolicyDenied));
    let r = h.probe(&["proxy", "connect", "evil.test", "443", "evil.test"]);
    assert!(r.denied(), "a repo grant never widens: {r:?}");
    // Any change to the files revokes the approval.
    std::fs::write(h.repo_path().join(".broker/policy.cedar"), "// edited\n").unwrap();
    assert!(reach(&h).allowed(), "changed content is treated as absent until re-approved");
    // A repository policy that tries to confer authority cannot be approved.
    std::fs::remove_file(h.repo_path().join(".broker/policy.cedar")).unwrap();
    std::fs::write(
        h.repo_path().join(".broker/broker.toml"),
        "version = 1\n[[egress]]\nhost = \"allowed.test\"\ncredential = { kind = \"static\", ref = \"env:HOME\" }\n",
    )
    .unwrap();
    let out = policy_cmd(&h, "approve");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not allowed in repository policy"), "{out:?}");
}

// ---------------------------------------------------------------- I8 (learn) ---

#[test]
fn i8_learn_mode_keeps_sandbox_proxy_and_ceiling() {
    let opts = Opts { canary_home: true, ..Default::default() };
    let h = Harness::with_opts("version = 1\n", &[], init_repo, opts);
    let learn = |args: &[&str]| {
        let mut argv = vec![h.bins.probe.display().to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        let out = Command::new(&h.bins.broker)
            .arg("learn")
            .arg("--")
            .args(&argv)
            .current_dir(h.repo.path())
            .env("BROKER_HOME", h.home.path())
            .env("BROKER_DAEMON_IDLE_SECS", "3")
            .envs(h.daemon_env.iter().map(|(k, v)| (k, v)))
            .output()
            .unwrap();
        ProbeResult::from(out)
    };
    // A canary key that exists on every host (the user's own may not).
    let key = h.canary_home().join(CanaryHome::SSH_KEY);
    let plain = h.canary_home().join(CanaryHome::PLAIN).display().to_string();
    assert!(learn(&["read", &plain]).allowed(), "control: the canary home is visible");
    assert_read_denied(&learn(&["read", &key.display().to_string()]), &key, "secrets stay unreadable");
    assert!(learn(&["tcp", "1.1.1.1", "443"]).denied(), "no direct route");
    assert!(learn(&["proxy", "connect", "169.254.169.254", "443", "-"]).denied(), "metadata denied");
    assert!(learn(&["proxy", "connect", "pastebin.com", "443", "pastebin.com"]).denied(), "ceiling holds");
    assert!(learn(&["proxy", "connect", "x.ngrok-free.app", "443", "x.ngrok-free.app"]).denied(), "ceiling holds");
    assert!(h.deny_reasons().contains(&Reason::CeilingPasteSite));
    assert!(h.events().iter().any(|e| e.kind == EventKind::SessionStart && e.detail["mode"] == "record"));
}
