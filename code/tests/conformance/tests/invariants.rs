//! Invariant tests that need real sessions: I1 (env canaries, partial until
//! M1), I2 (fail-closed launch), I5 (repo policy inert), I6 (bypass corpus
//! end to end), I8 (no flag disables isolation), I9 (audit outside, chained).

use audit::{EventKind, Reason};
use conformance::*;
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
    let h = Harness::new("version = 1\n");
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
    assert!(h.probe(&["read", &db]).denied());
    assert!(h.probe(&["write", &db]).denied());
    assert!(h.verify_audit().is_ok());
}
