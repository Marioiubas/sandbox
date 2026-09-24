//! M1 git scoping (Git Smart-HTTP Adapter): B2 (push to agent/x on the
//! session repo succeeds with a minted, repo-scoped token), B3 (pushes to
//! another repo, to main, or with force are denied and `broker why`
//! explains each) and category 1 ("push to an attacker repo on an allowed
//! host"). The forge is a fake GitHub running `git http-backend`.

use audit::{DecisionResult, EventKind, Reason};
use conformance::m1::*;
use conformance::*;

struct Git {
    h: Harness,
    gh: FakeGitHub,
    _ca_dir: tempfile::TempDir,
}

fn setup() -> Git {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let gh = FakeGitHub::start(&ca, "github.test");
    let web = gh.create_repo("acme", "web");
    gh.create_repo("acme", "other");
    let port = gh.server.port;
    let grant = loopback_grant(
        "git",
        "github.test",
        port,
        "protocol = \"git\"\n\
         allow = { fetch = [\"${repo_remote}\"], push = { repo = \"${repo_remote}\", refs = [\"agent/*\"], force = false } }\n\
         credential = { kind = \"github_app\", issuer = \"test\", permissions = { contents = \"write\" }, repos = [\"${repo_remote}\"], ttl = \"30m\" }",
    );
    let config = format!(
        "version = 1\n[tls]\nextra_roots = [\"{ca}\"]\n\n[issuers.github_app.test]\napp_id = \"{APP_ID}\"\n\
         installation_id = \"{INSTALLATION}\"\nprivate_key = \"file:gh-app.pem\"\napi_base = \"https://github.test:{port}\"\n\
         api_addrs = [\"127.0.0.1\"]\n\n{grant}",
        ca = ca.pem_path.display()
    );
    let url = gh.url("acme", "web");
    let h = Harness::custom(&config, &[], |p| {
        host_git(p, &["clone", "-q", &web.display().to_string(), "."]);
        host_git(p, &["remote", "set-url", "origin", &url]);
        host_git(p, &["config", "user.name", "agent"]);
        host_git(p, &["config", "user.email", "agent@example.invalid"]);
    });
    h.write_secret("gh-app.pem", &gh.key_pem);
    Git { h, gh, _ca_dir: ca_dir }
}

const COMMIT: &str = "echo \"$RANDOM $$\" >> work.txt && git add work.txt && git commit -q -m work";

fn deny_rows(h: &Harness) -> Vec<(Reason, String)> {
    h.events()
        .into_iter()
        .filter(|e| e.kind == EventKind::RequestDecision && e.detail.get("layer").is_some())
        .filter(|e| matches!(&e.decision, Some(d) if d.result == DecisionResult::Deny))
        .map(|e| (e.reason.unwrap(), e.detail.get("verb").and_then(|v| v.as_str()).unwrap_or("").to_string()))
        .collect()
}

#[test]
fn b2_push_to_agent_branch_succeeds_with_scoped_token() {
    let t = setup();
    let r = t.h.sh(&format!(
        "git fetch -q origin && git checkout -q -b agent/x && {COMMIT} && git push -q origin agent/x 2>&1; echo PUSH=$?"
    ));
    assert!(r.stdout.contains("PUSH=0"), "{r:?}");
    let local = host_git(&t.h.repo_path(), &["rev-parse", "HEAD"]);
    assert_eq!(t.gh.rev("acme", "web", "refs/heads/agent/x").as_deref(), Some(local.as_str()), "the push landed");
    // The token was minted with exactly the session repo and contents:write.
    let mints = t.gh.mints.lock().unwrap().clone();
    assert_eq!(mints.len(), 1, "one mint per scope for the session: {mints:?}");
    assert_eq!(mints[0]["repositories"], serde_json::json!(["web"]));
    assert_eq!(mints[0]["permissions"], serde_json::json!({"contents": "write"}));
    // A fast-forward on the same branch is allowed too (not a force).
    let r = t.h.sh(&format!("{COMMIT} && git push -q origin agent/x 2>&1; echo PUSH=$?"));
    assert!(r.stdout.contains("PUSH=0"), "{r:?}");
    assert!(deny_rows(&t.h).is_empty(), "{:?}", deny_rows(&t.h));
    // No token ever reached the sandbox side: git never saw one.
    let r = t.h.sh("git config --get-regexp 'credential|http' ; env | grep -i ghs_ ; echo DONE");
    assert!(!r.stdout.contains("ghs_"), "{r:?}");
    t.h.verify_audit().unwrap();
}

#[test]
fn b3_main_force_delete_and_other_repo_are_denied_and_explained() {
    let t = setup();
    let other = t.gh.url("acme", "other");
    let before_main = t.gh.rev("acme", "web", "refs/heads/main");
    let cases: Vec<(&str, String, Reason, &str)> = vec![
        ("main", format!("{COMMIT} && git push origin HEAD:main 2>&1"), Reason::GitRefNotAllowed, "refs/heads/main"),
        (
            "force",
            format!(
                "git checkout -q -b agent/f && {COMMIT} && git push -q origin agent/f && git commit -q --amend -m rewritten && git push -f origin agent/f 2>&1"
            ),
            Reason::GitForcePush,
            "force=true",
        ),
        ("delete", "git push origin :refs/heads/agent/base 2>&1".to_string(), Reason::GitForcePush, "(delete)"),
        (
            "other-repo",
            format!("git push {other} HEAD:refs/heads/agent/x 2>&1"),
            Reason::GitRepoNotAllowed,
            "acme/other",
        ),
        ("other-fetch", format!("git fetch {other} 2>&1"), Reason::GitRepoNotAllowed, "git.fetch"),
    ];
    for (name, script, reason, needle) in cases {
        let r = t.h.sh(&format!("{script}; echo RC=$?"));
        assert!(!r.stdout.contains("RC=0"), "{name}: git reported success: {r:?}");
        let ids = request_ids(&r.stdout);
        assert!(!ids.is_empty(), "{name}: git output names the request: {r:?}");
        let why = t.h.why(ids.last().unwrap());
        if std::env::var_os("SHOW_GIT").is_some() {
            eprintln!("=== {name}\n{}\n--- why\n{why}", r.stdout);
        }
        assert!(why.contains(reason.as_str()), "{name}: {why}");
        assert!(why.contains(needle), "{name}: `broker why` names {needle}: {why}");
    }
    assert_eq!(t.gh.rev("acme", "web", "refs/heads/main"), before_main, "main untouched");
    assert!(t.gh.rev("acme", "web", "refs/heads/agent/base").is_some(), "delete refused");
    assert!(t.gh.rev("acme", "other", "refs/heads/agent/x").is_none(), "nothing pushed to the other repo");
    let reasons: Vec<Reason> = deny_rows(&t.h).into_iter().map(|(r, _)| r).collect();
    for want in [Reason::GitRefNotAllowed, Reason::GitForcePush, Reason::GitRepoNotAllowed] {
        assert!(reasons.contains(&want), "{want:?} logged: {reasons:?}");
    }
}

#[test]
fn cat1_push_to_attacker_repo_mints_nothing() {
    let t = setup();
    let other = t.gh.url("acme", "other");
    let r = t.h.sh(&format!("git push {other} HEAD:refs/heads/main 2>&1; echo RC=$?"));
    assert!(!r.stdout.contains("RC=0"), "{r:?}");
    assert!(t.gh.mints.lock().unwrap().is_empty(), "no token was minted for a denied request");
    assert!(t.gh.server.seen().iter().all(|s| !s.path.starts_with("/acme/other")), "nothing reached the other repo");
}
