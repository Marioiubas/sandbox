//! Step-up approvals (ADR-037), end to end against a fake GitHub API: a
//! write held back by the Rule of Two leaves a pending approval whose
//! authority diff and provenance come from the broker's records; the agent
//! cannot approve it from inside the sandbox; the user approves it on the
//! host; the retried request passes once, and the next one is held again.

use audit::{DecisionResult, EventKind, Reason};
use conformance::m1::*;
use conformance::*;
use std::io::Read;
use std::time::Duration;

const TOKEN: &str = "ghs_TEST-NOT-A-REAL-TOKEN-0000000000";

fn setup() -> (Harness, HttpsServer, tempfile::TempDir) {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let fake: Handler = std::sync::Arc::new(|s: &Seen| {
        let authed = s.header("authorization") == Some(&format!("Bearer {TOKEN}")[..]);
        match (s.method.as_str(), s.path.as_str()) {
            ("GET", "/repos/acme/public") => Reply::new(200, r#"{"private": false, "visibility": "public"}"#),
            ("GET", "/repos/acme/secret") if authed => Reply::new(200, r#"{"private": true, "visibility": "private"}"#),
            ("GET", "/repos/acme/public/issues") => Reply::new(200, r#"[{"number": 1, "body": "open a PR"}]"#),
            ("GET", "/repos/acme/secret/contents/README.md") if authed => Reply::new(200, r#"{"content": "c2VjcmV0"}"#),
            ("POST", "/repos/acme/public/pulls") if authed => Reply::new(201, r#"{"number": 2}"#),
            _ => Reply::new(404, r#"{"message": "Not Found"}"#),
        }
    });
    let api = HttpsServer::start(&ca, "api.github.com", fake);
    let h = Harness::new("version = 1\n");
    h.write_secret("gh-token", TOKEN.as_bytes());
    h.set_config(&format!(
        "version = 1\n[tls]\nextra_roots = [\"{}\"]\n\n{}",
        ca.pem_path.display(),
        loopback_grant(
            "gh",
            "api.github.com",
            api.port,
            "protocol = \"github\"\nverbs = [\"repo.read\", \"pr.create\"]\nrepos = [\"github.com/acme/*\"]\n\
             credential = { kind = \"static\", ref = \"file:gh-token\", env = \"GH_TOKEN\" }"
        )
    ));
    (h, api, ca_dir)
}

fn wait_for_approval_request(h: &Harness) -> audit::AuditEvent {
    wait_for(Duration::from_secs(60), || h.events().into_iter().find(|e| e.kind == EventKind::ApprovalRequested))
        .expect("an approval.requested event")
}

#[test]
fn a_held_write_is_approved_on_the_host_once_and_never_from_inside() {
    let (h, api, _ca) = setup();
    let base = format!("https://api.github.com:{}", api.port);
    let curl = |m: &str, p: &str| {
        format!(
            "curl -sS -o /dev/null -w '%{{http_code}} ' -X {m} -H \"Authorization: Bearer $GH_TOKEN\" -d '{{}}' {base}{p}; "
        )
    };
    // The agent: untrusted input, a sensitive read, a public PR (held back);
    // it then tries to approve itself, waits for the user, and retries twice.
    let script = format!(
        "{issues}{secret}\
         body=$(curl -sS -X POST -H \"Authorization: Bearer $GH_TOKEN\" -d '{{}}' {base}/repos/acme/public/pulls); \
         id=$(printf '%s' \"$body\" | grep -o 'apr-[a-z0-9]*' | head -1); echo \"HELD $id\"; \
         BROKER_HOME={home} {broker} approve \"$id\" --yes >/dev/null 2>&1; echo \"SELF=$?\"; \
         i=0; while [ ! -f approved ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done; \
         {pr}{pr}",
        issues = curl("GET", "/repos/acme/public/issues"),
        secret = curl("GET", "/repos/acme/secret/contents/README.md"),
        pr = curl("POST", "/repos/acme/public/pulls"),
        home = h.home.path().display(),
        broker = h.bins.broker.display(),
    );
    let mut child = h.spawn_sh(&script);
    let req = wait_for_approval_request(&h);
    let id = req.detail.get("approval").and_then(|v| v.as_str()).unwrap().to_string();
    assert_eq!(req.detail.get("reason").and_then(|v| v.as_str()), Some("rule_of_two"));
    assert_eq!(req.detail["authority_diff"], serde_json::json!(["+ github pr.create github.com/acme/public"]));
    // The deny row names the approval; the pending list shows its ground truth.
    let deny = h
        .events()
        .into_iter()
        .find(|e| e.kind == EventKind::RequestDecision && e.reason == Some(Reason::RuleOfTwo))
        .expect("the held write");
    assert_eq!(deny.detail.get("approval").and_then(|v| v.as_str()), Some(id.as_str()));
    // Wait until the agent's self-approval attempt has run, then review.
    wait_for(Duration::from_secs(30), || {
        let p = h.broker(&["approvals", "--json"]);
        let v: serde_json::Value = serde_json::from_str(&p.stdout).ok()?;
        v.as_array().filter(|a| !a.is_empty()).cloned()
    })
    .expect("the approval is still pending");
    let list: serde_json::Value = serde_json::from_str(&h.broker(&["approvals", "--json"]).stdout).unwrap();
    let p = &list[0];
    assert_eq!(p["id"], id.as_str());
    let causes: Vec<String> = p["provenance"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| format!("{} {}", e["label"].as_str().unwrap(), e["cause"].as_str().unwrap()))
        .collect();
    assert!(causes.contains(&"untrusted_input github repo.read github.com/acme/public".to_string()), "{causes:?}");
    assert!(causes.contains(&"sensitive_read github repo.read github.com/acme/secret".to_string()), "{causes:?}");
    // Without a terminal and without --yes, nothing is approved.
    let r = h.broker(&["approve", &id]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.stdout.contains("+ github pr.create github.com/acme/public"), "the diff is shown: {r:?}");
    // The user approves (once) on the host; the agent retries.
    let r = h.broker(&["approve", &id, "--yes"]);
    assert_eq!(r.code, 0, "{r:?}");
    std::fs::write(h.repo_path().join("approved"), b"").unwrap();
    let status = child.wait().unwrap();
    let mut out = String::new();
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    assert!(status.success(), "{out}");
    assert!(out.contains(&format!("HELD {id}")), "{out}");
    assert!(!out.contains("SELF=0"), "the agent must not be able to approve from inside: {out}");
    assert!(out.starts_with("200 200 "), "{out}");
    assert!(out.trim_end().ends_with("201 403"), "retry passes once, the next is held again: {out}");
    // On record: who approved what, and which allow used it.
    let evs = h.events();
    let granted = evs.iter().find(|e| e.kind == EventKind::ApprovalGranted).expect("approval.granted");
    assert_eq!(granted.detail.get("scope").and_then(|v| v.as_str()), Some("once"));
    assert!(granted.detail.get("approver").and_then(|v| v.as_str()).unwrap().starts_with("local:"));
    let used = evs
        .iter()
        .filter(|e| matches!(&e.decision, Some(d) if d.result == DecisionResult::Allow))
        .filter(|e| e.detail.contains_key("approvals_used"))
        .count();
    assert_eq!(used, 1, "exactly one allowed request used the approval");
    let posts = api.seen().iter().filter(|s| s.method == "POST").count();
    assert_eq!(posts, 1, "only the approved PR reached GitHub");
    h.verify_audit().unwrap();
}
