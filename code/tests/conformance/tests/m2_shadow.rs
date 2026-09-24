//! Shadow mode (Policy Learning Loop): a candidate policy is evaluated on
//! every request beside the enforced one and its verdict logged; it never
//! decides anything. The report lists what it would tighten or widen.

use audit::{DecisionResult, EventKind};
use conformance::m1::*;
use conformance::*;
use std::process::Command;

fn broker(h: &Harness, args: &[&str]) -> ProbeResult {
    let out = Command::new(&h.bins.broker)
        .args(args)
        .current_dir(h.repo.path())
        .env("BROKER_HOME", h.home.path())
        .env("BROKER_DAEMON_IDLE_SECS", "3")
        .output()
        .unwrap();
    ProbeResult::from(out)
}

#[test]
fn a_shadow_candidate_is_logged_but_never_decides() {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let ok: Handler = std::sync::Arc::new(|_s: &Seen| Reply::new(200, "ok\n"));
    let api = HttpsServer::start(&ca, "api.test", ok);
    let head = format!("version = 1\n[tls]\nextra_roots = [\"{}\"]\n\n", ca.pem_path.display());
    let rules = |paths: &str| {
        loopback_grant("api", "api.test", api.port, &format!("methods = [\"POST\", \"GET\"]\npaths = [{paths}]"))
    };
    let h = Harness::new(&format!("{head}{}", rules("\"/v1/messages\", \"/v1/files\"")));
    // The candidate drops /v1/files and adds /v1/models.
    let cand = h.home.path().join("candidate.toml");
    std::fs::write(&cand, format!("{head}{}", rules("\"/v1/messages\", \"/v1/models\""))).unwrap();

    let bad = h.home.path().join("bad.toml");
    std::fs::write(&bad, "version = 1\n[[egress]]\nnope = 1\n").unwrap();
    assert_eq!(broker(&h, &["policy", "shadow", bad.to_str().unwrap()]).code, 125, "an invalid candidate is refused");
    let r = broker(&h, &["policy", "shadow", cand.to_str().unwrap()]);
    assert_eq!(r.code, 0, "{r:?}");

    let u = |p: &str| format!("https://api.test:{}{p}", api.port);
    let task = format!(
        "for p in /v1/messages /v1/files /v1/models; do curl -sS -o /dev/null -w '%{{http_code}} ' https://api.test:{}$p; done",
        api.port
    );
    let n0 = h.events().len();
    let r = broker(&h, &["run", "--", "/bin/sh", "-c", &task]);
    // The enforced policy decided: /v1/models is still denied.
    assert_eq!(r.stdout.trim(), "200 200 403", "{r:?}");
    assert!(api.seen().iter().all(|s| s.path != "/v1/models"), "nothing the candidate alone allows reached upstream");

    let evs: Vec<_> = h.events().into_iter().skip(n0).collect();
    let start = evs.iter().find(|e| e.kind == EventKind::SessionStart).unwrap();
    assert_eq!(start.detail["mode"], "shadow");
    assert!(start.detail["shadow"]["candidate"].as_str().unwrap().starts_with("sha256:"));
    let l7: Vec<_> = evs
        .iter()
        .filter(|e| {
            e.kind == EventKind::RequestDecision && e.detail.get("layer").and_then(|v| v.as_str()) == Some("l7")
        })
        .collect();
    let by_path = |p: &str| {
        l7.iter().find(|e| e.detail["actions"].to_string().contains(p)).unwrap_or_else(|| panic!("no row for {p}"))
    };
    let files = by_path("/v1/files");
    assert_eq!(files.decision.as_ref().unwrap().result, DecisionResult::Allow);
    assert_eq!(files.detail["shadow"]["allow"], false);
    assert_eq!(files.detail["shadow"]["differs"], true);
    let models = by_path("/v1/models");
    assert_eq!(models.decision.as_ref().unwrap().result, DecisionResult::Deny);
    assert_eq!(models.detail["shadow"]["allow"], true);
    assert_eq!(by_path("/v1/messages").detail["shadow"]["differs"], false);

    // `broker why` shows the candidate's verdict.
    let rid = files.request_id.as_ref().unwrap().to_string();
    let why = h.why(&rid);
    assert!(why.contains("shadow    the candidate policy would deny"), "{why}");

    let rep = broker(&h, &["policy", "shadow", "--report"]);
    assert_eq!(rep.code, 0, "{rep:?}");
    assert!(rep.stdout.contains("would deny 1 request(s) your policy allowed"), "{}", rep.stdout);
    assert!(rep.stdout.contains("would allow 1 request(s) your policy denied"), "{}", rep.stdout);
    assert!(rep.stdout.contains("revise it before enforcing"), "{}", rep.stdout);

    // Record mode is never shadowed; after --off, sessions are enforce again.
    let n1 = h.events().len();
    let r = broker(&h, &["learn", "--", "/bin/sh", "-c", &format!("curl -sS -o /dev/null {}", u("/v1/messages"))]);
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(broker(&h, &["policy", "shadow", "--off"]).code, 0);
    let r = broker(&h, &["run", "--", "/bin/sh", "-c", &format!("curl -sS -o /dev/null {}", u("/v1/messages"))]);
    assert_eq!(r.code, 0, "{r:?}");
    let later: Vec<_> = h.events().into_iter().skip(n1).collect();
    let modes: Vec<&str> =
        later.iter().filter(|e| e.kind == EventKind::SessionStart).filter_map(|e| e.detail["mode"].as_str()).collect();
    assert_eq!(modes, vec!["record", "enforce"]);
    assert!(later.iter().all(|e| e.detail.get("shadow").is_none()));
    h.verify_audit().unwrap();
}
