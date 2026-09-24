//! M2 acceptance C4: decisions export as OCSF 1.9.0 events that validate
//! (100%) and reach a test SIEM sink (Splunk HEC-style) and an OTLP/HTTP
//! collector; a sink token comes from a secret reference, never argv.

use conformance::m1::*;
use conformance::*;
use std::process::Command;

fn export(h: &Harness, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut c = Command::new(&h.bins.broker);
    c.args(["audit", "export"]).args(args).env("BROKER_HOME", h.home.path());
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().unwrap()
}

#[test]
fn c4_events_validate_and_reach_the_sinks() {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let ok: Handler = std::sync::Arc::new(|_s: &Seen| Reply::new(200, "ok\n"));
    let api = HttpsServer::start(&ca, "api.test", ok);
    let config = format!(
        "version = 1\n[tls]\nextra_roots = [\"{}\"]\n\n{}",
        ca.pem_path.display(),
        loopback_grant("api", "api.test", api.port, "methods = [\"POST\"]\npaths = [\"/v1/messages\"]")
    );
    let h = Harness::new(&config);
    let u = |p: &str| format!("https://api.test:{}{p}", api.port);
    let r = h.sh(&format!(
        "curl -sS -o /dev/null -X POST -d x {}; curl -sS -o /dev/null {}; curl -sS -m 5 -o /dev/null https://evil.test/ ; true",
        u("/v1/messages"),
        u("/v1/files")
    ));
    assert_eq!(r.code, 0, "{r:?}");

    // NDJSON to stdout: every decision is an OCSF event and validates.
    let out = export(&h, &[], &[]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let decisions = h.events().iter().filter(|e| e.kind == audit::EventKind::RequestDecision).count();
    assert_eq!(lines.len(), decisions, "one OCSF event per decision");
    for v in &lines {
        audit::ocsf::validate(v).unwrap_or_else(|e| panic!("{e}: {v}"));
    }
    let classes: std::collections::BTreeSet<u64> = lines.iter().filter_map(|v| v["class_uid"].as_u64()).collect();
    assert!(classes.contains(&4001) && classes.contains(&4002), "{classes:?}");
    assert!(lines.iter().any(|v| v["action_id"] == 2 && v["status_detail"] == "l7_no_rule_matched"));
    assert!(lines.iter().any(|v| v["action_id"] == 2 && v["status_detail"] == "host_not_allowed"));

    // Each event carries its chain position and hash (the export anchor);
    // `--from-seq` resumes after the last exported row.
    let last = lines.iter().filter_map(|v| v["metadata"]["sequence"].as_i64()).max().unwrap();
    assert!(lines.iter().all(|v| v["metadata"]["uid"].as_str().is_some_and(|h| h.len() == 64)));
    let out = export(&h, &["--from-seq", &last.to_string()], &[]);
    assert!(out.status.success() && out.stdout.iter().all(|b| b.is_ascii_whitespace()), "{out:?}");

    // HEC-style sink with a token from brokerd-side env (never argv).
    let hec = PlainSink::start();
    let url = format!("http://127.0.0.1:{}/services/collector/event", hec.port);
    let out = export(
        &h,
        &["--format", "hec", "--to", &url, "--token", "env:TEST_HEC_TOKEN"],
        &[("TEST_HEC_TOKEN", "hec-canary-token")],
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let got = hec.requests.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert!(got[0].0.to_ascii_lowercase().contains("authorization: splunk hec-canary-token"), "{}", got[0].0);
    let body = String::from_utf8_lossy(&got[0].1).to_string();
    let hec_events: Vec<serde_json::Value> = body.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(hec_events.len(), decisions);
    for e in &hec_events {
        audit::ocsf::validate(&e["event"]).unwrap();
        assert_eq!(e["source"], "broker");
    }

    // OTLP/HTTP logs collector.
    let otlp = PlainSink::start();
    let out = export(&h, &["--format", "otlp", "--to", &format!("http://127.0.0.1:{}/v1/logs", otlp.port)], &[]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let got = otlp.requests.lock().unwrap().clone();
    let v: serde_json::Value = serde_json::from_slice(&got[0].1).unwrap();
    let recs = v["resourceLogs"][0]["scopeLogs"][0]["logRecords"].as_array().unwrap();
    assert_eq!(recs.len(), decisions);

    // Plain HTTP to anything but loopback is refused.
    let out = export(&h, &["--format", "hec", "--to", "http://example.com/services/collector/event"], &[]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("loopback"), "{}", String::from_utf8_lossy(&out.stderr));
}

/// `audit.query` on the control socket: filters narrow the answer and bad
/// filters are refused, never ignored.
#[test]
fn audit_query_filters_through_the_daemon() {
    let h = Harness::new("version = 1\n");
    let r =
        h.sh("curl -sS -m 5 -o /dev/null https://evil.test/ ; curl -sS -m 5 -o /dev/null https://other.test/ ; true");
    assert_eq!(r.code, 0, "{r:?}");
    let q = |args: &[&str]| {
        let out = Command::new(&h.bins.broker)
            .args(["audit", "query"])
            .args(args)
            .env("BROKER_HOME", h.home.path())
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };
    let (code, out, err) = q(&["--decision", "deny", "--host", "EVIL.test", "--json"]);
    assert_eq!(code, Some(0), "{err}");
    let rows: Vec<serde_json::Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert!(!rows.is_empty());
    for r in &rows {
        assert_eq!(r["event"]["dest"]["host"], "evil.test");
        assert_eq!(r["event"]["decision"]["result"], "deny");
        assert_eq!(r["hash"].as_str().unwrap().len(), 64);
    }
    let (code, out, _) = q(&["--kind", "session.start", "--limit", "1"]);
    assert_eq!(code, Some(0));
    assert_eq!(out.lines().count(), 1);
    for bad in [&["--decision", "maybe"][..], &["--reason", "nope"], &["--host", "a..b"], &["--limit", "5000"]] {
        let (code, _, err) = q(bad);
        assert_eq!(code, Some(2), "{bad:?}: {err}");
    }
}
