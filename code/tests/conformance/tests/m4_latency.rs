//! M4 E3 latency harness (L4 Product Metrics): the latency the broker adds
//! over a direct connection on its L4 splice path and its terminated L7
//! path, for warm (reused) and new connections, under concurrent load; and
//! `broker run` start time. Thresholds (L4): warm added p50 ≤5 ms and
//! p95 ≤25 ms; new terminated connection added p50 ≤15 ms; start ≤150 ms.
//!
//! Run on demand (it measures, it does not gate):
//! `cargo test -p conformance --test m4_latency -- --ignored --nocapture`.
//! The report is printed and written to `$CARGO_TARGET_TMPDIR/latency.json`.

use conformance::m1::*;
use conformance::*;
use serde_json::json;
use std::time::Instant;

const CLIENTS: usize = 8;
const WARM: usize = 50;
const NEW: usize = 15;

fn pct(v: &[f64], p: f64) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[((s.len() - 1) as f64 * p).round() as usize]
}

/// `CLIENTS` concurrent curl processes, each making `n` requests (one
/// connection when `warm`, a new one per request otherwise); prints one
/// `time_total` per request.
fn script(url: &str, n: usize, warm: bool, extra: &str) -> String {
    let close = if warm { "" } else { "-H 'Connection: close'" };
    let urls: Vec<String> = (0..n).map(|i| format!("-o /dev/null '{url}?i={i}'")).collect();
    let one = format!("curl -sS {extra} {close} -w '%{{time_total}}\\n' {}", urls.join(" "));
    let par: String = (0..CLIENTS).map(|j| format!("( {one} > \"$T/o{j}\" ) & ")).collect();
    format!("T=$(mktemp -d); {par} wait; cat \"$T\"/o*")
}

fn times(out: &str, expect: usize) -> Vec<f64> {
    let v: Vec<f64> = out.lines().filter_map(|l| l.trim().parse::<f64>().ok()).map(|s| s * 1000.0).collect();
    assert_eq!(v.len(), expect, "every request answered: {out}");
    v
}

#[test]
#[ignore = "measurement; run on demand"]
fn e3_latency_report() {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let echo: Handler = std::sync::Arc::new(|_s: &Seen| Reply::new(200, "ok"));
    let splice = HttpsServer::start(&ca, "echo-splice.example.com", echo.clone());
    let term = HttpsServer::start(&ca, "echo-l7.example.com", echo);
    let h = Harness::new(&format!(
        "version = 1\n[tls]\nextra_roots = [\"{}\"]\n{}{}",
        ca.pem_path.display(),
        loopback_grant("splice", "echo-splice.example.com", splice.port, ""),
        loopback_grant("l7", "echo-l7.example.com", term.port, "methods = [\"GET\"]")
    ));
    let url = |s: &HttpsServer| format!("https://{}:{}/echo", s.host, s.port);
    let direct = |s: &HttpsServer, warm: bool, n: usize| {
        let extra = format!("--cacert {} --resolve {}:{}:127.0.0.1", ca.pem_path.display(), s.host, s.port);
        let out =
            std::process::Command::new("/bin/sh").arg("-c").arg(script(&url(s), n, warm, &extra)).output().unwrap();
        times(&String::from_utf8_lossy(&out.stdout), n * CLIENTS)
    };
    let brokered = |s: &HttpsServer, warm: bool, n: usize| {
        let r = h.sh(&script(&url(s), n, warm, ""));
        assert_eq!(r.code, 0, "{r:?}");
        times(&r.stdout, n * CLIENTS)
    };
    let _ = h.sh("true"); // start the daemon outside the measurements

    let mut rows = Vec::new();
    for (path, s) in [("splice (L4)", &splice), ("terminated (L7)", &term)] {
        for (conn, warm, n) in [("warm", true, WARM), ("new", false, NEW)] {
            let (d, b) = (direct(s, warm, n), brokered(s, warm, n));
            rows.push(json!({
                "path": path, "connection": conn, "requests": b.len(),
                "direct_ms": { "p50": pct(&d, 0.5), "p95": pct(&d, 0.95), "p99": pct(&d, 0.99) },
                "broker_ms": { "p50": pct(&b, 0.5), "p95": pct(&b, 0.95), "p99": pct(&b, 0.99) },
                "added_ms": { "p50": pct(&b, 0.5) - pct(&d, 0.5), "p95": pct(&b, 0.95) - pct(&d, 0.95) },
            }));
        }
    }
    let mut starts = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        assert_eq!(h.run_argv(None, &["/usr/bin/true".into()], &[]).code, 0);
        starts.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let report = json!({
        "os": std::env::consts::OS, "arch": std::env::consts::ARCH, "clients": CLIENTS,
        "paths": rows,
        "broker_run_true_ms": { "p50": pct(&starts, 0.5), "p95": pct(&starts, 0.95) },
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    for r in &rows {
        println!(
            "{:<16} {:<5} added p50 {:>6.2} ms  p95 {:>6.2} ms  (broker p50 {:.2}, direct p50 {:.2})",
            r["path"].as_str().unwrap(),
            r["connection"].as_str().unwrap(),
            r["added_ms"]["p50"].as_f64().unwrap(),
            r["added_ms"]["p95"].as_f64().unwrap(),
            r["broker_ms"]["p50"].as_f64().unwrap(),
            r["direct_ms"]["p50"].as_f64().unwrap()
        );
    }
    println!("broker run -- /usr/bin/true: p50 {:.1} ms, p95 {:.1} ms", pct(&starts, 0.5), pct(&starts, 0.95));
    std::fs::write(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("latency.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}
