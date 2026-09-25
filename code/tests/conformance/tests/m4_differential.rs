//! M4 conformance category 8 (parser differentials), the decision-changing
//! part: the broker authorizes the canonical path and forwards exactly that;
//! no request it allows under `paths = ["/allowed/**"]` can reach a path
//! outside `/allowed/` after the normalisations real servers apply (single
//! or double percent-decoding, backslash as slash, `;` parameters, doubled
//! slashes, dot segments, overlong UTF-8 dots). Everything else is denied
//! and logged with a reason.

use audit::{DecisionResult, EventKind};
use conformance::m1::*;
use conformance::*;

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

fn decode(p: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < p.len() {
        match (p[i], p.get(i + 1).copied().and_then(hex), p.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(h), Some(l)) => {
                out.push(h << 4 | l);
                i += 3;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// A lenient server's view of a received path: `decodes` rounds of
/// percent-decoding, overlong `C0 AE` and full-width dots as `.`, `\` as `/`, `;params`
/// dropped, empty segments collapsed, dot segments resolved.
fn server_view(path: &str, decodes: usize) -> String {
    let mut b = path.as_bytes().to_vec();
    for _ in 0..decodes {
        b = decode(&b);
    }
    // Overlong `C0 AE` decodes (lossily) to two replacement characters;
    // NFKC-normalising servers read a full-width dot as `.`.
    let s = String::from_utf8_lossy(&b).replace("\u{FFFD}\u{FFFD}", ".").replace('\u{FF0E}', ".").replace('\\', "/");
    let mut out: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        let seg = seg.split(';').next().unwrap_or("");
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            x => out.push(x),
        }
    }
    format!("/{}", out.join("/"))
}

#[test]
fn cat8_no_allowed_request_reaches_outside_its_path_rule() {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let api = HttpsServer::start(&ca, "api.test", std::sync::Arc::new(|_s: &Seen| Reply::new(200, "ok")));
    let h = Harness::new(&format!(
        "version = 1\n[tls]\nextra_roots = [\"{}\"]\n{}",
        ca.pem_path.display(),
        loopback_grant("api", "api.test", api.port, "methods = [\"GET\"]\npaths = [\"/allowed/**\"]")
    ));
    let targets = [
        "/allowed/x",
        "/allowed/a/b",
        "/allowed/%41",
        "/allowed/x%20y",
        "/allowed/../secret",
        "/allowed/./x",
        "/allowed/%2e%2e/secret",
        "/allowed/%2E%2E%2Fsecret",
        "/allowed%2f..%2fsecret",
        "/allowed/..%2fsecret",
        "/allowed/.%2e/secret",
        "/allowed\\..\\secret",
        "/allowed/..\\secret",
        "/allowed/%5c..%5csecret",
        "/allowed//../secret",
        "/allowed/;/../secret",
        "/allowed;/../secret",
        "/allowed/x;jsessionid=1/../../secret",
        "/allowed/..;/secret",
        "/allowed/..;x/secret",
        "/allowed/..%3b/secret",
        "/allowed/..%253b/secret",
        "/allowed/.;/x",
        "/allowed/%c0%ae%c0%ae/secret",
        "/allowed/%252e%252e/secret",
        "/allowed/%252e%252e%252fsecret",
        "/allowed/%ef%bc%8e%ef%bc%8e/secret",
        "/allowed/%00/x",
        "/Allowed/x",
        "//allowed/x",
        "/./allowed/x",
        "/secret/../allowed/x",
        "/allowed/x?/../../secret",
        "*",
        "http://api.test/allowed/x",
    ];
    let dir = h.repo_path();
    let probe = h.bins.probe.display().to_string();
    let n0 = h.events().len();
    let mut script = String::new();
    for (i, t) in targets.iter().enumerate() {
        let req = format!("GET {t} HTTP/1.1\r\nHost: api.test:{}\r\nConnection: close\r\n\r\n", api.port);
        std::fs::write(dir.join(format!("req{i}")), req).unwrap();
        script.push_str(&format!("{probe} tls-raw api.test {} @req{i} > /dev/null 2>&1; ", api.port));
    }
    let r = h.sh(&script);
    assert_eq!(r.code, 0, "{r:?}");

    let seen: Vec<String> = api.seen.lock().unwrap().iter().map(|s| s.path.clone()).collect();
    assert!(!seen.is_empty() && seen.contains(&"/allowed/x".to_string()), "in-policy controls succeed: {seen:?}");
    // No received path escapes the rule under any server's normalisation.
    for p in &seen {
        for decodes in 0..=2 {
            let v = server_view(p, decodes);
            assert!(v.starts_with("/allowed/") || v == "/allowed", "{p:?} is {v:?} after {decodes} decode(s)");
        }
    }
    // Every forwarded request is the path the broker authorized (and logged).
    let evs: Vec<_> = h.events().into_iter().skip(n0).collect();
    let allowed_paths: Vec<String> = evs
        .iter()
        .filter(|e| e.kind == EventKind::RequestDecision)
        .filter(|e| matches!(&e.decision, Some(d) if d.result == DecisionResult::Allow))
        .filter_map(|e| e.detail.get("actions").and_then(|a| a[0]["path"].as_str()).map(str::to_string))
        .collect();
    for p in &seen {
        assert!(allowed_paths.contains(p), "{p:?} reached the upstream without a matching allow row");
    }
    // Everything not forwarded was denied with a logged reason.
    let denies = evs
        .iter()
        .filter(|e| e.kind == EventKind::RequestDecision)
        .filter(|e| matches!(&e.decision, Some(d) if d.result == DecisionResult::Deny))
        .filter(|e| e.reason.is_some())
        .count();
    assert!(denies + seen.len() >= targets.len(), "{} denied + {} forwarded of {}", denies, seen.len(), targets.len());
    if std::env::var_os("SHOW_DIFFERENTIAL").is_some() {
        eprintln!("forwarded: {seen:?}\ndenied: {denies}");
    }
}
