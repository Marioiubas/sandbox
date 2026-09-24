//! M1 acceptance B8 and conformance categories 6 (redirects), 7 (Host /
//! SNI / CONNECT mismatch) and the HTTP-framing part of 8. The invariant
//! checked throughout: every request an upstream received has an L7 allow
//! row, and no credential crosses to a host it is not bound to.

use audit::{DecisionResult, EventKind, Reason};
use conformance::m1::*;
use conformance::*;

struct Fx {
    h: Harness,
    api: HttpsServer,
    other: HttpsServer,
    key: String,
    _ca_dir: tempfile::TempDir,
}

fn setup() -> Fx {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let key = canary("sk-ant-api03");
    let api = HttpsServer::start(&ca, "api.test", api_handler(key.clone()));
    let other = HttpsServer::start(&ca, "other.test", api_handler("never-valid".into()));
    let config = format!(
        "version = 1\n[tls]\nextra_roots = [\"{}\"]\n\n{}\n{}",
        ca.pem_path.display(),
        loopback_grant(
            "api",
            "api.test",
            api.port,
            "methods = [\"GET\", \"POST\"]\npaths = [\"/v1/messages\", \"/echo\", \"/redirect\", \"/plain\"]\n\
             credential = { kind = \"static\", ref = \"file:k\", header = \"x-api-key\", env = \"ANTHROPIC_API_KEY\" }"
        ),
        loopback_grant("other", "other.test", other.port, "methods = [\"GET\"]\npaths = [\"/plain\"]"),
    );
    let h = Harness::new(&config);
    h.write_secret("k", key.as_bytes());
    Fx { h, api, other, key, _ca_dir: ca_dir }
}

fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn l7_rows(h: &Harness, result: DecisionResult) -> usize {
    h.events()
        .iter()
        .filter(|e| e.kind == EventKind::RequestDecision && e.detail.get("layer").is_some())
        .filter(|e| matches!(&e.decision, Some(d) if d.result == result))
        .count()
}

fn denied_with(h: &Harness, reason: Reason) -> bool {
    h.events()
        .iter()
        .any(|e| e.reason == Some(reason) && matches!(&e.decision, Some(d) if d.result == DecisionResult::Deny))
}

/// Every upstream request is covered by an allow row (no desync, no bypass).
fn assert_no_unaudited_upstream_requests(f: &Fx) {
    let upstream = f.api.seen().len() + f.other.seen().len();
    assert_eq!(upstream, l7_rows(&f.h, DecisionResult::Allow), "api={:?} other={:?}", f.api.seen(), f.other.seen());
}

#[test]
fn cat6_redirects_are_reevaluated_and_drop_credentials() {
    let f = setup();
    let redirect = |to: &str| format!("https://api.test:{}/redirect?to={}", f.api.port, pct(to));
    // Off-policy hops: another host, a metadata literal, a forbidden path.
    for (to, reason) in [
        ("https://evil.test:443/".to_string(), Reason::HostNotAllowed),
        ("https://169.254.169.254/latest/meta-data/".to_string(), Reason::IpLiteral),
        (format!("https://api.test:{}/v1/files", f.api.port), Reason::L7NoRuleMatched),
    ] {
        let r = f.h.sh(&format!("curl -sS -L -o /dev/null -w '%{{http_code}}' '{}'; echo; echo RC=$?", redirect(&to)));
        assert!(!r.stdout.starts_with("200"), "{to}: {r:?}");
        assert!(denied_with(&f.h, reason), "{to}: {reason:?} logged");
    }
    // A cross-origin hop carrying the sentinel: bound to api.test only.
    let to = format!("https://other.test:{}/plain", f.other.port);
    let r = f.h.sh(&format!(
        "curl -sS -L -o /dev/null -w '%{{http_code}}' -H \"x-api-key: $ANTHROPIC_API_KEY\" '{}'",
        redirect(&to)
    ));
    assert_eq!(r.stdout, "403", "{r:?}");
    assert!(denied_with(&f.h, Reason::SentinelWrongHost));
    assert!(f.other.seen().is_empty(), "the sentinel never reached other.test");
    // Without it the hop succeeds, and other.test gets no credential.
    let r = f.h.sh(&format!("curl -sS -L -o /dev/null -w '%{{http_code}}' '{}'", redirect(&to)));
    assert_eq!(r.stdout, "200", "{r:?}");
    let seen = f.other.seen();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].header("x-api-key").is_none() && seen[0].header("authorization").is_none());
    assert!(!f.other.received(&f.key));
    assert_no_unaudited_upstream_requests(&f);
}

#[test]
fn cat7_host_sni_connect_must_agree() {
    let f = setup();
    let (ap, op) = (f.api.port, f.other.port);
    let probe = f.h.bins.probe.display().to_string();
    // Host header names another (even allowed) host.
    let r = f.h.sh(&format!(
        "curl -sS -o /dev/null -w '%{{http_code}}' -H 'Host: other.test:{op}' https://api.test:{ap}/plain"
    ));
    assert_eq!(r.stdout, "421", "{r:?}");
    // Absolute-form target naming another host inside the api.test tunnel.
    let r = f.h.sh(&format!(
        "{probe} tls-raw api.test {ap} 'GET https://evil.test/plain HTTP/1.1\\r\\nHost: api.test:{ap}\\r\\n\\r\\n'"
    ));
    assert!(r.stdout.contains("421") && r.stdout.contains("host_header_mismatch"), "{r:?}");
    // SNI for another host than CONNECT: cut before any HTTP.
    let r = f.h.sh(&format!(
        "{probe} tls-raw api.test {ap} 'GET /plain HTTP/1.1\\r\\nHost: other.test\\r\\n\\r\\n' other.test"
    ));
    assert_eq!(r.code, 10, "{r:?}");
    assert!(denied_with(&f.h, Reason::ConnectSniMismatch));
    assert!(denied_with(&f.h, Reason::HostHeaderMismatch));
    assert!(f.api.seen().is_empty() && f.other.seen().is_empty());
}

#[test]
fn cat8_ambiguous_framing_never_desyncs() {
    let f = setup();
    let ap = f.api.port;
    let probe = f.h.bins.probe.display().to_string();
    let host = format!("Host: api.test:{ap}\\r\\n");
    let attacks = [
        // CL.TE: a smuggled second request after a chunked terminator.
        format!(
            "POST /plain HTTP/1.1\\r\\n{host}Content-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /echo HTTP/1.1\\r\\n{host}\\r\\n"
        ),
        // TE.CL / non-final chunked.
        format!(
            "POST /plain HTTP/1.1\\r\\n{host}Transfer-Encoding: chunked, identity\\r\\nContent-Length: 3\\r\\n\\r\\nabc"
        ),
        // Conflicting Content-Length.
        format!("POST /plain HTTP/1.1\\r\\n{host}Content-Length: 3\\r\\nContent-Length: 40\\r\\n\\r\\nabc"),
        // NUL, bare CR and whitespace before the colon.
        format!("GET /plain HTTP/1.1\\r\\n{host}X-A: a\\x00b\\r\\n\\r\\n"),
        format!("GET /plain HTTP/1.1\\r\\n{host}X-A: a\\rb\\r\\n\\r\\n"),
        format!("GET /plain HTTP/1.1\\r\\n{host}X-A : b\\r\\n\\r\\n"),
        // Obsolete line folding.
        format!("GET /plain HTTP/1.1\\r\\n{host}X-A: a\\r\\n b\\r\\n\\r\\n"),
        // HTTP/2 prior knowledge on an http/1.1 tunnel.
        "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n".to_string(),
    ];
    for a in &attacks {
        let r = f.h.sh(&format!("{probe} tls-raw api.test {ap} '{a}'"));
        let resp = r.stdout.clone();
        if std::env::var_os("SHOW_FRAMING").is_some() {
            eprintln!("--- {a}\n=> code {} {:?}", r.code, resp.lines().next().unwrap_or(""));
        }
        assert!(r.code == 10 || resp.starts_with("HTTP/1.1 4") || resp.starts_with("HTTP/1.1 200"), "{a}: {r:?}");
        // At most the first (unambiguous) request is answered.
        assert!(resp.matches("HTTP/1.1 ").count() <= 1, "{a}: two responses on one ambiguous message: {resp}");
    }
    // Every message the parser refused is a logged deny, not a silent 400.
    let parse_denies =
        f.h.events()
            .iter()
            .filter(|e| e.reason == Some(Reason::MalformedRequest) && e.detail.get("layer").is_some())
            .count();
    assert!(parse_denies >= 7, "parse refusals logged: {parse_denies}");
    assert!(f.api.seen().iter().all(|s| s.path != "/echo"), "the smuggled request never reached the upstream");
    assert_no_unaudited_upstream_requests(&f);
    // Oversized head.
    let big = format!("GET /plain HTTP/1.1\r\nHost: api.test:{ap}\r\nX-Big: {}\r\n\r\n", "a".repeat(300_000));
    let file = f.h.repo_path().join("big-request.bin");
    std::fs::write(&file, big).unwrap();
    let r = f.h.sh(&format!("{probe} tls-raw api.test {ap} @{}", file.display()));
    assert!(
        r.code == 10 || r.stdout.starts_with("HTTP/1.1 4"),
        "code {} stdout {:?} stderr {:?}",
        r.code,
        r.stdout.chars().take(200).collect::<String>(),
        r.stderr
    );
    assert_no_unaudited_upstream_requests(&f);
}
