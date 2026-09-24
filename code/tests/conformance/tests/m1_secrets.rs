//! M1 Secrets Outside: B1 (only sentinels in the sandbox), B4 (planted key
//! rejected), B5 (a sentinel off-host is useless), B6 (LLM call with the
//! injected key), B7 (nothing reflected) and conformance categories 1 and 2.
//! The upstream is a fake API reached over verified TLS; the key is a canary.

use audit::{DecisionResult, EventKind, Reason};
use conformance::m1::*;
use conformance::*;

const PATHS: &str = r#"["/v1/messages", "/echo", "/echo-gzip", "/echo-header", "/cookie", "/redirect", "/plain"]"#;

struct Llm {
    h: Harness,
    srv: HttpsServer,
    key: String,
    _ca_dir: tempfile::TempDir,
}

fn llm() -> Llm {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let key = canary("sk-ant-api03");
    let srv = HttpsServer::start(&ca, "api.test", api_handler(key.clone()));
    let grant = loopback_grant(
        "llm",
        "api.test",
        srv.port,
        &format!(
            "methods = [\"GET\", \"POST\"]\npaths = {PATHS}\n\
             credential = {{ kind = \"static\", ref = \"file:llm-key\", header = \"x-api-key\", env = \"ANTHROPIC_API_KEY\" }}"
        ),
    );
    let config = format!("version = 1\n[tls]\nextra_roots = [\"{}\"]\n\n{grant}", ca.pem_path.display());
    let h = Harness::new(&config);
    h.write_secret("llm-key", key.as_bytes());
    Llm { h, srv, key, _ca_dir: ca_dir }
}

impl Llm {
    fn url(&self, path: &str) -> String {
        format!("https://api.test:{}{path}", self.srv.port)
    }
}

fn denies(h: &Harness, reason: Reason) -> usize {
    h.events()
        .iter()
        .filter(|e| e.kind == EventKind::RequestDecision)
        .filter(|e| matches!(&e.decision, Some(d) if d.result == DecisionResult::Deny) && e.reason == Some(reason))
        .count()
}

#[test]
fn b6_llm_call_succeeds_with_injected_key() {
    let t = llm();
    let url = t.url("/v1/messages");
    let r = t.h.sh(&format!(
        "curl -sS -X POST -H \"x-api-key: $ANTHROPIC_API_KEY\" -H 'content-type: application/json' -d '{{}}' -w '\\nHTTP %{{http_code}}\\n' {url}; \
         curl -sS -X POST -d '{{}}' -w '\\nHTTP %{{http_code}}\\n' {url}"
    ));
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.stdout.matches("HTTP 200").count(), 2, "with the sentinel and with no key at all: {r:?}");
    assert!(!r.stdout.contains(&t.key) && !r.stderr.contains(&t.key));
    let seen = t.srv.seen();
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|s| s.header("x-api-key") == Some(t.key.as_str())), "the real key reached the upstream");
    assert!(!t.srv.received(creds::sentinel::PREFIX), "no sentinel ever left the broker");
    // The decision rows name the credential by ID, never by value.
    let allows: Vec<_> =
        t.h.events()
            .into_iter()
            .filter(|e| e.kind == EventKind::RequestDecision && e.detail.get("layer").is_some())
            .collect();
    assert_eq!(allows.len(), 2);
    assert!(allows.iter().all(|e| e.detail["credential_id"] == "user:llm"));
    assert_eq!(allows[1].detail["credential_origin"], "reuse");
    t.h.verify_audit().unwrap();
}

#[test]
fn b1_i1_only_sentinels_inside_the_sandbox() {
    let t = llm();
    let hex = hex_arg(&t.key);
    // Use the credential first, so the scan runs in a session that holds it.
    let url = t.url("/v1/messages");
    let broker_cfg = t.h.config_dir().display().to_string();
    let r = t.h.sh(&format!(
        "curl -sS -o /dev/null -w 'HTTP %{{http_code}}\\n' -X POST -d '{{}}' {url} && \
         {probe} secret-scan {hex} \"$HOME:3\" \"$TMPDIR\" \"$PWD\" {broker_cfg}",
        probe = t.h.bins.probe.display()
    ));
    assert!(r.stdout.contains("HTTP 200"), "{r:?}");
    assert!(r.stdout.contains("CLEAN"), "canary found inside the sandbox: {r:?}");
    assert!(t.srv.received(&t.key));
    // The sandbox holds a sentinel instead.
    let env = t.h.sh("printf '%s' \"$ANTHROPIC_API_KEY\"");
    assert!(env.stdout.starts_with(creds::sentinel::PREFIX), "{env:?}");
    assert!(!env.stdout.contains(&t.key));
    // CI assertion: no canary value in any audit row (or DB page).
    let db = t.h.audit_bytes();
    assert!(!db.is_empty());
    assert!(!db.windows(t.key.len()).any(|w| w == t.key.as_bytes()), "canary in the audit database");
}

fn hex_arg(s: &str) -> String {
    hex::encode(s.as_bytes())
}

#[test]
fn b4_i7_planted_key_to_allowed_host_is_rejected() {
    let t = llm();
    let url = t.url("/v1/messages");
    let planted = [
        "-H 'x-api-key: sk-ant-api03-attacker-planted-key'",
        "-H 'authorization: Bearer sk-ant-attacker'",
        "-H 'cookie: session=attacker'",
        "-u 'user:ghp_attackerToken'",
    ];
    for p in planted {
        let r = t.h.sh(&format!("curl -sS -D - -o /dev/null -X POST -d '{{}}' {p} {url}"));
        assert!(r.stdout.contains(" 403"), "{p}: {r:?}");
        assert!(r.stdout.to_ascii_lowercase().contains("x-broker-reason: foreign_credential"), "{p}: {r:?}");
        let ids = request_ids(&r.stdout);
        assert_eq!(ids.len(), 1, "{r:?}");
        let why = t.h.why(&ids[0]);
        assert!(why.contains("foreign_credential") && why.contains("did not issue"), "{why}");
    }
    assert!(t.srv.seen().is_empty(), "no planted credential reached the upstream");
    assert!(!t.srv.received("attacker"));
    assert_eq!(denies(&t.h, Reason::ForeignCredential), planted.len());
    // A sentinel of this session sent to a host it is not bound to.
    let r = t.h.sh(&format!(
        "curl -sS -o /dev/null -w '%{{http_code}}' -H \"x-api-key: $ANTHROPIC_API_KEY\" -H 'x-api-key: other' {url}"
    ));
    assert_eq!(r.stdout, "403");
}

#[test]
fn b5_sentinel_copied_off_host_is_useless() {
    let t = llm();
    let r = t.h.sh("printf '%s' \"$ANTHROPIC_API_KEY\"");
    let sentinel = r.stdout.trim().to_string();
    assert!(sentinel.starts_with(creds::sentinel::PREFIX));
    // Nothing in the sentinel decodes to the secret.
    assert!(!sentinel.contains(&t.key));
    let raw = hex::decode(&sentinel[creds::sentinel::PREFIX.len()..]).unwrap();
    assert!(!raw.windows(8).any(|w| t.key.as_bytes().windows(8).any(|k| k == w)));
    // Sent straight to the upstream from outside any session: rejected.
    let out = std::process::Command::new("curl")
        .args(["-sS", "-o", "/dev/null", "-w", "%{http_code}", "--cacert"])
        .arg(t._ca_dir.path().join("test-upstream-ca.pem"))
        .args(["--resolve", &format!("api.test:{}:127.0.0.1", t.srv.port)])
        .args(["-X", "POST", "-d", "{}", "-H", &format!("x-api-key: {sentinel}")])
        .arg(t.url("/v1/messages"))
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "401", "{out:?}");
    // And another session's broker does not honour it either.
    let t2 = llm();
    let r = t2.h.sh(&format!(
        "curl -sS -o /dev/null -w '%{{http_code}}' -X POST -d '{{}}' -H 'x-api-key: {sentinel}' {}",
        t2.url("/v1/messages")
    ));
    assert_eq!(r.stdout, "403", "{r:?}");
    assert_eq!(denies(&t2.h, Reason::ForeignCredential), 1);
}

#[test]
fn b7_injected_secret_is_never_reflected() {
    let t = llm();
    for path in ["/echo", "/echo-gzip", "/echo-header"] {
        let r = t.h.sh(&format!("curl -sS --compressed -D - {} ; echo; echo EXIT=$?", t.url(path)));
        assert!(!r.stdout.contains(&t.key) && !r.stderr.contains(&t.key), "{path} reflected the key: {r:?}");
        let b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&t.key)
        };
        assert!(!r.stdout.contains(&b64));
    }
    // Each echo reached the upstream with the key and was cut on the way back.
    assert_eq!(t.srv.seen().iter().filter(|s| s.header("x-api-key") == Some(t.key.as_str())).count(), 3);
    let cut =
        t.h.events()
            .iter()
            .filter(|e| e.kind == EventKind::RequestOutcome && e.reason == Some(Reason::SecretReflected))
            .count();
    assert_eq!(cut, 3, "every reflection is logged as secret_reflected");
    // A clean response passes, and cookies never come back.
    let r = t.h.sh(&format!("curl -sS -D - {}", t.url("/cookie")));
    assert!(r.stdout.contains("cookie set"), "{r:?}");
    assert!(!r.stdout.to_ascii_lowercase().contains("set-cookie"), "{r:?}");
}

#[test]
fn cat2_unmatched_paths_and_methods_deny() {
    let t = llm();
    let r = t.h.sh(&format!(
        "for u in {a} {b}; do curl -sS -o /dev/null -w '%{{http_code}} ' $u; done; curl -sS -o /dev/null -w '%{{http_code}}' -X DELETE {c}",
        a = t.url("/v1/files"),
        b = t.url("/v1/messages/../files"),
        c = t.url("/v1/messages"),
    ));
    let codes: Vec<&str> = r.stdout.split_whitespace().collect();
    assert_eq!(codes.len(), 3, "{r:?}");
    assert!(codes.iter().all(|c| *c == "403"), "{r:?}");
    assert!(t.srv.seen().is_empty());
    assert!(denies(&t.h, Reason::L7NoRuleMatched) >= 2);
}
