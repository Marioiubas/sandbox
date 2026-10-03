//! Review test (I1, response filter): the HTTP/1.1 reason phrase is part of
//! the response the sandbox receives. hyper's client keeps a non-canonical
//! reason phrase as a response extension and hyper's server writes it back
//! out, so an upstream that reflects the attached key in its status line
//! (`HTTP/1.1 200 <key>`) must be cut like a reflection in a header or the
//! body: the key must never reach the sandbox.

use audit::{EventKind, Reason};
use conformance::m1::*;
use conformance::*;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A raw HTTPS upstream: reads one request head, records it, and answers
/// with the value of its `x-api-key` header as the reason phrase.
fn reflecting_upstream(ca: &TestCa, host: &str) -> (u16, Arc<Mutex<Vec<String>>>) {
    let std_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_l.set_nonblocking(true).unwrap();
    let port = std_l.local_addr().unwrap().port();
    let cfg = ca.ca.server_config(&netguard::canon_host(host.as_bytes()).unwrap()).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        rt.block_on(async move {
            let l = tokio::net::TcpListener::from_std(std_l).unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
            loop {
                let Ok((s, _)) = l.accept().await else { continue };
                let (acceptor, seen) = (acceptor.clone(), seen2.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(s).await else { return };
                    let mut head = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 64 << 10 {
                        match tls.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&head).into_owned();
                    seen.lock().unwrap().push(text.clone());
                    let key = text
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim().eq_ignore_ascii_case("x-api-key").then(|| v.trim().to_string())
                        })
                        .unwrap_or_else(|| "no-key".into());
                    let resp = format!("HTTP/1.1 200 {key}\r\ncontent-length: 3\r\nconnection: close\r\n\r\nok\n");
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
    });
    (port, seen)
}

#[test]
fn review_i1_key_reflected_in_reason_phrase_never_reaches_the_sandbox() {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let key = canary("sk-ant-api03");
    let (port, seen) = reflecting_upstream(&ca, "api.test");
    let grant = loopback_grant(
        "llm",
        "api.test",
        port,
        "methods = [\"GET\"]\npaths = [\"/status\"]\n\
         credential = { kind = \"static\", ref = \"file:llm-key\", header = \"x-api-key\", env = \"ANTHROPIC_API_KEY\" }",
    );
    let h = Harness::new(&format!("version = 1\n[tls]\nextra_roots = [\"{}\"]\n\n{grant}", ca.pem_path.display()));
    h.write_secret("llm-key", key.as_bytes());

    let r = h.sh(&format!("curl -sS -D - https://api.test:{port}/status; echo; echo EXIT=$?"));

    // Precondition: the upstream did receive the key (attached by the broker).
    assert!(
        seen.lock().unwrap().iter().any(|s| s.contains(&key)),
        "the broker attached the key upstream: {:?}",
        seen.lock().unwrap()
    );
    // I1: the reflection is cut; the key is not in anything the agent saw.
    assert!(
        !r.stdout.contains(&key) && !r.stderr.contains(&key),
        "the key reached the sandbox through the reason phrase: {r:?}"
    );
    let cut = h
        .events()
        .iter()
        .filter(|e| e.kind == EventKind::RequestOutcome && e.reason == Some(Reason::SecretReflected))
        .count();
    assert_eq!(cut, 1, "the reflection is logged as secret_reflected");
}
