//! In-process tests of the L4 pipeline: every decision path, both ingress
//! modes, the public bypass corpus, and the ordering guarantees (no DNS for
//! names that are not admitted; no upstream connection when audit fails).

use audit::{AuditEvent, ChainHash, DecisionResult, EventKind, Reason, Recorder, SessionId};
use brokerd::pipeline::{Outcome, PipelineCtx, Stats, handle};
use netguard::ingress::ChannelAuth;
use netguard::resolver::StaticResolver;
use policy::EgressPolicy;
use policy::config::EgressEntry;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;

#[derive(Default)]
struct MemRecorder {
    events: Mutex<Vec<AuditEvent>>,
}

impl Recorder for MemRecorder {
    fn append(&self, ev: &AuditEvent) -> anyhow::Result<ChainHash> {
        self.events.lock().unwrap().push(ev.clone());
        Ok(ChainHash([0; 32]))
    }
}

impl MemRecorder {
    fn denies(&self) -> Vec<Reason> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(&e.decision, Some(d) if d.result == DecisionResult::Deny))
            .map(|e| e.reason.expect("every deny carries a reason"))
            .collect()
    }
}

/// A TLS-ish upstream: reads the ClientHello, answers `UPSTREAM-OK`, counts accepts.
async fn upstream() -> (u16, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let (a, b) = (accepts.clone(), bytes.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            a.fetch_add(1, Ordering::SeqCst);
            let b = b.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                if let Ok(n) = s.read(&mut buf).await {
                    b.fetch_add(n, Ordering::SeqCst);
                    if n > 0 {
                        let _ = s.write_all(b"UPSTREAM-OK").await;
                    }
                }
            });
        }
    });
    (port, accepts, bytes)
}

struct Fx {
    ctx: Arc<PipelineCtx>,
    rec: Arc<MemRecorder>,
    resolver: Arc<StaticResolver>,
}

fn fx(
    entries: Vec<EgressEntry>,
    table: Vec<(&str, Vec<&str>)>,
    auth: ChannelAuth,
    recorder: Option<Arc<dyn Recorder>>,
) -> Fx {
    let policy = EgressPolicy::compile([("test", entries.as_slice())]).unwrap();
    let resolver = Arc::new(StaticResolver::new(
        table.into_iter().map(|(n, a)| (n.to_string(), a.into_iter().map(|x| x.parse::<IpAddr>().unwrap()).collect())),
    ));
    let rec = Arc::new(MemRecorder::default());
    let ctx = Arc::new(PipelineCtx {
        session: SessionId::new(),
        enduser: "local:test".into(),
        agent: "probe".into(),
        sandbox: "test".into(),
        policy: Arc::new(policy),
        resolver: resolver.clone(),
        recorder: recorder.unwrap_or_else(|| rec.clone()),
        auth,
        stats: Arc::new(Stats::default()),
        connect_timeout: Duration::from_secs(2),
        sni_timeout: Duration::from_secs(2),
    });
    Fx { ctx, rec, resolver }
}

fn grant(host: &str, port: u16, addrs: &[&str], classes: &[&str]) -> EgressEntry {
    EgressEntry {
        host: host.into(),
        ports: Some(vec![port]),
        addrs: addrs.iter().map(|s| s.to_string()).collect(),
        allow_addr_classes: classes.iter().map(|s| s.to_string()).collect(),
        id: None,
    }
}

fn connect_req(host: &[u8], port: u16, extra: &str) -> Vec<u8> {
    let mut v = b"CONNECT ".to_vec();
    v.extend_from_slice(host);
    v.extend_from_slice(format!(":{port} HTTP/1.1\r\n{extra}\r\n").as_bytes());
    v
}

fn socks_req(host: &[u8], port: u16) -> Vec<u8> {
    let mut v = vec![5, 1, 0, 5, 1, 0, 3, host.len() as u8];
    v.extend_from_slice(host);
    v.extend_from_slice(&port.to_be_bytes());
    v
}

async fn run(ctx: Arc<PipelineCtx>, input: Vec<u8>, after_ok: Option<Vec<u8>>) -> (Outcome, Vec<u8>) {
    let (mut client, server): (DuplexStream, DuplexStream) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move { handle(&ctx, server).await });
    client.write_all(&input).await.unwrap();
    let mut got = Vec::new();
    if let Some(hello) = after_ok {
        // Wait for the tunnel reply, then send the ClientHello.
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf)).await.unwrap().unwrap();
        got.extend_from_slice(&buf[..n]);
        client.write_all(&hello).await.unwrap();
    }
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buf = [0u8; 4096];
        loop {
            match client.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    got.extend_from_slice(&buf[..n]);
                    if got.ends_with(b"UPSTREAM-OK") {
                        drop(client);
                        break;
                    }
                }
            }
        }
        task.await.unwrap()
    })
    .await
    .expect("pipeline finished");
    (outcome, got)
}

fn reason(o: &Outcome) -> Option<Reason> {
    match o {
        Outcome::Denied { reason, .. } => Some(*reason),
        _ => None,
    }
}

#[tokio::test]
async fn allowed_connect_splices_and_logs_allow_then_outcome() {
    let (port, accepts, _) = upstream().await;
    let f = fx(vec![grant("allowed.test", port, &["127.0.0.1"], &["loopback"])], vec![], ChannelAuth::Implicit, None);
    let hello = tls::sni_peek::synthetic_client_hello(Some(b"allowed.test"));
    let (o, got) = run(f.ctx.clone(), connect_req(b"allowed.test", port, ""), Some(hello)).await;
    assert!(matches!(o, Outcome::Spliced { .. }), "{o:?}");
    assert!(got.starts_with(b"HTTP/1.1 200"));
    assert!(got.ends_with(b"UPSTREAM-OK"));
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    let kinds: Vec<EventKind> = f.rec.events.lock().unwrap().iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EventKind::RequestDecision, EventKind::RequestOutcome]);
    assert_eq!(f.resolver.query_count(), 0, "pinned addresses: no DNS");
}

#[tokio::test]
async fn socks5_allowed_path() {
    let (port, _, _) = upstream().await;
    let f = fx(vec![grant("allowed.test", port, &["127.0.0.1"], &["loopback"])], vec![], ChannelAuth::Implicit, None);
    let hello = tls::sni_peek::synthetic_client_hello(Some(b"ALLOWED.test"));
    let (o, got) = run(f.ctx.clone(), socks_req(b"allowed.test", port), Some(hello)).await;
    assert!(matches!(o, Outcome::Spliced { .. }), "{o:?}");
    assert!(got.ends_with(b"UPSTREAM-OK"));
}

#[tokio::test]
async fn sni_mismatch_and_non_tls_are_cut_before_any_upstream_byte() {
    let (port, _, bytes) = upstream().await;
    let f = fx(vec![grant("allowed.test", port, &["127.0.0.1"], &["loopback"])], vec![], ChannelAuth::Implicit, None);
    let fronted = tls::sni_peek::synthetic_client_hello(Some(b"evil.example"));
    let (o, _) = run(f.ctx.clone(), connect_req(b"allowed.test", port, ""), Some(fronted)).await;
    assert_eq!(reason(&o), Some(Reason::ConnectSniMismatch));
    let (o, _) =
        run(f.ctx.clone(), connect_req(b"allowed.test", port, ""), Some(b"SSH-2.0-OpenSSH_9.6\r\n".to_vec())).await;
    assert_eq!(reason(&o), Some(Reason::SniLess));
    // Nested SOCKS inside an allowed tunnel is not TLS either.
    let (o, _) = run(f.ctx.clone(), connect_req(b"allowed.test", port, ""), Some(vec![5, 1, 0])).await;
    assert_eq!(reason(&o), Some(Reason::SniLess));
    let no_sni = tls::sni_peek::synthetic_client_hello(None);
    let (o, _) = run(f.ctx.clone(), connect_req(b"allowed.test", port, ""), Some(no_sni)).await;
    assert_eq!(reason(&o), Some(Reason::SniLess));
    assert_eq!(bytes.load(Ordering::SeqCst), 0, "nothing reached the upstream");
}

#[tokio::test]
async fn names_not_admitted_are_never_resolved() {
    let f = fx(
        vec![grant("allowed.test", 443, &[], &[])],
        vec![("allowed.test", vec!["93.184.215.14"])],
        ChannelAuth::Implicit,
        None,
    );
    for h in ["evil.example", "c2VjcmV0.exfil.attacker.example", "allowed.test.evil.example", "dns.google"] {
        let (o, got) = run(f.ctx.clone(), connect_req(h.as_bytes(), 443, ""), None).await;
        assert!(reason(&o).is_some(), "{h}");
        assert!(got.starts_with(b"HTTP/1.1 403"), "{h}: {}", String::from_utf8_lossy(&got));
        assert!(String::from_utf8_lossy(&got).contains("X-Broker-Request-Id: req-"));
    }
    assert_eq!(f.resolver.query_count(), 0, "the query name is the exfiltration channel");
}

#[tokio::test]
async fn resolved_address_is_checked_after_the_name() {
    let f = fx(
        vec![
            grant("meta.test", 443, &[], &[]),
            grant("rebind.test", 443, &[], &[]),
            grant("private.test", 443, &[], &[]),
        ],
        vec![
            ("meta.test", vec!["169.254.169.254"]),
            ("rebind.test", vec!["93.184.215.14", "10.0.0.7"]),
            ("private.test", vec!["192.168.1.10"]),
        ],
        ChannelAuth::Implicit,
        None,
    );
    let (o, _) = run(f.ctx.clone(), connect_req(b"meta.test", 443, ""), None).await;
    assert_eq!(reason(&o), Some(Reason::MetadataAddr));
    let (o, _) = run(f.ctx.clone(), socks_req(b"rebind.test", 443), None).await;
    assert_eq!(reason(&o), Some(Reason::PrivateAddr));
    let (o, _) = run(f.ctx.clone(), connect_req(b"private.test", 443, ""), None).await;
    assert_eq!(reason(&o), Some(Reason::PrivateAddr));
    assert_eq!(f.resolver.query_count(), 3);
}

#[tokio::test]
async fn port_and_protocol_denials() {
    let f = fx(vec![grant("github.com", 443, &["140.82.112.3"], &[])], vec![], ChannelAuth::Implicit, None);
    let (o, _) = run(f.ctx.clone(), connect_req(b"github.com", 22, ""), None).await;
    assert_eq!(reason(&o), Some(Reason::PortNotAllowed), "SSH is not granted");
    let (o, _) =
        run(f.ctx.clone(), b"GET http://github.com/ HTTP/1.1\r\nHost: github.com\r\n\r\n".to_vec(), None).await;
    assert_eq!(reason(&o), Some(Reason::PlainHttpUnsupported));
    let (o, _) = run(f.ctx.clone(), vec![4, 1, 1, 187, 0, 0, 0, 1, b'x', 0, b'g', b'h', 0], None).await;
    assert_eq!(reason(&o), Some(Reason::Socks4Refused));
    let (o, _) = run(f.ctx.clone(), vec![5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0], None).await;
    assert_eq!(reason(&o), Some(Reason::SocksCommandUnsupported), "UDP ASSOCIATE");
    let (o, _) = run(f.ctx.clone(), vec![0x16, 3, 1, 0, 5], None).await;
    assert_eq!(reason(&o), Some(Reason::ProtocolUnsupported), "raw TLS without a proxy request");
}

#[tokio::test]
async fn audit_failure_denies_before_connecting() {
    let (port, accepts, _) = upstream().await;
    let failing: Arc<dyn Recorder> = Arc::new(audit::FailingRecorder);
    let f = fx(
        vec![grant("allowed.test", port, &["127.0.0.1"], &["loopback"])],
        vec![],
        ChannelAuth::Implicit,
        Some(failing),
    );
    let (o, got) = run(f.ctx.clone(), connect_req(b"allowed.test", port, ""), None).await;
    assert_eq!(reason(&o), Some(Reason::AuditUnavailable));
    assert!(got.starts_with(b"HTTP/1.1 503"));
    assert_eq!(accepts.load(Ordering::SeqCst), 0, "write-ahead: no upstream connection without a durable record");
}

#[tokio::test]
async fn loopback_channel_requires_the_session_sentinel() {
    let (port, _, _) = upstream().await;
    let sentinel = b"bks1_0123".to_vec();
    let f = fx(
        vec![grant("allowed.test", port, &["127.0.0.1"], &["loopback"])],
        vec![],
        ChannelAuth::Sentinel(sentinel),
        None,
    );
    let (o, got) = run(f.ctx.clone(), connect_req(b"allowed.test", port, ""), None).await;
    assert_eq!(reason(&o), Some(Reason::ProxyAuthRequired));
    assert!(got.starts_with(b"HTTP/1.1 407"));
    let bad = "Proxy-Authorization: Basic YnJva2VyOmJrczFfOTk5OQ==\r\n"; // broker:bks1_9999
    let (o, _) = run(f.ctx.clone(), connect_req(b"allowed.test", port, bad), None).await;
    assert_eq!(reason(&o), Some(Reason::BadSentinel));
    let good = "Proxy-Authorization: Basic YnJva2VyOmJrczFfMDEyMw==\r\n"; // broker:bks1_0123
    let hello = tls::sni_peek::synthetic_client_hello(Some(b"allowed.test"));
    let (o, _) = run(f.ctx.clone(), connect_req(b"allowed.test", port, good), Some(hello)).await;
    assert!(matches!(o, Outcome::Spliced { .. }), "{o:?}");
}

// ---- public bypass corpus through every ingress mode -----------------------

#[derive(serde::Deserialize)]
struct Corpus {
    case: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    input: Option<String>,
    input_hex: Option<String>,
    reason: Reason,
    #[serde(default)]
    via: Vec<String>,
}

fn corpus() -> Vec<(String, Vec<u8>, Reason, Vec<String>)> {
    let c: Corpus = toml::from_str(include_str!("../../../tests/bypass-corpus/hosts.toml")).unwrap();
    c.case
        .into_iter()
        .map(|k| {
            let bytes = match (k.input, k.input_hex) {
                (Some(s), None) => s.into_bytes(),
                (None, Some(h)) => hex::decode(h).unwrap(),
                _ => panic!("{}: exactly one of input / input_hex", k.id),
            };
            (k.id, bytes, k.reason, k.via)
        })
        .collect()
}

#[tokio::test]
async fn bypass_corpus_denied_with_reason_through_every_ingress_mode() {
    // Grants that the corpus tries to smuggle past: github, google suffixes, DoH.
    let f = fx(
        vec![
            grant("api.github.com", 443, &["140.82.112.5"], &[]),
            grant("*.google.com", 443, &["142.250.1.1"], &[]),
            grant("dns.google", 443, &["8.8.8.8"], &[]),
            grant("*.cloudflare-dns.com", 443, &["1.1.1.1"], &[]),
        ],
        vec![],
        ChannelAuth::Implicit,
        None,
    );
    let cases = corpus();
    assert!(cases.len() >= 30);
    let mut ran = 0;
    for (id, bytes, want, via) in &cases {
        for mode in ["connect", "socks5"] {
            if !via.is_empty() && !via.iter().any(|v| v == mode) {
                continue;
            }
            let input = if mode == "connect" { connect_req(bytes, 443, "") } else { socks_req(bytes, 443) };
            let (o, _) = run(f.ctx.clone(), input, None).await;
            assert_eq!(reason(&o), Some(*want), "corpus case {id} via {mode}");
            ran += 1;
        }
    }
    let denies = f.rec.denies();
    assert_eq!(denies.len(), ran, "every deny logged exactly once, with a reason");
    assert_eq!(f.resolver.query_count(), 0);
}

#[test]
fn corpus_matches_the_canonicaliser() {
    // The same corpus at the canonicaliser level: rejects map to the same reason.
    for (id, bytes, want, _) in corpus() {
        match netguard::canon_host(&bytes) {
            Err(r) => assert_eq!(r.reason(), want, "{id}"),
            Ok(h) => assert!(
                matches!(want, Reason::IpLiteral | Reason::DohEndpoint | Reason::HostNotAllowed),
                "{id}: accepted as {h:?} but corpus expects {want:?}"
            ),
        }
    }
}

// ---- same bytes, same decision, whatever the ingress mode ------------------

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]
    #[test]
    fn connect_and_socks5_agree(host in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..40)) {
        // Bytes that CONNECT framing itself cannot carry are out of scope here.
        proptest::prop_assume!(!host.iter().any(|b| matches!(b, b' ' | b'\r' | b'\n')));
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let f = fx(vec![grant("allowed.test", 443, &["140.82.112.5"], &[])], vec![], ChannelAuth::Implicit, None);
            let (a, _) = run(f.ctx.clone(), connect_req(&host, 443, ""), None).await;
            let (b, _) = run(f.ctx.clone(), socks_req(&host, 443), None).await;
            let (ra, rb) = (reason(&a), reason(&b));
            // CONNECT may fail framing on bytes SOCKS can carry (e.g. a bare ':' split).
            if ra != Some(Reason::MalformedRequest) {
                assert_eq!(ra, rb, "host bytes {:?}", host);
            }
        });
    }
}
