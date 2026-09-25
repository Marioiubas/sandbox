//! M3 CI identity (D1 attribution, D2 for CI, D7): a runner-style OIDC
//! token attributes the session and every audit row; the token never
//! reaches the agent; a token that does not verify refuses the launch
//! instead of falling back to the local user.

use audit::EventKind;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use conformance::*;
use ring::signature::RsaKeyPair;
use serde_json::{Value, json};

const ISS: &str = "https://token.actions.githubusercontent.com";
const SUB: &str = "repo:acme/web:ref:refs/heads/main";

/// A throwaway RSA key for this test run only.
fn key() -> RsaKeyPair {
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::pem::PemObject;
    let out = std::process::Command::new("openssl").args(["genrsa", "2048"]).output().expect("openssl on PATH");
    assert!(out.status.success());
    match PrivateKeyDer::from_pem_slice(&out.stdout).unwrap() {
        PrivateKeyDer::Pkcs1(k) => RsaKeyPair::from_der(k.secret_pkcs1_der()).unwrap(),
        PrivateKeyDer::Pkcs8(k) => RsaKeyPair::from_pkcs8(k.secret_pkcs8_der()).unwrap(),
        _ => panic!("unexpected key format"),
    }
}

fn token(k: &RsaKeyPair, claims: Value) -> String {
    let enc = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
    let input = format!("{}.{}", enc(&json!({"alg": "RS256", "kid": "k1", "typ": "JWT"})), enc(&claims));
    let mut sig = vec![0u8; k.public().modulus_len()];
    k.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), input.as_bytes(), &mut sig).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn claims(aud: &str, exp: i64) -> Value {
    json!({"iss": ISS, "aud": aud, "sub": SUB, "repository": "acme/web", "ref": "refs/heads/main",
           "workflow": "ci", "run_id": "42", "iat": now() - 5, "nbf": now() - 5, "exp": exp})
}

fn setup(k: &RsaKeyPair, with_issuer: bool) -> Harness {
    let h = Harness::new("version = 1\n");
    let p: ring::rsa::PublicKeyComponents<Vec<u8>> = k.public().into();
    let jwks = json!({"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
                                "n": URL_SAFE_NO_PAD.encode(&p.n), "e": URL_SAFE_NO_PAD.encode(&p.e)}]});
    h.write_secret("gha-jwks.json", jwks.to_string().as_bytes());
    if with_issuer {
        h.set_config(&format!(
            "version = 1\n[[identity.oidc]]\nissuer = \"{ISS}\"\naudience = \"broker-test\"\njwks_file = \"gha-jwks.json\"\n"
        ));
    }
    h
}

fn run(h: &Harness, tok: &str) -> ProbeResult {
    let script = format!(
        "{} env-has BROKER_IDENTITY_TOKEN; echo \"has=$?\"; env | grep -c '{}' ; true",
        h.bins.probe.display(),
        &tok[..40.min(tok.len())]
    );
    h.run_argv(None, &["/bin/sh".into(), "-c".into(), script], &[("BROKER_IDENTITY_TOKEN", tok)])
}

#[test]
fn a_runner_token_attributes_the_session_and_never_reaches_the_agent() {
    let k = key();
    let h = setup(&k, true);
    let tok = token(&k, claims("broker-test", now() + 300));
    let n0 = h.events().len();
    let r = run(&h, &tok);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.stdout.contains("has=10"), "the token is not in the agent's environment: {r:?}");
    assert!(r.stdout.lines().any(|l| l.trim() == "0"), "no copy of the token in the environment: {r:?}");
    let evs: Vec<_> = h.events().into_iter().skip(n0).collect();
    let start = evs.iter().find(|e| e.kind == EventKind::SessionStart).unwrap();
    assert_eq!(start.enduser.as_deref(), Some(SUB));
    assert_eq!(start.detail["identity"]["issuer"], ISS);
    assert_eq!(start.detail["identity"]["claims"]["run_id"], "42");
    assert!(evs.iter().filter(|e| e.session.is_some()).all(|e| e.enduser.as_deref() == Some(SUB)), "every row");
    let audit = std::fs::read(h.home.path().join("state/audit.db")).unwrap();
    let sig = tok.rsplit('.').next().unwrap();
    assert!(!audit.windows(sig.len()).any(|w| w == sig.as_bytes()), "the token is not logged");

    // Without a token the session is the local user.
    let n1 = h.events().len();
    assert_eq!(h.sh("true").code, 0);
    let local = h.events().into_iter().skip(n1).find(|e| e.kind == EventKind::SessionStart).unwrap();
    assert!(local.enduser.as_deref().unwrap_or("").starts_with("local:"));
}

#[test]
fn a_token_that_does_not_verify_refuses_the_launch() {
    let k = key();
    let h = setup(&k, true);
    for (tok, why) in [
        (token(&k, claims("someone-else", now() + 300)), "audience"),
        (token(&k, claims("broker-test", now() - 600)), "expired"),
        (token(&key(), claims("broker-test", now() + 300)), "signature"),
        ("not-a-token".to_string(), "compact JWS"),
    ] {
        let r = run(&h, &tok);
        assert_ne!(r.code, 0, "{why}: {r:?}");
        assert!(r.stderr.contains("identity token rejected"), "{why}: {r:?}");
    }
    // A token with no configured issuer is refused, not ignored.
    let h2 = setup(&k, false);
    let r = run(&h2, &token(&k, claims("broker-test", now() + 300)));
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("no [[identity.oidc]] issuer is configured"), "{r:?}");
}

#[test]
fn d7_the_identity_token_never_reaches_an_upstream() {
    // The agent calls a granted API with a brokered credential while the
    // session carries a verified identity token: the upstream sees the
    // broker's credential and nothing of the token.
    use conformance::m1::*;
    let k = key();
    let h = setup(&k, true);
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let api = HttpsServer::start(&ca, "api.example.com", std::sync::Arc::new(|_: &Seen| Reply::new(200, "{}")));
    h.write_secret("api-key", b"api-CANARY-not-a-real-key");
    let cfg = std::fs::read_to_string(h.config_dir().join("broker.toml")).unwrap();
    h.set_config(&format!(
        "{cfg}[tls]\nextra_roots = [\"{}\"]\n{}",
        ca.pem_path.display(),
        loopback_grant(
            "api",
            "api.example.com",
            api.port,
            "credential = { kind = \"static\", ref = \"file:api-key\", env = \"API_KEY\" }"
        )
    ));
    let tok = token(&k, claims("broker-test", now() + 300));
    let script = format!(
        "curl -sS -o /dev/null -w '%{{http_code}}' -H \"Authorization: Bearer $API_KEY\" -d x https://api.example.com:{}/v1/x",
        api.port
    );
    let r = h.run_argv(None, &["/bin/sh".into(), "-c".into(), script], &[("BROKER_IDENTITY_TOKEN", &tok)]);
    assert_eq!(r.stdout.trim(), "200", "{r:?}");
    let seen = api.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].header("authorization"), Some("Bearer api-CANARY-not-a-real-key"));
    let everything = format!("{:?}{}", seen[0].headers, String::from_utf8_lossy(&seen[0].body));
    for part in tok.split('.') {
        assert!(!everything.contains(part), "no part of the identity token reaches the upstream");
    }
}
