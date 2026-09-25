//! M3 D2 (with a stand-in identity provider; the Okta and Entra runs need
//! their dev tenants): `broker login` runs the OIDC device flow (RFC 8628)
//! through the daemon; new sessions and every audit row carry the IdP
//! subject and groups; the ID token is refreshed (with rotation) as it
//! expires; no IdP token reaches the agent, the audit log or an upstream;
//! `required` refuses sessions without a login; a denied sign-in signs in
//! nobody.

use audit::EventKind;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use conformance::m1::*;
use conformance::*;
use ring::signature::RsaKeyPair;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

const CLIENT: &str = "broker-cli-test";
const SUB: &str = "00u1abcTEST";

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

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn sign(k: &RsaKeyPair, claims: Value) -> String {
    let enc = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
    let input = format!("{}.{}", enc(&json!({"alg": "RS256", "kid": "idp1", "typ": "JWT"})), enc(&claims));
    let mut sig = vec![0u8; k.public().modulus_len()];
    k.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), input.as_bytes(), &mut sig).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

fn form(body: &[u8]) -> std::collections::HashMap<String, String> {
    let dec = |s: &str| {
        let mut out = Vec::new();
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                out.push(if b[i] == b'+' { b' ' } else { b[i] });
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    };
    String::from_utf8_lossy(body).split('&').filter_map(|p| p.split_once('=')).map(|(k, v)| (dec(k), dec(v))).collect()
}

/// What the stand-in IdP saw and issued.
#[derive(Default)]
struct Idp {
    issuer: String,
    deny: bool,
    polls: u32,
    refreshes: Vec<String>,
    issued: Vec<String>,
}

fn handler(k: Arc<RsaKeyPair>, idp: Arc<Mutex<Idp>>) -> Handler {
    Arc::new(move |s: &Seen| {
        let mut st = idp.lock().unwrap();
        let iss = st.issuer.clone();
        let p = k.public();
        let comps: ring::rsa::PublicKeyComponents<Vec<u8>> = p.into();
        let id_token = |st: &mut Idp| {
            let t = sign(
                &k,
                json!({"iss": iss, "aud": CLIENT, "sub": SUB, "groups": ["eng", "sre"], "email": "dev@example.com",
                       "iat": now() - 5, "exp": now() + 30}),
            );
            st.issued.push(t.clone());
            t
        };
        match (s.method.as_str(), s.path.as_str()) {
            ("GET", "/.well-known/openid-configuration") => Reply::new(
                200,
                json!({"issuer": iss, "device_authorization_endpoint": format!("{iss}/device"),
                       "token_endpoint": format!("{iss}/token"), "jwks_uri": format!("{iss}/keys")})
                .to_string(),
            ),
            ("GET", "/keys") => Reply::new(
                200,
                json!({"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "idp1",
                                 "n": URL_SAFE_NO_PAD.encode(&comps.n), "e": URL_SAFE_NO_PAD.encode(&comps.e)}]})
                .to_string(),
            ),
            ("POST", "/device") => {
                let f = form(&s.body);
                assert_eq!(f.get("client_id").map(String::as_str), Some(CLIENT));
                Reply::new(
                    200,
                    json!({"device_code": "dc-CANARY-device-code", "user_code": "WDJB-MJHT",
                           "verification_uri": format!("{iss}/activate"), "expires_in": 600, "interval": 1})
                    .to_string(),
                )
            }
            ("POST", "/token") => {
                let f = form(&s.body);
                match f.get("grant_type").map(String::as_str) {
                    Some("urn:ietf:params:oauth:grant-type:device_code") => {
                        assert_eq!(f.get("device_code").map(String::as_str), Some("dc-CANARY-device-code"));
                        st.polls += 1;
                        if st.deny {
                            return Reply::new(400, r#"{"error":"access_denied"}"#);
                        }
                        if st.polls < 2 {
                            return Reply::new(400, r#"{"error":"authorization_pending"}"#);
                        }
                        let t = id_token(&mut st);
                        Reply::new(
                            200,
                            json!({"access_token": "at-CANARY-access", "token_type": "Bearer", "id_token": t,
                                   "refresh_token": "rt-CANARY-0", "expires_in": 30})
                            .to_string(),
                        )
                    }
                    Some("refresh_token") => {
                        let rt = f.get("refresh_token").cloned().unwrap_or_default();
                        let n = st.refreshes.len();
                        if rt != format!("rt-CANARY-{n}") {
                            return Reply::new(400, r#"{"error":"invalid_grant"}"#);
                        }
                        st.refreshes.push(rt);
                        let t = id_token(&mut st);
                        Reply::new(
                            200,
                            json!({"access_token": "at-CANARY-access", "id_token": t, "refresh_token": format!("rt-CANARY-{}", n + 1)})
                                .to_string(),
                        )
                    }
                    _ => Reply::new(400, r#"{"error":"unsupported_grant_type"}"#),
                }
            }
            _ => Reply::new(404, "{}"),
        }
    })
}

struct Fx {
    h: Harness,
    idp: Arc<Mutex<Idp>>,
    server: HttpsServer,
    _ca: tempfile::TempDir,
}

fn setup(required: bool, deny: bool) -> Fx {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let idp = Arc::new(Mutex::new(Idp { deny, ..Default::default() }));
    let server = HttpsServer::start(&ca, "idp.example.com", handler(Arc::new(key()), idp.clone()));
    let issuer = format!("https://idp.example.com:{}", server.port);
    idp.lock().unwrap().issuer = issuer.clone();
    let h = Harness::new(&format!(
        "version = 1\n[tls]\nextra_roots = [\"{}\"]\n[identity.login]\nissuer = \"{issuer}\"\nclient_id = \"{CLIENT}\"\n\
         scopes = [\"openid\", \"groups\", \"offline_access\"]\naddrs = [\"127.0.0.1\"]\nrequired = {required}\n",
        ca.pem_path.display()
    ));
    Fx { h, idp, server, _ca: ca_dir }
}

#[test]
fn d2_a_device_login_names_the_session_and_every_row_with_subject_and_groups() {
    let f = setup(false, false);
    let r = f.h.broker(&["login"]);
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.stdout.contains("enter the code WDJB-MJHT"), "{r:?}");
    assert!(r.stdout.contains(&format!("signed in as {SUB}")) && r.stdout.contains("groups eng, sre"), "{r:?}");
    assert!(f.idp.lock().unwrap().polls >= 2, "authorization_pending was honoured");
    let st = f.h.broker(&["login", "--status"]);
    assert!(st.stdout.contains(&format!("signed in as {SUB}")), "{st:?}");

    // Two sessions: each refreshes the 30-second ID token, with rotation.
    let n0 = f.h.events().len();
    let run = f.h.sh("env | grep -c CANARY; true");
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.stdout.trim(), "0", "no IdP token or code in the agent's environment");
    assert_eq!(f.h.sh("true").code, 0);
    assert_eq!(f.idp.lock().unwrap().refreshes, ["rt-CANARY-0", "rt-CANARY-1"], "refreshed with the rotated token");
    let evs: Vec<_> = f.h.events().into_iter().skip(n0).collect();
    let starts: Vec<_> = evs.iter().filter(|e| e.kind == EventKind::SessionStart).collect();
    assert_eq!(starts.len(), 2);
    for e in evs.iter().filter(|e| e.session.is_some()) {
        assert_eq!(e.enduser.as_deref(), Some(SUB), "{:?}", e.kind);
        assert_eq!(e.enduser_groups, ["eng", "sre"], "{:?}", e.kind);
    }
    assert_eq!(starts[0].detail["identity"]["issuer"], f.idp.lock().unwrap().issuer.as_str());

    // D7: no IdP token, code or refresh token in the audit log.
    let audit = String::from_utf8_lossy(&f.h.audit_bytes()).to_string();
    for t in f.idp.lock().unwrap().issued.iter() {
        assert!(!audit.contains(t.rsplit('.').next().unwrap()), "no ID token in the audit log");
    }
    for c in ["rt-CANARY", "at-CANARY", "dc-CANARY"] {
        assert!(!audit.contains(c), "{c} never logged");
    }

    // Logout: the next session is the local user again.
    assert_eq!(f.h.broker(&["logout"]).stdout.trim(), "signed out");
    let n1 = f.h.events().len();
    assert_eq!(f.h.sh("true").code, 0);
    let local = f.h.events().into_iter().skip(n1).find(|e| e.kind == EventKind::SessionStart).unwrap();
    assert!(local.enduser.as_deref().unwrap_or("").starts_with("local:"));
    assert!(local.enduser_groups.is_empty());
    drop(f.server);
}

#[test]
fn a_required_login_refuses_sessions_without_one_and_a_denied_sign_in_signs_in_nobody() {
    let f = setup(true, true);
    let r = f.h.sh("true");
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("run `broker login`"), "{r:?}");
    let l = f.h.broker(&["login"]);
    assert_eq!(l.code, 1, "{l:?}");
    assert!(l.stderr.contains("denied"), "{l:?}");
    assert!(f.h.broker(&["login", "--status"]).stdout.contains("not signed in"));
    assert_ne!(f.h.sh("true").code, 0, "still refused");
}
