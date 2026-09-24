use super::*;
use std::sync::Mutex;

/// A throwaway RSA key generated for this test run only.
pub(crate) fn test_key_pem() -> Secret {
    let out = std::process::Command::new("openssl").args(["genrsa", "2048"]).output().expect("openssl on PATH");
    assert!(out.status.success(), "openssl genrsa failed");
    Secret::new(out.stdout)
}

fn perms(p: &[(&str, &str)]) -> BTreeMap<String, String> {
    p.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn repos() -> Vec<RepoId> {
    vec![RepoId::parse("github.com/acme/web").unwrap()]
}

#[test]
fn jwt_is_rs256_and_verifies() {
    let key = load_rsa_key(&test_key_pem()).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let jwt = app_jwt("12345", &key, now).unwrap();
    let text = std::str::from_utf8(jwt.expose()).unwrap().to_string();
    let parts: Vec<&str> = text.split('.').collect();
    assert_eq!(parts.len(), 3);
    let dec = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap();
    let hdr: serde_json::Value = serde_json::from_slice(&dec(parts[0])).unwrap();
    assert_eq!(hdr["alg"], "RS256");
    let claims: serde_json::Value = serde_json::from_slice(&dec(parts[1])).unwrap();
    assert_eq!(claims["iss"], 12345, "numeric app IDs are sent as numbers");
    assert_eq!(claims["iat"], 1_800_000_000u64 - 60);
    assert_eq!(claims["exp"], 1_800_000_000u64 + 540);
    use ring::signature::KeyPair;
    let pk = ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        key.public_key().as_ref(),
    );
    pk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &dec(parts[2])).expect("signature verifies");
    let jwt2 = app_jwt("Iv1.abc", &key, now).unwrap();
    let c2: serde_json::Value =
        serde_json::from_slice(&dec(std::str::from_utf8(jwt2.expose()).unwrap().split('.').nth(1).unwrap())).unwrap();
    assert_eq!(c2["iss"], "Iv1.abc");
}

#[test]
fn key_formats() {
    assert!(load_rsa_key(&Secret::new(b"garbage".to_vec())).is_err());
    // A syntactically framed but empty key (header built at runtime so no
    // key-shaped literal lives in the repository).
    let fake = format!("-----BEGIN {k}-----\nAAAA\n-----END {k}-----\n", k = "PRIVATE KEY");
    let e = load_rsa_key(&Secret::new(fake.into_bytes()));
    assert!(e.is_err());
}

#[test]
fn body_always_names_repositories_and_permissions() {
    let b = request_body(&perms(&[("contents", "write")]), &repos()).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["repositories"], serde_json::json!(["web"]));
    assert_eq!(v["permissions"], serde_json::json!({"contents": "write"}));
    assert!(request_body(&perms(&[]), &repos()).is_err());
    assert!(request_body(&perms(&[("contents", "write")]), &[]).is_err());
}

#[test]
fn responses_beyond_the_request_are_refused() {
    let p = perms(&[("contents", "write")]);
    let ok = br#"{"token":"ghs_CANARYTOKEN","expires_at":"2026-09-24T12:00:00Z","permissions":{"contents":"write","metadata":"read"},"repository_selection":"selected","repositories":[{"name":"web"}]}"#;
    let (tok, exp) = verify_response(201, ok, &p, &repos()).unwrap();
    assert_eq!(tok.expose(), b"ghs_CANARYTOKEN");
    assert_eq!(exp.duration_since(UNIX_EPOCH).unwrap().as_secs(), 1_790_251_200);
    let lower = br#"{"token":"t","expires_at":"2026-09-24T12:00:00Z","permissions":{"contents":"read"}}"#;
    assert!(verify_response(201, lower, &p, &repos()).is_ok(), "narrower than requested is fine");
    for bad in [
        &br#"{"token":"t","expires_at":"2026-09-24T12:00:00Z","permissions":{"contents":"admin"}}"#[..],
        br#"{"token":"t","expires_at":"2026-09-24T12:00:00Z","permissions":{"contents":"write","issues":"write"}}"#,
        br#"{"token":"t","expires_at":"2026-09-24T12:00:00Z","permissions":{"contents":"write"},"repository_selection":"all"}"#,
        br#"{"token":"t","expires_at":"2026-09-24T12:00:00Z","permissions":{"contents":"write"},"repositories":[{"name":"other"}]}"#,
        br#"{"token":"t","expires_at":"2026-09-24T12:00:00Z"}"#,
        br#"{"token":"","expires_at":"2026-09-24T12:00:00Z","permissions":{}}"#,
        br#"{"token":"t","permissions":{}}"#,
        br#"{"token":"t\nx","expires_at":"2026-09-24T12:00:00Z","permissions":{}}"#,
        b"not json",
    ] {
        let e = verify_response(201, bad, &p, &repos());
        assert!(e.is_err(), "{}", String::from_utf8_lossy(bad));
    }
    assert!(verify_response(401, ok, &p, &repos()).is_err());
    let msg = verify_response(422, b"{\"message\":\"CANARY\"}", &p, &repos()).unwrap_err().to_string();
    assert!(!msg.contains("CANARY"), "upstream bodies are not echoed");
}

struct FakeTransport {
    calls: Mutex<Vec<(String, String, Vec<u8>)>>,
}

#[async_trait::async_trait]
impl Transport for FakeTransport {
    async fn post_json(
        &self,
        api: &ApiEndpoint,
        path: &str,
        bearer: &Secret,
        body: Vec<u8>,
    ) -> anyhow::Result<(u16, Vec<u8>)> {
        assert!(bearer.expose().starts_with(b"eyJ"), "a JWT");
        self.calls.lock().unwrap().push((api.authority(), path.to_string(), body));
        Ok((
            201,
            br#"{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z","permissions":{"contents":"write"}}"#.to_vec(),
        ))
    }
}

#[tokio::test]
async fn mint_posts_scoped_request() {
    let spec = GitHubAppIssuerSpec {
        app_id: "1".into(),
        installation_id: "42".into(),
        private_key: "env:UNUSED".into(),
        api_base: None,
        api_addrs: vec![],
    };
    let app = GitHubApp::from_spec("acme", &spec).unwrap();
    let key = load_rsa_key(&test_key_pem()).unwrap();
    let t = FakeTransport { calls: Mutex::new(vec![]) };
    let (tok, _) = mint(&app, &key, &t, &perms(&[("contents", "write")]), &repos()).await.unwrap();
    assert_eq!(tok.expose(), b"ghs_x");
    let calls = t.calls.lock().unwrap().clone();
    assert_eq!(calls[0].0, "api.github.com");
    assert_eq!(calls[0].1, "/app/installations/42/access_tokens");
    let v: serde_json::Value = serde_json::from_slice(&calls[0].2).unwrap();
    assert!(v.get("repositories").is_some() && v.get("permissions").is_some());
    let other = vec![RepoId::parse("gitlab.com/acme/web").unwrap()];
    assert!(mint(&app, &key, &t, &perms(&[("contents", "write")]), &other).await.is_err());
    let bad = GitHubAppIssuerSpec { installation_id: "4x".into(), ..spec.clone() };
    assert!(GitHubApp::from_spec("acme", &bad).is_err());
    assert!(!format!("{app:?}").contains("BEGIN"));
}
