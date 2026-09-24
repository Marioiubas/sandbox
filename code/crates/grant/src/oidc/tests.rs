use super::*;
use ring::signature::RsaKeyPair;
use serde_json::json;

/// A throwaway RSA key for this test run only (as the M1 issuer tests).
fn key() -> RsaKeyPair {
    use rustls_pki_types::PrivateKeyDer;
    use rustls_pki_types::pem::PemObject;
    let out = std::process::Command::new("openssl").args(["genrsa", "2048"]).output().expect("openssl on PATH");
    assert!(out.status.success());
    match PrivateKeyDer::from_pem_slice(&out.stdout).unwrap() {
        PrivateKeyDer::Pkcs1(k) => RsaKeyPair::from_der(k.secret_pkcs1_der()).unwrap(),
        PrivateKeyDer::Pkcs8(k) => RsaKeyPair::from_pkcs8(k.secret_pkcs8_der()).unwrap(),
        _ => panic!("unexpected key format"),
    }
}

fn sign(k: &RsaKeyPair, header: Value, claims: Value) -> String {
    let enc = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
    let input = format!("{}.{}", enc(&header), enc(&claims));
    let mut sig = vec![0u8; k.public().modulus_len()];
    k.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), input.as_bytes(), &mut sig).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

fn jwks(k: &RsaKeyPair, kid: &str) -> Jwks {
    let p: ring::rsa::PublicKeyComponents<Vec<u8>> = k.public().into();
    let doc = json!({"keys": [
        {"kty": "EC", "kid": "ignored"},
        {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
         "n": URL_SAFE_NO_PAD.encode(&p.n), "e": URL_SAFE_NO_PAD.encode(&p.e)},
    ]});
    Jwks::parse(doc.to_string().as_bytes()).unwrap()
}

const ISS: &str = "https://token.actions.githubusercontent.com";

#[test]
fn a_runner_token_verifies_and_everything_else_is_refused() {
    let k = key();
    let set = jwks(&k, "k1");
    assert_eq!(set.keys.len(), 1, "only RSA signature keys are kept");
    let trusted = [IssuerConfig { issuer: ISS.into(), audience: "broker".into() }];
    let now = 1_800_000_000i64;
    let claims = json!({"iss": ISS, "aud": "broker", "sub": "repo:acme/web:ref:refs/heads/main",
                        "repository": "acme/web", "exp": now + 300, "iat": now - 10, "nbf": now - 10});
    let hdr = json!({"alg": "RS256", "kid": "k1", "typ": "JWT"});
    let tok = sign(&k, hdr.clone(), claims.clone());
    let id = verify(&tok, &trusted, &set, now).unwrap();
    assert_eq!(id.subject, "repo:acme/web:ref:refs/heads/main");
    assert_eq!(id.claims["repository"], "acme/web");
    assert_eq!(claimed_issuer(&tok).unwrap(), ISS);

    let with = |f: &dyn Fn(&mut Value)| {
        let mut c = claims.clone();
        f(&mut c);
        sign(&k, hdr.clone(), c)
    };
    assert_eq!(verify(&tok, &trusted, &set, now + 400).unwrap_err(), OidcError::Time);
    assert_eq!(
        verify(&with(&|c| c["iss"] = json!("https://evil.example")), &trusted, &set, now).unwrap_err(),
        OidcError::UntrustedIssuer("https://evil.example".into())
    );
    assert_eq!(
        verify(&with(&|c| c["aud"] = json!("someone-else")), &trusted, &set, now).unwrap_err(),
        OidcError::Audience("broker".into())
    );
    assert!(verify(&with(&|c| c["aud"] = json!(["x", "broker"])), &trusted, &set, now).is_ok());
    assert_eq!(verify(&with(&|c| c["nbf"] = json!(now + 600)), &trusted, &set, now).unwrap_err(), OidcError::Time);
    assert_eq!(verify(&with(&|c| c["sub"] = json!("")), &trusted, &set, now).unwrap_err(), OidcError::Subject);
    // Unknown key, another key's signature, algorithm confusion, tampering.
    let other = sign(&k, json!({"alg": "RS256", "kid": "k2"}), claims.clone());
    assert_eq!(verify(&other, &trusted, &set, now).unwrap_err(), OidcError::UnknownKey);
    let foreign = sign(&key(), hdr.clone(), claims.clone());
    assert_eq!(verify(&foreign, &trusted, &set, now).unwrap_err(), OidcError::Jwt(JwtError::BadSignature));
    let hs = sign(&k, json!({"alg": "HS256", "kid": "k1"}), claims.clone());
    assert!(matches!(verify(&hs, &trusted, &set, now), Err(OidcError::Jwt(JwtError::Algorithm(_)))));
    let mut parts: Vec<String> = tok.split('.').map(str::to_string).collect();
    parts[1] = URL_SAFE_NO_PAD.encode(claims.to_string().replace("acme/web", "evil/web"));
    assert_eq!(verify(&parts.join("."), &trusted, &set, now).unwrap_err(), OidcError::Jwt(JwtError::BadSignature));
}
