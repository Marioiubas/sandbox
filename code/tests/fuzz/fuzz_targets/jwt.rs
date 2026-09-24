//! Identity tokens and key sets: arbitrary input never panics; a token that
//! parses carries a string `alg`; a non-RS256 token never verifies.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = grant::oidc::Jwks::parse(data);
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = grant::oidc::claimed_issuer(s);
    if let Ok(j) = grant::jwt::parse(s) {
        let _ = j.kid();
        let v = j.verify_rs256(&[0xc3; 256], &[1, 0, 1]);
        if j.alg() != "RS256" {
            assert!(v.is_err());
        }
    }
});
