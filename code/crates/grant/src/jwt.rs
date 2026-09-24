//! Compact JWS (RFC 7515) parsing, strictly: three base64url parts without
//! padding, a JSON-object header with a string `alg`, a JSON-object payload,
//! a bounded size. Verification is RS256 only; `none`, HMAC and anything
//! else are rejected before any key is looked at.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

/// Largest token accepted.
pub const MAX_TOKEN: usize = 16 << 10;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JwtError {
    #[error("the token is not a compact JWS")]
    Malformed,
    #[error("the token is larger than {MAX_TOKEN} bytes")]
    TooLarge,
    #[error("algorithm {0:?} is not accepted (RS256 only)")]
    Algorithm(String),
    #[error("the signature does not verify")]
    BadSignature,
}

#[derive(Clone, Debug)]
pub struct Jws {
    pub header: Map<String, Value>,
    pub claims: Map<String, Value>,
    signing_input: String,
    signature: Vec<u8>,
}

fn part(s: &str) -> Result<Vec<u8>, JwtError> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| JwtError::Malformed)
}

fn object(b: &[u8]) -> Result<Map<String, Value>, JwtError> {
    match serde_json::from_slice(b) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(JwtError::Malformed),
    }
}

pub fn parse(token: &str) -> Result<Jws, JwtError> {
    if token.len() > MAX_TOKEN {
        return Err(JwtError::TooLarge);
    }
    let mut it = token.split('.');
    let (Some(h), Some(c), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(JwtError::Malformed);
    };
    let header = object(&part(h)?)?;
    if !header.get("alg").is_some_and(|a| a.is_string()) {
        return Err(JwtError::Malformed);
    }
    Ok(Jws { header, claims: object(&part(c)?)?, signing_input: format!("{h}.{c}"), signature: part(s)? })
}

impl Jws {
    pub fn alg(&self) -> &str {
        self.header.get("alg").and_then(|a| a.as_str()).unwrap_or("")
    }

    pub fn kid(&self) -> Option<&str> {
        self.header.get("kid").and_then(|k| k.as_str())
    }

    /// RS256 with an RSA public key given as big-endian modulus and exponent.
    pub fn verify_rs256(&self, n: &[u8], e: &[u8]) -> Result<(), JwtError> {
        if self.alg() != "RS256" {
            return Err(JwtError::Algorithm(self.alg().to_string()));
        }
        ring::signature::RsaPublicKeyComponents { n, e }
            .verify(&ring::signature::RSA_PKCS1_2048_8192_SHA256, self.signing_input.as_bytes(), &self.signature)
            .map_err(|_| JwtError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rejects_what_is_not_a_compact_jws() {
        let enc = |s: &str| URL_SAFE_NO_PAD.encode(s);
        let ok = format!("{}.{}.{}", enc(r#"{"alg":"RS256"}"#), enc(r#"{"sub":"x"}"#), enc("sig"));
        assert!(parse(&ok).is_ok());
        for bad in [
            String::new(),
            "a.b".into(),
            format!("{ok}.extra"),
            format!("{}.{}.{}", enc(r#"["alg"]"#), enc("{}"), enc("s")),
            format!("{}.{}.{}", enc(r#"{"alg":1}"#), enc("{}"), enc("s")),
            format!("{}.{}.{}", enc(r#"{"alg":"RS256"}"#), enc("[]"), enc("s")),
            format!("{}=.{}.{}", enc(r#"{"alg":"RS256"}"#), enc("{}"), enc("s")),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
        assert_eq!(parse(&"a".repeat(MAX_TOKEN + 1)).unwrap_err(), JwtError::TooLarge);
        let none = parse(&format!("{}.{}.", enc(r#"{"alg":"none"}"#), enc("{}"))).unwrap();
        assert_eq!(none.verify_rs256(&[1], &[1]), Err(JwtError::Algorithm("none".into())));
    }

    proptest! {
        #[test]
        fn never_panics(s in "[A-Za-z0-9_.=-]{0,200}") {
            let _ = parse(&s).map(|j| j.verify_rs256(&[1, 2, 3], &[1, 0, 1]));
        }
    }
}
