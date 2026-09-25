//! AWS Signature Version 4 (IAM User Guide, "Create a signed AWS API
//! request"): canonical request, string to sign, signing key, signature.
//! The broker signs its own STS calls with the base credentials and
//! re-signs authorized S3 requests with minted session credentials; the
//! client's signature (made with a sentinel) never leaves the broker.

use ring::hmac;
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use zeroize::Zeroizing;

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

pub fn hex_sha256(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// `(YYYYMMDD, YYYYMMDDTHHMMSSZ)` in UTC.
pub fn amz_dates(t: SystemTime) -> (String, String) {
    let dt = time::OffsetDateTime::from(t);
    let d = format!("{:04}{:02}{:02}", dt.year(), u8::from(dt.month()), dt.day());
    let full = format!("{d}T{:02}{:02}{:02}Z", dt.hour(), dt.minute(), dt.second());
    (d, full)
}

/// A header value in canonical form: trimmed, runs of spaces collapsed.
/// `None` for values that are not visible ASCII (nothing to sign safely).
pub fn canonical_value(v: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(v).ok()?;
    if !s.bytes().all(|b| b == b' ' || b == b'\t' || b.is_ascii_graphic()) {
        return None;
    }
    Some(s.split([' ', '\t']).filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" "))
}

/// What a signature is scoped to.
pub struct Scope<'a> {
    pub access_key_id: &'a str,
    pub secret: &'a [u8],
    pub region: &'a str,
    pub service: &'a str,
    /// `YYYYMMDDTHHMMSSZ`; also sent as `x-amz-date`.
    pub amz_date: &'a str,
}

impl Scope<'_> {
    fn date(&self) -> &str {
        &self.amz_date[..8.min(self.amz_date.len())]
    }
    fn credential_scope(&self) -> String {
        format!("{}/{}/{}/aws4_request", self.date(), self.region, self.service)
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data).as_ref().to_vec()
}

/// The canonical request. `headers` are `(lower-case name, canonical
/// value)`; repeated names are joined with commas, names sorted.
pub fn canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
) -> (String, String) {
    let mut merged: Vec<(String, String)> = Vec::new();
    let mut sorted = headers.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in sorted {
        match merged.last_mut() {
            Some((lk, lv)) if *lk == k => {
                lv.push(',');
                lv.push_str(&v);
            }
            _ => merged.push((k, v)),
        }
    }
    let signed = merged.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    let canon: String = merged.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    (format!("{method}\n{canonical_uri}\n{canonical_query}\n{canon}\n{signed}\n{payload_hash}"), signed)
}

/// Sign; returns `(signed headers, signature hex)`.
pub fn sign(
    scope: &Scope,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
) -> (String, String) {
    let (creq, signed) = canonical_request(method, canonical_uri, canonical_query, headers, payload_hash);
    let sts = format!("{ALGORITHM}\n{}\n{}\n{}", scope.amz_date, scope.credential_scope(), hex_sha256(creq.as_bytes()));
    let k_secret = Zeroizing::new([b"AWS4".as_slice(), scope.secret].concat());
    let k_date = Zeroizing::new(hmac(&k_secret, scope.date().as_bytes()));
    let k_region = Zeroizing::new(hmac(&k_date, scope.region.as_bytes()));
    let k_service = Zeroizing::new(hmac(&k_region, scope.service.as_bytes()));
    let k_signing = Zeroizing::new(hmac(&k_service, b"aws4_request"));
    (signed, hex::encode(hmac(&k_signing, sts.as_bytes())))
}

/// The `Authorization` header value.
pub fn authorization(scope: &Scope, signed_headers: &str, signature: &str) -> String {
    format!(
        "{ALGORITHM} Credential={}/{}, SignedHeaders={signed_headers}, Signature={signature}",
        scope.access_key_id,
        scope.credential_scope()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AWS SigV4 test suite (awslabs/aws-c-auth, tests/aws-signing-test-suite/v4).
    const AKID: &str = "AKIDEXAMPLE";
    const SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn scope() -> Scope<'static> {
        Scope {
            access_key_id: AKID,
            secret: SECRET,
            region: "us-east-1",
            service: "service",
            amz_date: "20150830T123600Z",
        }
    }

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn aws_test_suite_vectors() {
        let base = [("host", "example.amazonaws.com"), ("x-amz-date", "20150830T123600Z")];
        let s = scope();
        // get-vanilla
        let (signed, sig) = sign(&s, "GET", "/", "", &h(&base), EMPTY);
        assert_eq!(signed, "host;x-amz-date");
        assert_eq!(sig, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
        // get-vanilla-query-order-key-case
        let (_, sig) = sign(&s, "GET", "/", "Param1=value1&Param2=value2", &h(&base), EMPTY);
        assert_eq!(sig, "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500");
        // get-utf8
        let (_, sig) = sign(&s, "GET", "/%E1%88%B4", "", &h(&base), EMPTY);
        assert_eq!(sig, "8318018e0b0f223aa2bbf98705b62bb787dc9c0e678f255a891fd03141be5d85");
        // post-x-www-form-urlencoded (signed body)
        let body_hash = hex_sha256(b"Param1=value1");
        assert_eq!(body_hash, "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e");
        let post = h(&[
            ("x-amz-date", "20150830T123600Z"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("host", "example.amazonaws.com"),
            ("content-length", "13"),
            ("x-amz-content-sha256", &body_hash),
        ]);
        let (signed, sig) = sign(&s, "POST", "/", "", &post, &body_hash);
        assert_eq!(signed, "content-length;content-type;host;x-amz-content-sha256;x-amz-date");
        assert_eq!(sig, "d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b");
        assert_eq!(
            authorization(&s, &signed, &sig),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date, \
             Signature=d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b"
        );
    }

    #[test]
    fn canonical_values_and_dates() {
        assert_eq!(canonical_value(b"  a   b \t c  ").as_deref(), Some("a b c"));
        assert_eq!(canonical_value(b"x\xffy"), None);
        assert_eq!(canonical_value(b"x\ny"), None);
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_440_938_160);
        assert_eq!(amz_dates(t), ("20150830".to_string(), "20150830T123600Z".to_string()));
        let (c, signed) = canonical_request("GET", "/", "", &h(&[("x-b", "2"), ("x-a", "1"), ("x-b", "3")]), EMPTY);
        assert_eq!(signed, "x-a;x-b");
        assert!(c.contains("x-a:1\nx-b:2,3\n"), "{c}");
    }
}
