//! Client credentials on terminated requests (I7, pipeline step 5).
//!
//! Every header and query parameter that commonly carries a credential is
//! inspected. A value is acceptable only if it is this session's sentinel
//! bound to the destination; anything else is a credential the broker did
//! not issue and the request is rejected (the Cowork planted-key lesson).
//! Cookies are rejected outright: the broker strips `Set-Cookie` from
//! terminated responses, so a cookie on a terminated request was planted.
//! After inspection every such header and parameter is stripped; the only
//! credential that reaches the upstream is the one the broker attaches.

use crate::sentinel::{SentinelCheck, Sentinels};
use audit::Reason;
use base64::Engine;
use http::HeaderMap;
use netguard::CanonicalHost;

/// Request headers that carry credentials (lower case).
pub const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "x-auth-token",
    "x-access-token",
    "private-token",
    "job-token",
    "x-amz-security-token",
    "x-github-token",
    "x-vault-token",
    "x-npm-token",
];

/// Query parameters that carry credentials (lower case).
pub const CREDENTIAL_PARAMS: &[&str] = &[
    "access_token",
    "api_key",
    "apikey",
    "key",
    "token",
    "private_token",
    "client_secret",
    "password",
    "x-amz-credential",
    "x-amz-signature",
    "x-amz-security-token",
    "sig",
    "signature",
];

/// A sentinel the client presented (by credential ID).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialUse {
    pub credential_id: String,
    /// Where it was: header or query parameter name.
    pub location: String,
}

/// Why a request was rejected, and where (header/parameter name only; the
/// value is never reported).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejected {
    pub reason: Reason,
    pub location: String,
}

fn verdict(
    v: &[u8],
    loc: &str,
    sentinels: &Sentinels,
    dest: &CanonicalHost,
    uses: &mut Vec<CredentialUse>,
) -> Result<(), Rejected> {
    match sentinels.check(v, dest) {
        SentinelCheck::Valid(id) => {
            uses.push(CredentialUse { credential_id: id, location: loc.to_string() });
            Ok(())
        }
        SentinelCheck::WrongHost(_) => Err(Rejected { reason: Reason::SentinelWrongHost, location: loc.to_string() }),
        SentinelCheck::NotSentinel => Err(Rejected { reason: Reason::ForeignCredential, location: loc.to_string() }),
    }
}

fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

/// Inspect a terminated request. `channel_sentinel` is the session's proxy
/// sentinel (macOS loopback ingress), which a client may repeat inside the
/// tunnel as `Proxy-Authorization`; it is stripped, not forwarded.
pub fn inspect(
    headers: &HeaderMap,
    query: Option<&str>,
    sentinels: &Sentinels,
    dest: &CanonicalHost,
    channel_sentinel: Option<&[u8]>,
) -> Result<Vec<CredentialUse>, Rejected> {
    let mut uses = Vec::new();
    for name in CREDENTIAL_HEADERS {
        for value in headers.get_all(*name) {
            let v = value.as_bytes();
            if v.iter().all(|b| b.is_ascii_whitespace()) {
                continue;
            }
            match *name {
                "cookie" => return Err(Rejected { reason: Reason::ForeignCredential, location: "cookie".into() }),
                "authorization" | "proxy-authorization" => {
                    let s = std::str::from_utf8(v)
                        .map_err(|_| Rejected { reason: Reason::ForeignCredential, location: name.to_string() })?;
                    let (scheme, rest) = s.trim().split_once(' ').unwrap_or((s.trim(), ""));
                    let rest = rest.trim();
                    match scheme.to_ascii_lowercase().as_str() {
                        "bearer" | "token" => verdict(rest.as_bytes(), name, sentinels, dest, &mut uses)?,
                        "basic" => {
                            let raw = base64::engine::general_purpose::STANDARD.decode(rest).map_err(|_| Rejected {
                                reason: Reason::ForeignCredential,
                                location: name.to_string(),
                            })?;
                            let pass = match raw.iter().position(|&b| b == b':') {
                                Some(i) => &raw[i + 1..],
                                None => &raw[..],
                            };
                            if *name == "proxy-authorization" && channel_sentinel.is_some_and(|c| c == pass) {
                                continue;
                            }
                            verdict(pass, name, sentinels, dest, &mut uses)?
                        }
                        // A SigV4 signature made with an access key ID: only
                        // this session's sentinel is acceptable (the broker
                        // re-signs); the signature itself is discarded.
                        "aws4-hmac-sha256" => {
                            let akid = rest
                                .split(',')
                                .find_map(|p| p.trim().strip_prefix("Credential="))
                                .and_then(|c| c.split('/').next())
                                .filter(|a| !a.is_empty())
                                .ok_or_else(|| Rejected {
                                    reason: Reason::ForeignCredential,
                                    location: name.to_string(),
                                })?;
                            verdict(akid.as_bytes(), name, sentinels, dest, &mut uses)?
                        }
                        _ => {
                            return Err(Rejected { reason: Reason::ForeignCredential, location: name.to_string() });
                        }
                    }
                }
                _ => verdict(v, name, sentinels, dest, &mut uses)?,
            }
        }
    }
    if let Some(q) = query {
        for pair in q.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let k = percent_decode(k).map(|k| String::from_utf8_lossy(&k).to_ascii_lowercase()).unwrap_or_default();
            if !CREDENTIAL_PARAMS.contains(&k.as_str()) || v.is_empty() {
                continue;
            }
            let v = percent_decode(v)
                .ok_or_else(|| Rejected { reason: Reason::ForeignCredential, location: format!("?{k}") })?;
            verdict(&v, &format!("?{k}"), sentinels, dest, &mut uses)?;
        }
    }
    Ok(uses)
}

/// Remove every credential header, and return the query with credential
/// parameters removed (the attached credential is the only one that leaves).
pub fn strip(headers: &mut HeaderMap, query: Option<&str>) -> Option<String> {
    for name in CREDENTIAL_HEADERS {
        headers.remove(*name);
    }
    let q = query?;
    let kept: Vec<&str> = q
        .split('&')
        .filter(|pair| {
            let k = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
            let k = percent_decode(k).map(|k| String::from_utf8_lossy(&k).to_ascii_lowercase()).unwrap_or_default();
            !CREDENTIAL_PARAMS.contains(&k.as_str())
        })
        .collect();
    if kept.is_empty() { None } else { Some(kept.join("&")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use netguard::{HostPattern, canon_host};
    use policy::{AttachSpec, CredKind, CredentialDef, SecretRef};
    use proptest::prelude::*;
    use std::sync::Arc;

    fn setup() -> (Sentinels, String, CanonicalHost) {
        let c = Arc::new(CredentialDef {
            id: "anthropic".into(),
            kind: CredKind::Static { secret: SecretRef::parse("env:X").unwrap() },
            attach: AttachSpec::Header { name: "x-api-key".into() },
            env: Some("ANTHROPIC_API_KEY".into()),
            swap_body: false,
            hosts: vec![HostPattern::parse("api.anthropic.com").unwrap()],
            ttl: None,
            high_risk: false,
        });
        let s = Sentinels::issue(&[c]);
        let v = s.value_for("anthropic").unwrap().to_string();
        (s, v, canon_host(b"api.anthropic.com").unwrap())
    }

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn sigv4_authorization_carries_only_a_sentinel_access_key_id() {
        let (s, v, api) = setup();
        let sig = |akid: &str| {
            format!(
                "AWS4-HMAC-SHA256 Credential={akid}/20260925/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=00ff"
            )
        };
        let ok = inspect(&hm(&[("authorization", &sig(&v))]), None, &s, &api, None).unwrap();
        assert_eq!(ok[0].credential_id, "anthropic");
        for bad in [
            sig("AKIDEXAMPLEFOREIGN"),
            sig(""),
            "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=00".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ] {
            let r = inspect(&hm(&[("authorization", &bad)]), None, &s, &api, None).unwrap_err();
            assert_eq!(r.reason, Reason::ForeignCredential, "{bad}");
        }
        let other = canon_host(b"evil.example").unwrap();
        let r = inspect(&hm(&[("authorization", &sig(&v))]), None, &s, &other, None).unwrap_err();
        assert_eq!(r.reason, Reason::SentinelWrongHost);
    }

    #[test]
    fn sentinel_accepted_everything_else_rejected() {
        let (s, v, api) = setup();
        let ok = inspect(&hm(&[("x-api-key", &v)]), None, &s, &api, None).unwrap();
        assert_eq!(ok, vec![CredentialUse { credential_id: "anthropic".into(), location: "x-api-key".into() }]);
        assert!(inspect(&hm(&[("authorization", &format!("Bearer {v}"))]), None, &s, &api, None).is_ok());
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{v}"));
        assert!(inspect(&hm(&[("authorization", &format!("Basic {basic}"))]), None, &s, &api, None).is_ok());
        assert!(inspect(&HeaderMap::new(), None, &s, &api, None).unwrap().is_empty());

        let planted = [
            ("x-api-key", "sk-ant-api03-attacker".to_string()),
            ("authorization", "Bearer sk-ant-attacker".to_string()),
            ("authorization", format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("u:ghp_x"))),
            ("authorization", "Digest username=x".to_string()),
            ("authorization", format!("Bearer {v}x")),
            ("cookie", "session=abc".to_string()),
            ("x-goog-api-key", "AIza-attacker".to_string()),
            ("private-token", "glpat-x".to_string()),
        ];
        for (k, val) in planted {
            let r = inspect(&hm(&[(k, &val)]), None, &s, &api, None).unwrap_err();
            assert_eq!(r.reason, Reason::ForeignCredential, "{k}: {val}");
            assert_eq!(r.location, k);
        }
        // Two values, one foreign: rejected.
        assert!(inspect(&hm(&[("x-api-key", &v), ("x-api-key", "attacker")]), None, &s, &api, None).is_err());
        // Right sentinel, wrong host.
        let evil = canon_host(b"evil.example").unwrap();
        assert_eq!(
            inspect(&hm(&[("x-api-key", &v)]), None, &s, &evil, None).unwrap_err().reason,
            Reason::SentinelWrongHost
        );
    }

    #[test]
    fn query_parameters() {
        let (s, v, api) = setup();
        assert!(inspect(&HeaderMap::new(), Some("a=1&b=2"), &s, &api, None).unwrap().is_empty());
        let r = inspect(&HeaderMap::new(), Some("a=1&key=AIzaSyAttacker"), &s, &api, None).unwrap_err();
        assert_eq!((r.reason, r.location.as_str()), (Reason::ForeignCredential, "?key"));
        let r = inspect(&HeaderMap::new(), Some("Access%5FToken=x"), &s, &api, None).unwrap_err();
        assert_eq!(r.location, "?access_token", "parameter names are decoded before matching");
        assert!(inspect(&HeaderMap::new(), Some(&format!("key={v}")), &s, &api, None).is_ok());
        assert_eq!(strip(&mut HeaderMap::new(), Some(&format!("a=1&key={v}&b=2"))).as_deref(), Some("a=1&b=2"));
        assert_eq!(strip(&mut HeaderMap::new(), Some("token=x")), None);
    }

    #[test]
    fn channel_sentinel_in_tunnel_is_tolerated_and_stripped() {
        let (s, _, api) = setup();
        let ch = b"bks1_0123";
        let pa = base64::engine::general_purpose::STANDARD.encode("broker:bks1_0123");
        let h = hm(&[("proxy-authorization", &format!("Basic {pa}"))]);
        assert!(inspect(&h, None, &s, &api, Some(ch)).unwrap().is_empty());
        assert!(inspect(&h, None, &s, &api, None).is_err());
        let mut h = h;
        strip(&mut h, None);
        assert!(h.is_empty());
    }

    proptest! {
        /// Whatever credential headers a client sends, none survive strip.
        #[test]
        fn strip_removes_every_credential_header(
            picks in proptest::collection::vec((0..CREDENTIAL_HEADERS.len(), "[ -~]{0,40}"), 0..8),
            other in "[a-z]{1,10}",
        ) {
            let mut h = HeaderMap::new();
            for (i, v) in &picks {
                if let Ok(v) = HeaderValue::from_str(v) {
                    h.append(CREDENTIAL_HEADERS[*i], v);
                }
            }
            h.insert(http::header::HeaderName::from_bytes(format!("x-keep-{other}").as_bytes()).unwrap(), HeaderValue::from_static("1"));
            strip(&mut h, None);
            for n in CREDENTIAL_HEADERS {
                prop_assert!(h.get(*n).is_none());
            }
            prop_assert_eq!(h.len(), 1);
        }

        /// Only this session's sentinel for the host is ever accepted.
        #[test]
        fn random_values_are_foreign(v in "[!-~]{1,80}") {
            let (s, sentinel, api) = setup();
            prop_assume!(v != sentinel);
            let h = hm(&[("x-api-key", &v)]);
            prop_assert!(inspect(&h, None, &s, &api, None).is_err());
        }
    }
}
