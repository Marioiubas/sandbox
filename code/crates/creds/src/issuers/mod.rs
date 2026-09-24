//! Issuers and attachment. `static` reads a root from a secret source;
//! `github_app` mints installation tokens. Both hand back an [`Issued`]
//! that only [`attach`] turns into a header.

pub mod github_app;

use crate::{Issued, Secret};
use base64::Engine;
use http::{HeaderMap, HeaderName, HeaderValue};
use netguard::{CanonicalHost, canon_host};
use policy::AttachSpec;
use std::net::IpAddr;

/// An HTTPS API the broker itself calls (issuer endpoints).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiEndpoint {
    pub host: CanonicalHost,
    pub port: u16,
    /// Path prefix without trailing slash (`""` for the root).
    pub base_path: String,
    /// Pinned addresses; empty means resolve with the broker resolver.
    pub addrs: Vec<IpAddr>,
}

impl ApiEndpoint {
    /// `https://host[:port][/base]`; plain HTTP is refused.
    pub fn parse(url: &str, addrs: &[String]) -> Result<ApiEndpoint, String> {
        let rest = url.strip_prefix("https://").ok_or_else(|| format!("{url:?}: issuer APIs must be https://"))?;
        let (auth, base) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None => (rest, ""),
        };
        let (h, port) = match auth.rsplit_once(':') {
            Some((h, p)) if !h.contains(']') || h.ends_with(']') => {
                (h, p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("{url:?}: bad port"))?)
            }
            _ => (auth, 443),
        };
        let host = canon_host(h.as_bytes()).map_err(|e| format!("{url:?}: {e}"))?;
        if !base.is_empty() && netguard::canon_path(base.as_bytes()).map(|p| p.path() != base).unwrap_or(true) {
            return Err(format!("{url:?}: base path is not canonical"));
        }
        let addrs = addrs
            .iter()
            .map(|a| canon_host(a.as_bytes()).ok().and_then(|h| h.ip()).ok_or_else(|| format!("bad address {a:?}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ApiEndpoint { host, port, base_path: base.to_string(), addrs })
    }

    pub fn authority(&self) -> String {
        if self.port == 443 { self.host.as_str().to_string() } else { format!("{}:{}", self.host, self.port) }
    }
}

/// How issuers reach their APIs (brokerd implements it with the broker
/// resolver and verified TLS; tests with fakes).
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn post_json(
        &self,
        api: &ApiEndpoint,
        path: &str,
        bearer: &Secret,
        body: Vec<u8>,
    ) -> anyhow::Result<(u16, Vec<u8>)>;
}

fn header_value(spec: &AttachSpec, secret: &[u8]) -> Vec<u8> {
    match spec {
        AttachSpec::Bearer => [b"Bearer ".as_slice(), secret].concat(),
        AttachSpec::Token => [b"token ".as_slice(), secret].concat(),
        AttachSpec::Basic { username } => {
            let raw = [username.as_bytes(), b":", secret].concat();
            let enc = base64::engine::general_purpose::STANDARD.encode(&raw);
            [b"Basic ".as_slice(), enc.as_bytes()].concat()
        }
        AttachSpec::Header { .. } => secret.to_vec(),
    }
}

/// Set the credential header on a forwarded request (after `strip`).
pub fn attach(issued: &Issued, spec: &AttachSpec, headers: &mut HeaderMap) -> anyhow::Result<()> {
    let name = HeaderName::from_bytes(spec.header_name().as_bytes())?;
    let mut v = HeaderValue::from_bytes(&header_value(spec, issued.secret().expose()))
        .map_err(|_| anyhow::anyhow!("credential {} is not a valid header value", issued.credential_id))?;
    v.set_sensitive(true);
    headers.insert(name, v);
    Ok(())
}

/// Byte strings the response filter must never let back into the sandbox:
/// the secret, its base64 and percent-encoded forms, and the header value.
pub fn needles(issued: &Issued, spec: &AttachSpec) -> Vec<Vec<u8>> {
    let s = issued.secret().expose();
    let mut v = vec![s.to_vec(), base64::engine::general_purpose::STANDARD.encode(s).into_bytes()];
    let pct: String = s
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    v.push(pct.into_bytes());
    if let AttachSpec::Basic { .. } = spec {
        let hv = header_value(spec, s);
        v.push(hv[b"Basic ".len()..].to_vec());
    }
    v.sort();
    v.dedup();
    v.retain(|n| n.len() >= 6);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issued(s: &str) -> Issued {
        Issued::new("c", "static", Secret::new(s.as_bytes().to_vec()), None, None, [0; 32], "load")
    }

    #[test]
    fn attach_forms() {
        let i = issued("sekret-123");
        let mut h = HeaderMap::new();
        attach(&i, &AttachSpec::Bearer, &mut h).unwrap();
        assert_eq!(h["authorization"], "Bearer sekret-123");
        assert!(h["authorization"].is_sensitive());
        attach(&i, &AttachSpec::Basic { username: "x-access-token".into() }, &mut h).unwrap();
        let want = base64::engine::general_purpose::STANDARD.encode("x-access-token:sekret-123");
        assert_eq!(h["authorization"], format!("Basic {want}").as_str());
        attach(&i, &AttachSpec::Header { name: "x-api-key".into() }, &mut h).unwrap();
        assert_eq!(h["x-api-key"], "sekret-123");
        let bad = issued("line\nbreak");
        assert!(!format!("{:#}", attach(&bad, &AttachSpec::Bearer, &mut h).unwrap_err()).contains("line"));
    }

    #[test]
    fn needle_forms() {
        let i = issued("a/b+c=secret");
        let n = needles(&i, &AttachSpec::Basic { username: "u".into() });
        assert!(n.contains(&b"a/b+c=secret".to_vec()));
        assert!(n.contains(&b"a%2Fb%2Bc%3Dsecret".to_vec()));
        assert!(n.contains(&base64::engine::general_purpose::STANDARD.encode("u:a/b+c=secret").into_bytes()));
    }

    #[test]
    fn endpoints() {
        let e = ApiEndpoint::parse("https://api.github.com", &[]).unwrap();
        assert_eq!((e.host.as_str(), e.port, e.base_path.as_str()), ("api.github.com", 443, ""));
        let e = ApiEndpoint::parse("https://ghe.example:8443/api/v3/", &["10.0.0.5".into()]).unwrap();
        assert_eq!((e.port, e.base_path.as_str(), e.authority()), (8443, "/api/v3", "ghe.example:8443".into()));
        assert_eq!(e.addrs, vec!["10.0.0.5".parse::<IpAddr>().unwrap()]);
        for bad in ["http://api.github.com", "https://api.github.com:0", "https://a\u{0}b", "https://x/a/../b"] {
            assert!(ApiEndpoint::parse(bad, &[]).is_err(), "{bad}");
        }
        assert!(ApiEndpoint::parse("https://x", &["0x7f.1".into()]).is_err());
    }
}
