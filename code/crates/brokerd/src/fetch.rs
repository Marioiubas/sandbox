//! Broker-originated HTTPS to identity providers (discovery documents, key
//! sets, the device and token endpoints): the host through the one
//! canonicaliser (I6), resolution by the broker, public addresses only (a
//! discovery document cannot steer the broker at a metadata endpoint or a
//! private network), verified TLS. Addresses pinned in user or org policy
//! replace DNS, but never reach metadata or link-local addresses.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use netguard::resolver::PolicyResolver;
use netguard::{AddrClass, CanonicalHost, canon_host, classify_addr};
use rustls_pki_types::CertificateDer;
use std::net::IpAddr;
use std::time::Duration;

/// An `https://` URL, split and canonicalised.
pub struct Target {
    pub host: CanonicalHost,
    pub port: u16,
    /// `host[:port]` as the URL spelled it (the Host header).
    pub authority: String,
    pub path: String,
}

impl Target {
    pub fn parse(url: &str) -> Result<Target, String> {
        let rest = url.strip_prefix("https://").ok_or_else(|| format!("{url}: only https:// is fetched"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (h, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("{url}: bad port"))?),
            None => (authority, 443),
        };
        let host = canon_host(h.as_bytes()).map_err(|e| format!("{url}: host {e}"))?;
        if path.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(format!("{url}: bad path"));
        }
        Ok(Target { host, port, authority: authority.to_string(), path: path.to_string() })
    }

    /// Same host and port (endpoints must live on the issuer's host).
    pub fn same_origin(&self, other: &Target) -> bool {
        self.host == other.host && self.port == other.port
    }
}

async fn addresses(t: &Target, pins: &[IpAddr]) -> Result<Vec<IpAddr>, String> {
    if !pins.is_empty() {
        if pins.iter().any(|a| matches!(classify_addr(*a), AddrClass::Metadata | AddrClass::LinkLocal)) {
            return Err(format!("{}: a pinned address is a metadata or link-local address; refused", t.host));
        }
        return Ok(pins.to_vec());
    }
    let addrs = netguard::resolver::SystemResolver::new()
        .resolve(&t.host)
        .await
        .map_err(|r| format!("resolving {}: {r:?}", t.host))?;
    if addrs.is_empty() || addrs.iter().any(|a| classify_addr(*a) != AddrClass::Public) {
        return Err(format!("{} resolves to a non-public address; refused", t.host));
    }
    Ok(addrs)
}

/// One request: GET, or POST of a form body. Returns the status and at
/// most `max` bytes of the body.
pub async fn request(
    url: &str,
    pins: &[IpAddr],
    form: Option<&str>,
    roots: &[CertificateDer<'static>],
    max: usize,
) -> Result<(u16, Vec<u8>), String> {
    let t = Target::parse(url)?;
    let addrs = addresses(&t, pins).await.map_err(|e| format!("{url}: {e}"))?;
    let fetch = async {
        let tcp = crate::upstream::connect_addrs(&addrs, t.port).await.ok_or("connect failed")?;
        let cfg = tls::upstream::client_config(roots).map_err(|e| e.to_string())?;
        let tls = crate::upstream::tls_connect(&cfg, &t.host, tcp).await.map_err(|r| format!("TLS: {r:?}"))?;
        let (mut s, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let b = hyper::Request::builder()
            .uri(t.path.as_str())
            .header("host", t.authority.as_str())
            .header("user-agent", "broker")
            .header("accept", "application/json");
        let req = match form {
            None => b.method("GET").body(Full::new(Bytes::new())),
            Some(f) => b
                .method("POST")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Full::new(Bytes::from(f.to_string()))),
        }
        .map_err(|e| e.to_string())?;
        let resp = s.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = Limited::new(resp.into_body(), max).collect().await.map_err(|_| "body too large or broken")?;
        Ok::<(u16, Vec<u8>), String>((status, body.to_bytes().to_vec()))
    };
    tokio::time::timeout(Duration::from_secs(15), fetch)
        .await
        .map_err(|_| format!("{url}: timed out"))?
        .map_err(|e| format!("{url}: {e}"))
}

/// GET `url` (https only) and return at most `max` bytes of a 200 body.
pub async fn get(url: &str, roots: &[CertificateDer<'static>], max: usize) -> Result<Vec<u8>, String> {
    get_pinned(url, &[], roots, max).await
}

/// As [`get`], through pinned addresses when given.
pub async fn get_pinned(
    url: &str,
    pins: &[IpAddr],
    roots: &[CertificateDer<'static>],
    max: usize,
) -> Result<Vec<u8>, String> {
    match request(url, pins, None, roots, max).await? {
        (200, b) => Ok(b),
        (s, _) => Err(format!("{url}: HTTP {s}")),
    }
}
