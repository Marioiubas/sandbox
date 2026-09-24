//! Broker-originated HTTPS reads (identity discovery documents and key
//! sets): the host through the one canonicaliser (I6), resolution by the
//! broker, public addresses only (a discovery document cannot steer the
//! broker at a metadata endpoint or a private network), verified TLS.

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use netguard::resolver::PolicyResolver;
use netguard::{AddrClass, canon_host, classify_addr};
use rustls_pki_types::CertificateDer;
use std::time::Duration;

/// GET `url` (https only) and return at most `max` bytes of a 200 body.
pub async fn get(url: &str, roots: &[CertificateDer<'static>], max: usize) -> Result<Vec<u8>, String> {
    let rest = url.strip_prefix("https://").ok_or_else(|| format!("{url}: only https:// is fetched"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (h, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| format!("{url}: bad port"))?),
        None => (authority, 443),
    };
    let host = canon_host(h.as_bytes()).map_err(|e| format!("{url}: host {e}"))?;
    let addrs = netguard::resolver::SystemResolver::new()
        .resolve(&host)
        .await
        .map_err(|r| format!("{url}: resolving {host}: {r:?}"))?;
    if addrs.is_empty() || addrs.iter().any(|a| classify_addr(*a) != AddrClass::Public) {
        return Err(format!("{url}: {host} resolves to a non-public address; refused"));
    }
    let fetch = async {
        let tcp = crate::upstream::connect_addrs(&addrs, port).await.ok_or("connect failed")?;
        let cfg = tls::upstream::client_config(roots).map_err(|e| e.to_string())?;
        let tls = crate::upstream::tls_connect(&cfg, &host, tcp).await.map_err(|r| format!("TLS: {r:?}"))?;
        let (mut s, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let req = hyper::Request::get(path)
            .header("host", authority)
            .header("user-agent", "broker")
            .header("accept", "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(|e| e.to_string())?;
        let resp = s.send_request(req).await.map_err(|e| e.to_string())?;
        if resp.status() != hyper::StatusCode::OK {
            return Err(format!("HTTP {}", resp.status()));
        }
        let body = Limited::new(resp.into_body(), max).collect().await.map_err(|_| "body too large or broken")?;
        Ok::<Vec<u8>, String>(body.to_bytes().to_vec())
    };
    tokio::time::timeout(Duration::from_secs(15), fetch)
        .await
        .map_err(|_| format!("{url}: timed out"))?
        .map_err(|e| format!("{url}: {e}"))
}
