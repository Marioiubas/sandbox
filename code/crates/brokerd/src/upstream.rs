//! Broker-originated TLS (pipeline step 7): re-originated requests and the
//! issuers' own API calls. Verification is always full, against Mozilla's
//! roots plus roots the user configured; there is no insecure mode.

use audit::Reason;
use bytes::Bytes;
use creds::Secret;
use creds::issuers::{ApiEndpoint, Transport};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use netguard::resolver::PolicyResolver;
use netguard::{AddrClass, CanonicalHost, classify_addr};
use rustls::ClientConfig;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const TLS_TIMEOUT: Duration = Duration::from_secs(15);

/// Connect to the first reachable address (IPv4 first).
pub async fn connect_addrs(addrs: &[IpAddr], port: u16) -> Option<TcpStream> {
    let mut ordered = addrs.to_vec();
    ordered.sort_by_key(|a| a.is_ipv6());
    for a in ordered {
        if let Ok(Ok(s)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::new(a, port))).await {
            let _ = s.set_nodelay(true);
            return Some(s);
        }
    }
    None
}

/// Linux: acknowledge the upstream's segments at once rather than after the
/// delayed-ACK timer. An upstream that leaves Nagle on (Java servers by
/// default) otherwise holds its first response behind its TLS session
/// tickets until our delayed ACK: ~40 ms on a fresh connection. The kernel
/// may leave quick-ACK mode again, so it is re-armed at the points that
/// matter (after connect, after the handshake). Best effort.
pub fn quickack(s: &TcpStream) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let one: libc::c_int = 1;
        // SAFETY: a valid, open socket fd and a correctly sized c_int value.
        let _ = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                (&one as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }
    #[cfg(not(target_os = "linux"))]
    let _ = s;
}

/// TLS toward the upstream, verified for exactly the canonical host.
pub async fn tls_connect(
    cfg: &Arc<ClientConfig>,
    host: &CanonicalHost,
    tcp: TcpStream,
) -> Result<TlsStream<TcpStream>, Reason> {
    let name = tls::upstream::server_name(host).map_err(|_| Reason::UpstreamTls)?;
    match tokio::time::timeout(TLS_TIMEOUT, TlsConnector::from(cfg.clone()).connect(name, tcp)).await {
        Ok(Ok(s)) => {
            quickack(s.get_ref().0);
            Ok(s)
        }
        _ => Err(Reason::UpstreamTls),
    }
}

/// The issuers' transport: broker resolver, verified TLS, one request.
pub struct BrokerTransport {
    pub resolver: Arc<dyn PolicyResolver>,
    pub tls: Arc<ClientConfig>,
}

impl BrokerTransport {
    /// One request to an issuer API: broker resolver (never a metadata or
    /// link-local address), verified TLS, a 1 MiB response limit.
    async fn send(&self, api: &ApiEndpoint, req: http::Request<Full<Bytes>>) -> anyhow::Result<(u16, Vec<u8>)> {
        let addrs = if api.addrs.is_empty() {
            let a =
                self.resolver.resolve(&api.host).await.map_err(|r| anyhow::anyhow!("resolving {}: {r:?}", api.host))?;
            // A configured issuer API is trusted, but never a metadata or link-local address.
            if a.iter().any(|x| matches!(classify_addr(*x), AddrClass::Metadata | AddrClass::LinkLocal)) {
                anyhow::bail!("{} resolved to a metadata or link-local address", api.host);
            }
            a
        } else {
            api.addrs.clone()
        };
        let tcp = connect_addrs(&addrs, api.port)
            .await
            .ok_or_else(|| anyhow::anyhow!("cannot connect to {}", api.authority()))?;
        let tls = tls_connect(&self.tls, &api.host, tcp)
            .await
            .map_err(|_| anyhow::anyhow!("TLS to {} failed verification", api.authority()))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = tokio::time::timeout(Duration::from_secs(20), sender.send_request(req)).await??;
        let status = resp.status().as_u16();
        let bytes = Limited::new(resp.into_body(), 1 << 20)
            .collect()
            .await
            .map_err(|_| anyhow::anyhow!("issuer response too large or broken"))?
            .to_bytes();
        Ok((status, bytes.to_vec()))
    }
}

#[async_trait::async_trait]
impl Transport for BrokerTransport {
    async fn post_json(
        &self,
        api: &ApiEndpoint,
        path: &str,
        bearer: &Secret,
        body: Vec<u8>,
    ) -> anyhow::Result<(u16, Vec<u8>)> {
        let mut auth = http::HeaderValue::from_bytes(&[b"Bearer ".as_slice(), bearer.expose()].concat())
            .map_err(|_| anyhow::anyhow!("issuer bearer is not a header value"))?;
        auth.set_sensitive(true);
        let req = http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", api.authority())
            .header("authorization", auth)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .header("user-agent", concat!("broker/", env!("CARGO_PKG_VERSION")))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))?;
        self.send(api, req).await
    }

    async fn post(
        &self,
        api: &ApiEndpoint,
        path: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> anyhow::Result<(u16, Vec<u8>)> {
        let mut req = http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", api.authority())
            .header("user-agent", concat!("broker/", env!("CARGO_PKG_VERSION")))
            .body(Full::new(Bytes::from(body)))?;
        for (k, v) in headers {
            let mut v =
                http::HeaderValue::from_str(&v).map_err(|_| anyhow::anyhow!("header {k} is not a header value"))?;
            v.set_sensitive(true);
            req.headers_mut().insert(http::HeaderName::from_bytes(k.as_bytes())?, v);
        }
        self.send(api, req).await
    }
}
