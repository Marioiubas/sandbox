//! Ingress: identify the protocol on a sandbox connection, run the CONNECT or
//! SOCKS5 handshake, authenticate the session where the channel requires it,
//! and hand the *raw* destination bytes to the pipeline. No decision is made
//! here; the pipeline canonicalises, authorises and replies.

pub mod connect;
pub mod socks5;

use audit::{Reason, RequestId};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressKind {
    Connect,
    Socks5,
}

impl IngressKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            IngressKind::Connect => "connect",
            IngressKind::Socks5 => "socks5",
        }
    }
}

/// How the channel identifies its session.
#[derive(Clone)]
pub enum ChannelAuth {
    /// The channel itself is per-session (Linux UDS): no credential needed;
    /// any offered proxy credential is consumed and ignored.
    Implicit,
    /// Loopback channel (macOS): every connection must present this session's
    /// sentinel as the proxy password; it is consumed, never forwarded.
    Sentinel(Vec<u8>),
}

impl std::fmt::Debug for ChannelAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelAuth::Implicit => f.write_str("Implicit"),
            ChannelAuth::Sentinel(_) => f.write_str("Sentinel(<redacted>)"),
        }
    }
}

/// Constant-time byte comparison for sentinels.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A parsed destination awaiting a decision.
#[derive(Debug)]
pub struct RawDestination {
    pub kind: IngressKind,
    /// Host bytes exactly as received (domain forms), never a `&str`.
    pub host_bytes: Vec<u8>,
    /// Set when SOCKS5 carried a binary address instead of a name.
    pub binary_addr: Option<IpAddr>,
    pub port: u16,
    /// Client bytes received after the handshake (forwarded after SNI check).
    pub leftover: Vec<u8>,
}

#[derive(Debug)]
pub struct IngressReject {
    pub kind: Option<IngressKind>,
    pub reason: Reason,
    /// Raw host bytes if the handshake got that far (for the audit record).
    pub host_bytes: Option<Vec<u8>>,
}

async fn read_more<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>, cap: usize) -> std::io::Result<()> {
    let mut chunk = [0u8; 2048];
    let want = chunk.len().min(cap.saturating_sub(buf.len()).max(1));
    let n = s.read(&mut chunk[..want]).await?;
    if n == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

/// Run the handshake. On `Err`, the caller logs the reject and calls
/// [`reply_deny`]; the stream is still usable for that reply.
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    auth: &ChannelAuth,
) -> Result<RawDestination, IngressReject> {
    let io_reject = |kind| IngressReject { kind, reason: Reason::MalformedRequest, host_bytes: None };
    let mut buf = Vec::with_capacity(512);
    let first = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_more(s, &mut buf, connect::MAX_HEAD)).await {
        Ok(Ok(())) => buf[0],
        _ => return Err(io_reject(None)),
    };
    match first {
        0x05 => tokio::time::timeout(HANDSHAKE_TIMEOUT, socks5_handshake(s, buf, auth))
            .await
            .unwrap_or_else(|_| Err(io_reject(Some(IngressKind::Socks5)))),
        0x04 => Err(IngressReject { kind: None, reason: Reason::Socks4Refused, host_bytes: None }),
        b'A'..=b'Z' | b'a'..=b'z' => tokio::time::timeout(HANDSHAKE_TIMEOUT, connect_handshake(s, buf, auth))
            .await
            .unwrap_or_else(|_| Err(io_reject(Some(IngressKind::Connect)))),
        _ => Err(IngressReject { kind: None, reason: Reason::ProtocolUnsupported, host_bytes: None }),
    }
}

async fn connect_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    mut buf: Vec<u8>,
    auth: &ChannelAuth,
) -> Result<RawDestination, IngressReject> {
    let kind = Some(IngressKind::Connect);
    let req = loop {
        match connect::parse(&buf) {
            connect::ParseOutcome::Done(r) => break r,
            connect::ParseOutcome::Reject(reason) => {
                return Err(IngressReject { kind, reason, host_bytes: None });
            }
            connect::ParseOutcome::Incomplete => {
                if read_more(s, &mut buf, connect::MAX_HEAD).await.is_err() {
                    return Err(IngressReject { kind, reason: Reason::MalformedRequest, host_bytes: None });
                }
            }
        }
    };
    if let ChannelAuth::Sentinel(expected) = auth {
        let reason = match req.proxy_authorization.as_deref().map(connect::basic_password) {
            None => Some(Reason::ProxyAuthRequired),
            Some(None) => Some(Reason::BadSentinel),
            Some(Some(pw)) if !ct_eq(&pw, expected) => Some(Reason::BadSentinel),
            Some(Some(_)) => None,
        };
        if let Some(reason) = reason {
            return Err(IngressReject { kind, reason, host_bytes: Some(req.host) });
        }
    }
    Ok(RawDestination {
        kind: IngressKind::Connect,
        host_bytes: req.host,
        binary_addr: None,
        port: req.port,
        leftover: req.leftover,
    })
}

async fn socks5_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    mut buf: Vec<u8>,
    auth: &ChannelAuth,
) -> Result<RawDestination, IngressReject> {
    let kind = Some(IngressKind::Socks5);
    let rej = |reason| IngressReject { kind, reason, host_bytes: None };
    const CAP: usize = 1024;
    let (methods, used) = loop {
        match socks5::parse_greeting(&buf) {
            socks5::Parsed::Done(m, n) => break (m, n),
            socks5::Parsed::Reject(r) => return Err(rej(r)),
            socks5::Parsed::Incomplete => {
                read_more(s, &mut buf, CAP).await.map_err(|_| rej(Reason::MalformedRequest))?
            }
        }
    };
    buf.drain(..used);
    let method = match auth {
        ChannelAuth::Implicit if methods.contains(&socks5::AUTH_NONE) => socks5::AUTH_NONE,
        _ if methods.contains(&socks5::AUTH_USERPASS) => socks5::AUTH_USERPASS,
        _ => {
            let _ = s.write_all(&[socks5::VER, socks5::AUTH_NO_ACCEPTABLE]).await;
            return Err(IngressReject { kind, reason: Reason::ProxyAuthRequired, host_bytes: None });
        }
    };
    s.write_all(&[socks5::VER, method]).await.map_err(|_| rej(Reason::MalformedRequest))?;
    if method == socks5::AUTH_USERPASS {
        let ((_user, pass), used) = loop {
            match socks5::parse_userpass(&buf) {
                socks5::Parsed::Done(up, n) => break (up, n),
                socks5::Parsed::Reject(r) => return Err(rej(r)),
                socks5::Parsed::Incomplete => {
                    read_more(s, &mut buf, CAP).await.map_err(|_| rej(Reason::MalformedRequest))?
                }
            }
        };
        buf.drain(..used);
        let ok = match auth {
            ChannelAuth::Implicit => true,
            ChannelAuth::Sentinel(expected) => ct_eq(&pass, expected),
        };
        let _ = s.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]).await;
        if !ok {
            return Err(rej(Reason::BadSentinel));
        }
    }
    let (req, used) = loop {
        match socks5::parse_request(&buf) {
            socks5::Parsed::Done(r, n) => break (r, n),
            socks5::Parsed::Reject(r) => return Err(rej(r)),
            socks5::Parsed::Incomplete => {
                read_more(s, &mut buf, CAP).await.map_err(|_| rej(Reason::MalformedRequest))?
            }
        }
    };
    buf.drain(..used);
    let (host_bytes, binary_addr) = match req.addr {
        socks5::Addr::Domain(d) => (d, None),
        socks5::Addr::V4(o) => {
            let ip = IpAddr::V4(Ipv4Addr::from(o));
            (ip.to_string().into_bytes(), Some(ip))
        }
        socks5::Addr::V6(o) => {
            let ip = IpAddr::V6(Ipv6Addr::from(o));
            (format!("[{ip}]").into_bytes(), Some(ip))
        }
    };
    Ok(RawDestination { kind: IngressKind::Socks5, host_bytes, binary_addr, port: req.port, leftover: buf })
}

/// Tell the client the tunnel is up.
pub async fn reply_ok<S: AsyncWrite + Unpin>(s: &mut S, kind: IngressKind) -> std::io::Result<()> {
    match kind {
        IngressKind::Connect => s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await,
        IngressKind::Socks5 => s.write_all(&socks5::reply(socks5::REP_SUCCEEDED)).await,
    }?;
    s.flush().await
}

/// Tell the client why it was denied: the reason code and the request ID for
/// `broker why`, never policy text or secret values.
pub async fn reply_deny<S: AsyncWrite + Unpin>(
    s: &mut S,
    kind: Option<IngressKind>,
    reason: Reason,
    request_id: &RequestId,
) -> std::io::Result<()> {
    match kind {
        Some(IngressKind::Connect) => {
            let (status, extra) = match reason {
                Reason::ProxyAuthRequired | Reason::BadSentinel => {
                    ("407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"broker\"\r\n")
                }
                Reason::ResolveFailed | Reason::NoAddresses | Reason::UpstreamConnectFailed => ("502 Bad Gateway", ""),
                Reason::MalformedRequest => ("400 Bad Request", ""),
                Reason::AuditUnavailable => ("503 Service Unavailable", ""),
                Reason::PlainHttpUnsupported => ("405 Method Not Allowed", ""),
                _ => ("403 Forbidden", ""),
            };
            let body = format!(
                "broker denied: {} ({})\nrequest: {}\nexplain: broker why {}\n",
                reason.as_str(),
                reason.explain(),
                request_id,
                request_id
            );
            let head = format!(
                "HTTP/1.1 {status}\r\n{extra}Content-Type: text/plain; charset=utf-8\r\nX-Broker-Request-Id: {request_id}\r\nX-Broker-Reason: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                reason.as_str(),
                body.len()
            );
            s.write_all(head.as_bytes()).await?;
            s.write_all(body.as_bytes()).await?;
        }
        Some(IngressKind::Socks5) => {
            // Auth failures were already answered in the sub-negotiation.
            if !matches!(reason, Reason::ProxyAuthRequired | Reason::BadSentinel) {
                s.write_all(&socks5::reply(socks5::reply_for(reason))).await?;
            }
        }
        None => {
            if reason == Reason::Socks4Refused {
                // SOCKS4 "request rejected or failed".
                s.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await?;
            }
        }
    }
    s.flush().await?;
    s.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn connect_with_sentinel() {
        let (mut client, mut server) = duplex(4096);
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YnJva2VyOnMzY3JldA==\r\n\r\n")
            .await
            .unwrap();
        let d = handshake(&mut server, &ChannelAuth::Sentinel(b"s3cret".to_vec())).await.unwrap();
        assert_eq!(d.kind, IngressKind::Connect);
        assert_eq!(d.host_bytes, b"example.com");
    }

    #[tokio::test]
    async fn connect_missing_or_wrong_sentinel() {
        let (mut client, mut server) = duplex(4096);
        client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").await.unwrap();
        let e = handshake(&mut server, &ChannelAuth::Sentinel(b"x".to_vec())).await.unwrap_err();
        assert_eq!(e.reason, Reason::ProxyAuthRequired);
        let (mut client, mut server) = duplex(4096);
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic YnJva2VyOnd.cm9uZw==\r\n\r\n")
            .await
            .unwrap();
        let e = handshake(&mut server, &ChannelAuth::Sentinel(b"x".to_vec())).await.unwrap_err();
        assert_eq!(e.reason, Reason::BadSentinel);
    }

    #[tokio::test]
    async fn socks5_userpass_and_domain() {
        let (mut client, mut server) = duplex(4096);
        let mut msg = vec![5, 1, 2, 1, 6];
        msg.extend(b"broker");
        msg.push(2);
        msg.extend(b"ok");
        msg.extend([5, 1, 0, 3, 7]);
        msg.extend(b"a.b.com");
        msg.extend([1, 187]);
        client.write_all(&msg).await.unwrap();
        let d = handshake(&mut server, &ChannelAuth::Sentinel(b"ok".to_vec())).await.unwrap();
        assert_eq!((d.kind, d.host_bytes.as_slice(), d.port), (IngressKind::Socks5, &b"a.b.com"[..], 443));
        let mut resp = [0u8; 4];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [5, 2, 1, 0]);
    }

    #[tokio::test]
    async fn socks5_requires_sentinel_on_loopback() {
        let (mut client, mut server) = duplex(4096);
        client.write_all(&[5, 1, 0]).await.unwrap();
        let e = handshake(&mut server, &ChannelAuth::Sentinel(b"ok".to_vec())).await.unwrap_err();
        assert_eq!(e.reason, Reason::ProxyAuthRequired);
    }

    #[tokio::test]
    async fn socks4_and_garbage() {
        let (mut client, mut server) = duplex(64);
        client.write_all(&[4, 1, 0, 80, 0, 0, 0, 1, 0]).await.unwrap();
        assert_eq!(handshake(&mut server, &ChannelAuth::Implicit).await.unwrap_err().reason, Reason::Socks4Refused);
        let (mut client, mut server) = duplex(64);
        client.write_all(&[0x16, 3, 1]).await.unwrap();
        assert_eq!(
            handshake(&mut server, &ChannelAuth::Implicit).await.unwrap_err().reason,
            Reason::ProtocolUnsupported
        );
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
