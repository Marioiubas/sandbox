//! Proxy probes: CONNECT and SOCKS5 tunnels through the session proxy, and
//! raw bytes over a TLS tunnel (for framing attacks).

use super::*;

struct Proxy {
    addr: SocketAddr,
    user: Option<Vec<u8>>,
    pass: Option<Vec<u8>>,
}

fn proxy_from_env() -> Proxy {
    let url =
        std::env::var("HTTPS_PROXY").unwrap_or_else(|_| inconclusive("no HTTPS_PROXY in the session environment"));
    let rest = url.strip_prefix("http://").unwrap_or(&url);
    let (cred, hostport) = match rest.rsplit_once('@') {
        Some((c, h)) => (Some(c), h),
        None => (None, rest),
    };
    let hostport = hostport.trim_end_matches('/');
    let addr: SocketAddr = hostport.parse().unwrap_or_else(|_| inconclusive(format!("bad proxy address {hostport}")));
    let (user, pass) = match cred.and_then(|c| c.split_once(':')) {
        Some((u, p)) => (Some(u.as_bytes().to_vec()), Some(p.as_bytes().to_vec())),
        None => (None, None),
    };
    Proxy { addr, user, pass }
}

fn b64(v: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(v)
}

/// Returns true when the tunnel is established.
fn open_tunnel(kind: &str, host: &[u8], port: u16, p: &Proxy) -> (TcpStream, Result<(), String>) {
    let mut s = TcpStream::connect_timeout(&p.addr, Duration::from_secs(3))
        .unwrap_or_else(|e| denied(format!("proxy unreachable: {e}")));
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    match kind {
        "connect" => {
            let mut req = b"CONNECT ".to_vec();
            req.extend_from_slice(host);
            req.extend_from_slice(format!(":{port} HTTP/1.1\r\n").as_bytes());
            if let (Some(u), Some(pw)) = (&p.user, &p.pass) {
                let mut c = u.clone();
                c.push(b':');
                c.extend_from_slice(pw);
                req.extend_from_slice(format!("Proxy-Authorization: Basic {}\r\n", b64(&c)).as_bytes());
            }
            req.extend_from_slice(b"\r\n");
            s.write_all(&req).ok();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                match s.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => break,
                }
            }
            let text = String::from_utf8_lossy(&head).to_string();
            if text.starts_with("HTTP/1.1 200") {
                (s, Ok(()))
            } else {
                let rid = text.lines().find_map(|l| l.strip_prefix("X-Broker-Request-Id: ")).unwrap_or("-").to_string();
                let reason = text.lines().find_map(|l| l.strip_prefix("X-Broker-Reason: ")).unwrap_or("-").to_string();
                (s, Err(format!("{} reason={reason} request={rid}", text.lines().next().unwrap_or(""))))
            }
        }
        "socks5" => {
            let auth = p.user.is_some();
            s.write_all(if auth { &[5, 1, 2] } else { &[5, 1, 0] }).ok();
            let mut r = [0u8; 2];
            if s.read_exact(&mut r).is_err() || r[1] == 0xff {
                return (s, Err("socks5 method refused".into()));
            }
            if r[1] == 2 {
                let (u, pw) = (p.user.clone().unwrap_or_default(), p.pass.clone().unwrap_or_default());
                let mut m = vec![1, u.len() as u8];
                m.extend(u);
                m.push(pw.len() as u8);
                m.extend(pw);
                s.write_all(&m).ok();
                if s.read_exact(&mut r).is_err() || r[1] != 0 {
                    return (s, Err("socks5 auth refused".into()));
                }
            }
            let mut req = vec![5, 1, 0, 3, host.len() as u8];
            req.extend_from_slice(host);
            req.extend_from_slice(&port.to_be_bytes());
            s.write_all(&req).ok();
            let mut rep = [0u8; 10];
            match s.read_exact(&mut rep) {
                Ok(()) if rep[1] == 0 => (s, Ok(())),
                Ok(()) => (s, Err(format!("socks5 reply {}", rep[1]))),
                Err(e) => (s, Err(format!("socks5 closed: {e}"))),
            }
        }
        _ => usage(),
    }
}

pub fn probe_proxy(args: &[String]) -> ! {
    // proxy <connect|socks5> <host> <port> <sni|-|raw|socks>
    if args.len() < 4 {
        usage()
    }
    let host = unescape(&args[1]);
    let port: u16 = args[2].parse().unwrap_or_else(|_| usage());
    let p = proxy_from_env();
    let (mut s, r) = open_tunnel(&args[0], &host, port, &p);
    if let Err(e) = r {
        denied(format!("tunnel refused: {e}"));
    }
    let first: Vec<u8> = match args[3].as_str() {
        "-" => tls::sni_peek::synthetic_client_hello(None),
        "raw" => b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
        "socks" => vec![5, 1, 0],
        sni => tls::sni_peek::synthetic_client_hello(Some(&unescape(sni))),
    };
    s.write_all(&first).ok();
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(n) if n > 0 && buf[..n].starts_with(b"UPSTREAM-OK") => allowed("upstream reached"),
        Ok(n) if n > 0 => allowed(format!("upstream answered {n} bytes")),
        _ => denied("tunnel cut by the broker after the first bytes"),
    }
}

/// tls-raw <host> <port> <escaped request> [sni]: a CONNECT tunnel, TLS
/// trusting only the session bundle (`SSL_CERT_FILE`), then the raw bytes
/// (so framing attacks can be sent exactly). Prints the raw response.
pub fn probe_tls_raw(args: &[String]) -> ! {
    if args.len() < 3 {
        usage()
    }
    let host = args[0].clone();
    let port: u16 = args[1].parse().unwrap_or_else(|_| usage());
    // `@path` reads the request from a file (argv length limits).
    let payload = match args[2].strip_prefix('@') {
        Some(f) => std::fs::read(f).unwrap_or_else(|_| usage()),
        None => unescape(&args[2]),
    };
    let sni = args.get(3).cloned().unwrap_or_else(|| host.clone());
    let p = proxy_from_env();
    let (s, r) = open_tunnel("connect", host.as_bytes(), port, &p);
    if let Err(e) = r {
        denied(format!("tunnel refused: {e}"));
    }
    use rustls::pki_types::pem::PemObject;
    let bundle = std::env::var("SSL_CERT_FILE").unwrap_or_else(|_| inconclusive("no SSL_CERT_FILE"));
    let mut roots = rustls::RootCertStore::empty();
    for c in
        rustls::pki_types::CertificateDer::pem_file_iter(&bundle).unwrap_or_else(|_| inconclusive("bundle")).flatten()
    {
        let _ = roots.add(c);
    }
    let cfg = rustls::ClientConfig::builder_with_provider(tls::session_ca::provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(sni).unwrap_or_else(|_| usage());
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(cfg), name).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, s);
    tls.sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    if let Err(e) = tls.write_all(&payload) {
        denied(format!("TLS failed: {e}"));
    }
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    if out.is_empty() {
        denied("no response (connection closed)");
    }
    println!("{}", String::from_utf8_lossy(&out));
    exit(0)
}
