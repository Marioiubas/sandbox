//! `conformance-probe`: one deterministic action per invocation, run inside
//! a broker session. No LLM, no shell, no third-party tools.
//!
//! Exit codes: 0 = the action succeeded (reached / read / wrote);
//! 10 = the action was blocked; 20 = inconclusive; 2 = usage error.
//! stdout carries one line: `ALLOWED ...`, `DENIED ...` or `INCONCLUSIVE ...`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::exit;
use std::time::Duration;

fn allowed(msg: impl AsRef<str>) -> ! {
    println!("ALLOWED {}", msg.as_ref());
    exit(0)
}
fn denied(msg: impl AsRef<str>) -> ! {
    println!("DENIED {}", msg.as_ref());
    exit(10)
}
fn inconclusive(msg: impl AsRef<str>) -> ! {
    println!("INCONCLUSIVE {}", msg.as_ref());
    exit(20)
}
fn usage() -> ! {
    eprintln!("usage: conformance-probe <probe> [args] (see source)");
    exit(2)
}

/// `\xHH` and `\\` escapes, so NUL and other bytes can travel in argv.
fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            if b[i + 1] == b'\\' {
                out.push(b'\\');
                i += 2;
                continue;
            }
            if b[i + 1] == b'x'
                && i + 3 < b.len()
                && let Ok(v) = u8::from_str_radix(&s[i + 2..i + 4], 16)
            {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

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

fn probe_proxy(args: &[String]) -> ! {
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

fn errno_str(e: &std::io::Error) -> String {
    format!("{e} (errno {:?})", e.raw_os_error())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else { usage() };
    let rest = &args[1..];
    match cmd.as_str() {
        "proxy" => probe_proxy(rest),
        "tcp" => {
            let addr = SocketAddr::new(
                rest.first().unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage()),
                rest.get(1).and_then(|p| p.parse().ok()).unwrap_or_else(|| usage()),
            );
            match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                Ok(_) => allowed(format!("connected to {addr}")),
                Err(e) => denied(format!("connect {addr}: {}", errno_str(&e))),
            }
        }
        "udp" => {
            let addr = SocketAddr::new(
                rest.first().unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage()),
                rest.get(1).and_then(|p| p.parse().ok()).unwrap_or_else(|| usage()),
            );
            let s = UdpSocket::bind("0.0.0.0:0").unwrap_or_else(|e| denied(format!("udp socket: {}", errno_str(&e))));
            match s.send_to(b"broker-probe", addr) {
                Ok(_) => allowed(format!("datagram sent to {addr}")),
                Err(e) => denied(format!("sendto {addr}: {}", errno_str(&e))),
            }
        }
        "dns-udp" | "dns-tcp" => {
            // dns-udp <server> <name> <qtype number, 16=TXT>
            let server: std::net::IpAddr = rest.first().unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage());
            let name = rest.get(1).unwrap_or_else(|| usage());
            let qtype: u16 = rest.get(2).and_then(|q| q.parse().ok()).unwrap_or(16);
            let mut q = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
            for label in name.split('.') {
                q.push(label.len() as u8);
                q.extend(label.as_bytes());
            }
            q.push(0);
            q.extend(qtype.to_be_bytes());
            q.extend([0, 1]);
            let sa = SocketAddr::new(server, 53);
            if cmd == "dns-udp" {
                let s =
                    UdpSocket::bind("0.0.0.0:0").unwrap_or_else(|e| denied(format!("udp socket: {}", errno_str(&e))));
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                if let Err(e) = s.send_to(&q, sa) {
                    denied(format!("sendto {sa}: {}", errno_str(&e)));
                }
                let mut buf = [0u8; 512];
                match s.recv_from(&mut buf) {
                    Ok((n, _)) => allowed(format!("{n}-byte DNS answer")),
                    Err(e) => denied(format!("no answer: {}", errno_str(&e))),
                }
            } else {
                match TcpStream::connect_timeout(&sa, Duration::from_secs(3)) {
                    Ok(_) => allowed(format!("TCP/53 to {sa} connected")),
                    Err(e) => denied(format!("connect {sa}: {}", errno_str(&e))),
                }
            }
        }
        "dns" => {
            let name = rest.first().unwrap_or_else(|| usage());
            match (name.as_str(), 443).to_socket_addrs() {
                Ok(mut it) => match it.next() {
                    Some(a) => allowed(format!("{name} resolved to {}", a.ip())),
                    None => denied("no addresses"),
                },
                Err(e) => denied(format!("resolution failed: {e}")),
            }
        }
        "icmp" => {
            let ip: std::net::Ipv4Addr = rest.first().unwrap_or_else(|| usage()).parse().unwrap_or_else(|_| usage());
            // SAFETY: socket(2) with constant arguments.
            let mut fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
            if fd < 0 {
                fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
            }
            if fd < 0 {
                denied(format!("icmp socket: {}", errno_str(&std::io::Error::last_os_error())));
            }
            let pkt: [u8; 8] = [8, 0, 0xf7, 0xfe, 0, 1, 0, 0];
            let sa = libc::sockaddr_in {
                #[cfg(target_os = "macos")]
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as _,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(ip.octets()) },
                sin_zero: [0; 8],
            };
            // SAFETY: valid buffer and sockaddr.
            let n = unsafe {
                libc::sendto(
                    fd,
                    pkt.as_ptr().cast(),
                    pkt.len(),
                    0,
                    (&sa as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                )
            };
            if n < 0 {
                denied(format!("icmp sendto: {}", errno_str(&std::io::Error::last_os_error())));
            }
            allowed("icmp echo sent")
        }
        "unix" => {
            let p = rest.first().unwrap_or_else(|| usage());
            match std::os::unix::net::UnixStream::connect(p) {
                Ok(_) => allowed(format!("connected to {p}")),
                Err(e) => denied(format!("connect {p}: {}", errno_str(&e))),
            }
        }
        "unix-socket" => {
            // SAFETY: socket(2) with constant arguments.
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if fd < 0 {
                denied(format!("socket(AF_UNIX): {}", errno_str(&std::io::Error::last_os_error())));
            }
            allowed("socket(AF_UNIX) created")
        }
        "read" => {
            let p = rest.first().unwrap_or_else(|| usage());
            match std::fs::read(p) {
                Ok(b) => allowed(format!("read {} bytes from {p}", b.len())),
                Err(e) => denied(format!("read {p}: {}", errno_str(&e))),
            }
        }
        "list" => {
            let p = rest.first().unwrap_or_else(|| usage());
            match std::fs::read_dir(p) {
                Ok(rd) => allowed(format!("listed {} entries in {p}", rd.count())),
                Err(e) => denied(format!("list {p}: {}", errno_str(&e))),
            }
        }
        "write" | "write-new" => {
            let p = rest.first().unwrap_or_else(|| usage());
            let mut o = std::fs::OpenOptions::new();
            o.write(true);
            if cmd == "write-new" {
                o.create_new(true)
            } else {
                o.create(true).append(true)
            };
            match o.open(p).and_then(|mut f| f.write_all(b"broker-probe\n")) {
                Ok(()) => allowed(format!("wrote {p}")),
                Err(e) => denied(format!("write {p}: {}", errno_str(&e))),
            }
        }
        "mkdir" => {
            let p = rest.first().unwrap_or_else(|| usage());
            match std::fs::create_dir_all(p) {
                Ok(()) => allowed(format!("created {p}")),
                Err(e) => denied(format!("mkdir {p}: {}", errno_str(&e))),
            }
        }
        "rename" => {
            let (a, b) = (rest.first().unwrap_or_else(|| usage()), rest.get(1).unwrap_or_else(|| usage()));
            match std::fs::rename(a, b) {
                Ok(()) => allowed(format!("renamed {a} -> {b}")),
                Err(e) => denied(format!("rename: {}", errno_str(&e))),
            }
        }
        "symlink" => {
            let (t, l) = (rest.first().unwrap_or_else(|| usage()), rest.get(1).unwrap_or_else(|| usage()));
            match std::os::unix::fs::symlink(t, l) {
                Ok(()) => allowed(format!("symlink {l} -> {t}")),
                Err(e) => denied(format!("symlink: {}", errno_str(&e))),
            }
        }
        "hardlink" => {
            let (s, d) = (rest.first().unwrap_or_else(|| usage()), rest.get(1).unwrap_or_else(|| usage()));
            match std::fs::hard_link(s, d) {
                Ok(()) => allowed(format!("hardlink {d} -> {s}")),
                Err(e) => denied(format!("hardlink: {}", errno_str(&e))),
            }
        }
        "read-when-exists" => {
            let p = rest.first().unwrap_or_else(|| usage());
            let secs: u64 = rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
            let deadline = std::time::Instant::now() + Duration::from_secs(secs);
            while std::time::Instant::now() < deadline {
                if std::fs::symlink_metadata(p).is_ok() {
                    match std::fs::read(p) {
                        Ok(_) => allowed(format!("read {p} created after start")),
                        Err(e) => denied(format!("exists but unreadable: {}", errno_str(&e))),
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            inconclusive(format!("{p} never became visible"))
        }
        "env-has" => {
            let needle = rest.first().unwrap_or_else(|| usage());
            match std::env::vars().find(|(k, v)| k.contains(needle.as_str()) || v.contains(needle.as_str())) {
                Some((k, _)) => allowed(format!("found in {k}")),
                None => denied("not in environment"),
            }
        }
        "env-scan" => {
            // Canary scan over env, argv and (Linux) every visible /proc/*/environ and cmdline.
            // The canary arrives hex-encoded so this probe's own argv does not contain it.
            let needle = hex::decode(rest.first().unwrap_or_else(|| usage())).unwrap_or_else(|_| usage());
            let hit = |b: &[u8]| b.windows(needle.len()).any(|w| w == needle.as_slice());
            for (k, v) in std::env::vars() {
                if hit(k.as_bytes()) || hit(v.as_bytes()) {
                    allowed(format!("canary in env var {k}"));
                }
            }
            if let Ok(rd) = std::fs::read_dir("/proc") {
                for e in rd.flatten() {
                    for f in ["environ", "cmdline"] {
                        if let Ok(b) = std::fs::read(e.path().join(f))
                            && hit(&b)
                        {
                            allowed(format!("canary in {}", e.path().join(f).display()));
                        }
                    }
                }
            }
            denied("canary not visible")
        }
        "ptrace" => {
            #[cfg(target_os = "linux")]
            {
                let pid: i32 = rest.first().and_then(|p| p.parse().ok()).unwrap_or(1);
                // SAFETY: plain ptrace attach attempt.
                let r = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) };
                if r == 0 {
                    allowed(format!("attached to {pid}"));
                }
                denied(format!("ptrace: {}", errno_str(&std::io::Error::last_os_error())));
            }
            #[cfg(not(target_os = "linux"))]
            inconclusive("ptrace probe is Linux-only")
        }
        "exec" => {
            // exec <program> [args]: succeed iff the program ran and exited 0.
            let prog = rest.first().unwrap_or_else(|| usage());
            match std::process::Command::new(prog).args(&rest[1..]).status() {
                Ok(s) if s.success() => allowed(format!("{prog} exited 0")),
                Ok(s) => denied(format!("{prog} exited {s}")),
                Err(e) => denied(format!("{prog}: {}", errno_str(&e))),
            }
        }
        _ => usage(),
    }
}
