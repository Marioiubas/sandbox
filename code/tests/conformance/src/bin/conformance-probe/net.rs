//! Network probes: raw TCP, UDP, DNS to a chosen server, ICMP and Unix
//! sockets (each must be blocked inside the sandbox).

use super::*;

pub fn run(cmd: &str, rest: &[String]) -> ! {
    match cmd {
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
        _ => usage(),
    }
}
