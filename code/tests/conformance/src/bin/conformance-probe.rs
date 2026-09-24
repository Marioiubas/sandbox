//! `conformance-probe`: one deterministic action per invocation, run inside
//! a broker session. No LLM, no shell, no third-party tools.
//!
//! Exit codes: 0 = the action succeeded (reached / read / wrote);
//! 10 = the action was blocked; 20 = inconclusive; 2 = usage error.
//! stdout carries one line: `ALLOWED ...`, `DENIED ...` or `INCONCLUSIVE ...`.

// A binary's modules live beside it in `conformance-probe/` (a directory
// without `main.rs`, so cargo does not treat them as binaries).
#[path = "conformance-probe/fs.rs"]
mod fs;
#[path = "conformance-probe/net.rs"]
mod net;
#[path = "conformance-probe/proxy.rs"]
mod proxy;
#[path = "conformance-probe/secrets.rs"]
mod secrets;

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

/// `\xHH`, `\r`, `\n`, `\t` and `\\` escapes, so NUL, CRLF and other
/// bytes can travel in argv.
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
            let named = match b[i + 1] {
                b'r' => Some(b'\r'),
                b'n' => Some(b'\n'),
                b't' => Some(b'\t'),
                _ => None,
            };
            if let Some(v) = named {
                out.push(v);
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

fn errno_str(e: &std::io::Error) -> String {
    format!("{e} (errno {:?})", e.raw_os_error())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else { usage() };
    let rest = &args[1..];
    match cmd.as_str() {
        "proxy" => proxy::probe_proxy(rest),
        "tls-raw" => proxy::probe_tls_raw(rest),
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
        "tcp" | "udp" | "dns-udp" | "dns-tcp" | "icmp" | "unix" | "unix-socket" => net::run(&cmd, rest),
        "read" | "list" | "write" | "write-new" | "mkdir" | "rename" | "symlink" | "hardlink" | "read-when-exists" => {
            fs::run(&cmd, rest)
        }
        "env-has" | "env-scan" | "secret-scan" => secrets::run(&cmd, rest),
        _ => usage(),
    }
}
