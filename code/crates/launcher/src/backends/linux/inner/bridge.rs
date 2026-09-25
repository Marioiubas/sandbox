//! The in-namespace bridge from the loopback proxy port to the broker's
//! data socket (the sandbox has no network interface of its own).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Bind in this process (so the port is ready before the agent starts),
/// then double-fork so the bridge is reparented to the namespace's init
/// and never shows up in the agent's wait().
pub fn start(port: u16, sock: &Path) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    // SAFETY: single-threaded at this point (the shim has not started threads).
    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
        0 => {
            // SAFETY: fork in the intermediate child.
            match unsafe { libc::fork() } {
                0 => {
                    // Non-dumpable: the agent (same uid) cannot read our memory via /proc.
                    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
                    serve(listener, sock);
                    unsafe { libc::_exit(0) };
                }
                _ => unsafe { libc::_exit(0) },
            }
        }
        pid => {
            let mut st = 0;
            // SAFETY: reap the intermediate child.
            unsafe { libc::waitpid(pid, &mut st, 0) };
            drop(listener);
            Ok(())
        }
    }
}

fn copy(mut from: impl Read, mut to: impl Write) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

fn serve(listener: TcpListener, sock: &Path) {
    for conn in listener.incoming() {
        let Ok(tcp) = conn else { continue };
        // Relay writes at once: with Nagle, a small write after another
        // (the CONNECT reply, then the TLS handshake) waits for the client's
        // delayed ACK, adding tens of milliseconds to every new connection.
        let _ = tcp.set_nodelay(true);
        let sock = sock.to_path_buf();
        std::thread::spawn(move || {
            let Ok(uds) = UnixStream::connect(&sock) else { return };
            let (Ok(tcp_r), Ok(uds_r)) = (tcp.try_clone(), uds.try_clone()) else { return };
            let up = std::thread::spawn(move || {
                copy(tcp_r, &uds);
                let _ = uds.shutdown(Shutdown::Write);
            });
            copy(uds_r, &tcp);
            let _ = tcp.shutdown(Shutdown::Write);
            let _ = up.join();
        });
    }
    unsafe { libc::_exit(0) }
}
