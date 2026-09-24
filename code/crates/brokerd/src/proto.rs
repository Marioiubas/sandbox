//! The control protocol on `ctl.sock`: newline-delimited JSON-RPC 2.0.
//!
//! `ctl.sock` is per user (mode 0600 in a 0700 directory, peer UID checked)
//! and unreachable from every sandbox (seccomp forbids new AF_UNIX sockets
//! on Linux; the Seatbelt profile allows no Unix-socket connects and masks
//! the broker directories). The data plane is a separate channel.
//!
//! `session.start` carries the agent's stdin/stdout/stderr as `SCM_RIGHTS`
//! file descriptors in the same `sendmsg` as the request line.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

pub const MAX_LINE: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl Request {
    pub fn new(id: Option<u64>, method: &str, params: Value) -> Self {
        Request { jsonrpc: "2.0".into(), id: id.map(Value::from), method: method.into(), params }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// Either a response (has `id`) or a notification (has `method`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Incoming {
    #[serde(default)]
    pub id: Option<Value>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub params: Option<Value>,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<RpcError>,
}

pub mod codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    /// Launch refused: a layer, the proxy, the policy or the audit log is not ready (I2).
    pub const LAUNCH_REFUSED: i64 = -32001;
    pub const NOT_FOUND: i64 = -32004;
    pub const BUSY: i64 = -32005;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartParams {
    pub argv: Vec<String>,
    pub cwd: String,
    #[serde(default)]
    pub profile: Option<String>,
    /// The client's non-secret environment (filtered again by brokerd).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StartResult {
    pub session_id: String,
    pub backend: String,
    pub profile: String,
    pub egress: String,
    pub grants: Vec<String>,
    pub layers: Vec<launcher::LayerStatus>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Exited {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

/// Send one line plus file descriptors in a single `sendmsg`.
pub fn send_with_fds(sock: &impl AsRawFd, line: &[u8], fds: &[RawFd]) -> std::io::Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    let iov = [IoSlice::new(line)];
    let cmsg = [ControlMessage::ScmRights(fds)];
    let n = sendmsg::<()>(sock.as_raw_fd(), &iov, if fds.is_empty() { &[] } else { &cmsg }, MsgFlags::empty(), None)
        .map_err(std::io::Error::from)?;
    if n < line.len() {
        // The fds went with the first chunk; send the rest plainly.
        let rest = &line[n..];
        let mut off = 0;
        while off < rest.len() {
            let k = nix::sys::socket::send(sock.as_raw_fd(), &rest[off..], MsgFlags::empty())
                .map_err(std::io::Error::from)?;
            off += k;
        }
    }
    Ok(())
}

/// One `recvmsg`: returns bytes read and any file descriptors received
/// (with close-on-exec set).
pub fn recv_with_fds(fd: RawFd, buf: &mut [u8]) -> std::io::Result<(usize, Vec<OwnedFd>)> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    let mut cmsg = nix::cmsg_space!([RawFd; 8]);
    let mut iov = [IoSliceMut::new(buf)];
    let msg = recvmsg::<()>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty()).map_err(std::io::Error::from)?;
    let mut fds = Vec::new();
    for c in msg.cmsgs().map_err(std::io::Error::from)? {
        if let ControlMessageOwned::ScmRights(v) = c {
            for raw in v {
                // SAFETY: the kernel just installed this descriptor for us.
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
                fds.push(owned);
            }
        }
    }
    let n = msg.bytes;
    Ok((n, fds))
}

pub fn to_line<T: Serialize>(v: &T) -> Vec<u8> {
    let mut l = serde_json::to_vec(v).expect("serialisable");
    l.push(b'\n');
    l
}

pub fn ok(id: Value, result: impl Serialize) -> Response {
    Response {
        jsonrpc: "2.0".into(),
        id,
        result: Some(serde_json::to_value(result).unwrap_or(Value::Null)),
        error: None,
    }
}

pub fn err(id: Value, code: i64, message: impl Into<String>, data: Option<Value>) -> Response {
    Response { jsonrpc: "2.0".into(), id, result: None, error: Some(RpcError { code, message: message.into(), data }) }
}

pub fn notification(method: &str, params: impl Serialize) -> Value {
    serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn fds_travel_with_the_line() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, w) = UnixStream::pair().unwrap();
        let line = to_line(&Request::new(Some(1), "session.start", serde_json::json!({"argv": ["x"]})));
        send_with_fds(&a, &line, &[r.as_raw_fd(), w.as_raw_fd(), 2]).unwrap();
        let mut buf = vec![0u8; 4096];
        let (n, fds) = recv_with_fds(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..n], &line[..]);
        assert_eq!(fds.len(), 3);
        let req: Request = serde_json::from_slice(&buf[..n - 1]).unwrap();
        assert_eq!(req.method, "session.start");
    }
}
