//! SOCKS5 (RFC 1928) with username/password auth (RFC 1929), parsed strictly.
//!
//! Only the CONNECT command is supported. Domain names are passed to the
//! canonicaliser as raw bytes (the srt NUL-byte bypass came through SOCKS5);
//! binary addresses become canonical hosts through the same rules as text.

use audit::Reason;

pub const VER: u8 = 0x05;
pub const AUTH_NONE: u8 = 0x00;
pub const AUTH_USERPASS: u8 = 0x02;
pub const AUTH_NO_ACCEPTABLE: u8 = 0xff;

pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed<T> {
    Incomplete,
    Done(T, usize),
    Reject(Reason),
}

/// Client greeting: returns the offered methods.
pub fn parse_greeting(b: &[u8]) -> Parsed<Vec<u8>> {
    match b {
        [] | [_] => Parsed::Incomplete,
        [v, ..] if *v == 0x04 => Parsed::Reject(Reason::Socks4Refused),
        [v, ..] if *v != VER => Parsed::Reject(Reason::MalformedRequest),
        [_, 0, ..] => Parsed::Reject(Reason::MalformedRequest),
        [_, n, rest @ ..] => {
            let n = *n as usize;
            if rest.len() < n { Parsed::Incomplete } else { Parsed::Done(rest[..n].to_vec(), 2 + n) }
        }
    }
}

/// RFC 1929 sub-negotiation: returns (username, password).
pub fn parse_userpass(b: &[u8]) -> Parsed<(Vec<u8>, Vec<u8>)> {
    if b.is_empty() {
        return Parsed::Incomplete;
    }
    if b[0] != 0x01 {
        return Parsed::Reject(Reason::MalformedRequest);
    }
    let Some(&ulen) = b.get(1) else { return Parsed::Incomplete };
    let ulen = ulen as usize;
    if ulen == 0 {
        return Parsed::Reject(Reason::MalformedRequest);
    }
    if b.len() < 2 + ulen + 1 {
        return Parsed::Incomplete;
    }
    let user = b[2..2 + ulen].to_vec();
    let plen = b[2 + ulen] as usize;
    if plen == 0 {
        return Parsed::Reject(Reason::MalformedRequest);
    }
    let start = 3 + ulen;
    if b.len() < start + plen {
        return Parsed::Incomplete;
    }
    Parsed::Done((user, b[start..start + plen].to_vec()), start + plen)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Addr {
    /// Raw domain bytes for the canonicaliser.
    Domain(Vec<u8>),
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub addr: Addr,
    pub port: u16,
}

/// CONNECT request. BIND and UDP ASSOCIATE are refused.
pub fn parse_request(b: &[u8]) -> Parsed<Request> {
    if b.len() < 4 {
        return Parsed::Incomplete;
    }
    if b[0] != VER || b[2] != 0x00 {
        return Parsed::Reject(Reason::MalformedRequest);
    }
    match b[1] {
        0x01 => {}
        0x02 | 0x03 => return Parsed::Reject(Reason::SocksCommandUnsupported),
        _ => return Parsed::Reject(Reason::MalformedRequest),
    }
    let (addr, off) = match b[3] {
        0x01 => {
            if b.len() < 4 + 4 + 2 {
                return Parsed::Incomplete;
            }
            (Addr::V4(b[4..8].try_into().expect("len checked")), 8)
        }
        0x03 => {
            let Some(&len) = b.get(4) else { return Parsed::Incomplete };
            let len = len as usize;
            if len == 0 {
                return Parsed::Reject(Reason::EmptyHost);
            }
            if b.len() < 5 + len + 2 {
                return Parsed::Incomplete;
            }
            (Addr::Domain(b[5..5 + len].to_vec()), 5 + len)
        }
        0x04 => {
            if b.len() < 4 + 16 + 2 {
                return Parsed::Incomplete;
            }
            (Addr::V6(b[4..20].try_into().expect("len checked")), 20)
        }
        _ => return Parsed::Reject(Reason::MalformedRequest),
    };
    let port = u16::from_be_bytes([b[off], b[off + 1]]);
    if port == 0 {
        return Parsed::Reject(Reason::MalformedRequest);
    }
    Parsed::Done(Request { addr, port }, off + 2)
}

/// A reply with BND.ADDR 0.0.0.0:0.
pub fn reply(rep: u8) -> [u8; 10] {
    [VER, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// Map a deny reason to the closest SOCKS5 reply code.
pub fn reply_for(reason: Reason) -> u8 {
    match reason {
        Reason::SocksCommandUnsupported => REP_CMD_NOT_SUPPORTED,
        Reason::ResolveFailed | Reason::NoAddresses | Reason::UpstreamConnectFailed => REP_HOST_UNREACHABLE,
        Reason::MalformedRequest => REP_GENERAL_FAILURE,
        _ => REP_NOT_ALLOWED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting() {
        assert_eq!(parse_greeting(&[5, 2, 0, 2]), Parsed::Done(vec![0, 2], 4));
        assert_eq!(parse_greeting(&[5, 2, 0]), Parsed::Incomplete);
        assert_eq!(parse_greeting(&[4, 1, 0, 80]), Parsed::Reject(Reason::Socks4Refused));
        assert_eq!(parse_greeting(&[5, 0]), Parsed::Reject(Reason::MalformedRequest));
    }

    #[test]
    fn userpass() {
        let mut b = vec![1, 6];
        b.extend(b"broker");
        b.push(3);
        b.extend(b"abc");
        assert_eq!(parse_userpass(&b), Parsed::Done((b"broker".to_vec(), b"abc".to_vec()), b.len()));
        assert_eq!(parse_userpass(&b[..5]), Parsed::Incomplete);
        assert_eq!(parse_userpass(&[1, 0, 0]), Parsed::Reject(Reason::MalformedRequest));
    }

    #[test]
    fn requests() {
        let mut d = vec![5, 1, 0, 3, 11];
        d.extend(b"example.com");
        d.extend([1, 187]);
        assert_eq!(
            parse_request(&d),
            Parsed::Done(Request { addr: Addr::Domain(b"example.com".to_vec()), port: 443 }, d.len())
        );
        let v4 = [5, 1, 0, 1, 169, 254, 169, 254, 0, 80];
        assert_eq!(parse_request(&v4), Parsed::Done(Request { addr: Addr::V4([169, 254, 169, 254]), port: 80 }, 10));
        assert_eq!(parse_request(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]), Parsed::Reject(Reason::SocksCommandUnsupported));
        assert_eq!(parse_request(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 1]), Parsed::Reject(Reason::SocksCommandUnsupported));
        assert_eq!(parse_request(&[5, 1, 1, 1, 0, 0, 0, 0, 0, 1]), Parsed::Reject(Reason::MalformedRequest));
        assert_eq!(parse_request(&[5, 1, 0, 3, 0, 0, 1]), Parsed::Reject(Reason::EmptyHost));
        assert_eq!(parse_request(&[5, 1, 0, 9, 0]), Parsed::Reject(Reason::MalformedRequest));
        // NUL-byte domain is carried raw to the canonicaliser.
        let mut n = vec![5, 1, 0, 3, 28];
        n.extend(b"attacker.example\x00.google.com");
        n.extend([1, 187]);
        match parse_request(&n) {
            Parsed::Done(Request { addr: Addr::Domain(d), .. }, _) => assert!(d.contains(&0)),
            other => panic!("{other:?}"),
        }
    }
}
