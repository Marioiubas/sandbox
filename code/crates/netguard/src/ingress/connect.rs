//! Strict HTTP CONNECT request-head parser.
//!
//! Accepts exactly `CONNECT <authority> HTTP/1.x\r\n` followed by header
//! lines and an empty line, all CRLF-terminated. The authority host bytes are
//! returned raw for the canonicaliser; nothing here interprets them.

use audit::Reason;

pub const MAX_HEAD: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct ConnectRequest {
    /// Host bytes exactly as sent (brackets kept for IPv6).
    pub host: Vec<u8>,
    pub port: u16,
    /// Raw `Proxy-Authorization` value, if present (consumed, never forwarded).
    pub proxy_authorization: Option<Vec<u8>>,
    /// Bytes after the head (for example an early ClientHello).
    pub leftover: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseOutcome {
    /// Need more bytes; call again with a longer buffer.
    Incomplete,
    Done(ConnectRequest),
    Reject(Reason),
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Parse a decimal port: 1-5 digits, no sign, no leading zero, 1..=65535.
pub fn parse_port(s: &[u8]) -> Option<u16> {
    if s.is_empty() || s.len() > 5 || !s.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s[0] == b'0' {
        return None;
    }
    let v: u32 = std::str::from_utf8(s).ok()?.parse().ok()?;
    if v == 0 || v > 65535 { None } else { Some(v as u16) }
}

/// Split `host:port`, keeping IPv6 brackets on the host.
pub fn split_authority(a: &[u8]) -> Option<(&[u8], u16)> {
    if a.first() == Some(&b'[') {
        let close = a.iter().position(|&b| b == b']')?;
        let (host, rest) = a.split_at(close + 1);
        let port = rest.strip_prefix(b":")?;
        return Some((host, parse_port(port)?));
    }
    let colon = a.iter().rposition(|&b| b == b':')?;
    let (host, rest) = a.split_at(colon);
    Some((host, parse_port(&rest[1..])?))
}

pub fn parse(buf: &[u8]) -> ParseOutcome {
    let Some(end) = find_head_end(buf) else {
        if buf.len() >= MAX_HEAD {
            return ParseOutcome::Reject(Reason::MalformedRequest);
        }
        // Early classification of obvious non-CONNECT methods.
        if let Some(sp) = buf.iter().position(|&b| b == b' ') {
            let method = &buf[..sp];
            if method != b"CONNECT" && !method.is_empty() && method.iter().all(|&b| is_tchar(b)) {
                return ParseOutcome::Reject(Reason::PlainHttpUnsupported);
            }
        }
        return ParseOutcome::Incomplete;
    };
    if end + 4 > MAX_HEAD {
        return ParseOutcome::Reject(Reason::MalformedRequest);
    }
    let head = &buf[..end];
    let leftover = buf[end + 4..].to_vec();
    // Bare LF or CR anywhere other than CRLF pairs is a framing ambiguity.
    for (i, &b) in head.iter().enumerate() {
        if b == b'\n' && (i == 0 || head[i - 1] != b'\r') {
            return ParseOutcome::Reject(Reason::MalformedRequest);
        }
        if b == b'\r' && head.get(i + 1) != Some(&b'\n') {
            return ParseOutcome::Reject(Reason::MalformedRequest);
        }
    }
    // A NUL in the authority is left for the canonicaliser, so the same
    // destination bytes get the same reason through every ingress mode;
    // header names and values are checked below.
    let mut lines = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let Some(request_line) = lines.next() else {
        return ParseOutcome::Reject(Reason::MalformedRequest);
    };
    let parts: Vec<&[u8]> = request_line.split(|&b| b == b' ').collect();
    if parts.len() != 3 {
        return ParseOutcome::Reject(Reason::MalformedRequest);
    }
    let (method, target, version) = (parts[0], parts[1], parts[2]);
    if method != b"CONNECT" {
        if !method.is_empty() && method.iter().all(|&b| is_tchar(b)) {
            return ParseOutcome::Reject(Reason::PlainHttpUnsupported);
        }
        return ParseOutcome::Reject(Reason::MalformedRequest);
    }
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return ParseOutcome::Reject(Reason::MalformedRequest);
    }
    let Some((host, port)) = split_authority(target) else {
        return ParseOutcome::Reject(Reason::MalformedRequest);
    };
    let mut proxy_authorization = None;
    for line in lines {
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            return ParseOutcome::Reject(Reason::MalformedRequest); // obs-fold
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return ParseOutcome::Reject(Reason::MalformedRequest);
        };
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return ParseOutcome::Reject(Reason::MalformedRequest);
        }
        let value = trim_ows(&line[colon + 1..]);
        if value.iter().any(|&b| b < 0x20 && b != b'\t' || b == 0x7f) {
            return ParseOutcome::Reject(Reason::MalformedRequest);
        }
        if name.eq_ignore_ascii_case(b"proxy-authorization") {
            if proxy_authorization.is_some() {
                return ParseOutcome::Reject(Reason::MalformedRequest);
            }
            proxy_authorization = Some(value.to_vec());
        }
    }
    ParseOutcome::Done(ConnectRequest { host: host.to_vec(), port, proxy_authorization, leftover })
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

/// Extract the password from `Basic base64(user:password)`.
pub fn basic_password(value: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine;
    let rest = value.strip_prefix(b"Basic ").or_else(|| value.strip_prefix(b"basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(rest).ok()?;
    let colon = decoded.iter().position(|&b| b == b':')?;
    Some(decoded[colon + 1..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(b: &[u8]) -> ConnectRequest {
        match parse(b) {
            ParseOutcome::Done(r) => r,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn basic_connect() {
        let r = done(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n");
        assert_eq!(r.host, b"api.github.com");
        assert_eq!(r.port, 443);
        assert!(r.leftover.is_empty());
    }

    #[test]
    fn ipv6_and_leftover_and_auth() {
        let r =
            done(b"CONNECT [::1]:8443 HTTP/1.0\r\nProxy-Authorization: Basic YnJva2VyOnNlY3JldA==\r\n\r\n\x16\x03\x01");
        assert_eq!(r.host, b"[::1]");
        assert_eq!(r.port, 8443);
        assert_eq!(r.leftover, b"\x16\x03\x01");
        assert_eq!(basic_password(r.proxy_authorization.as_ref().unwrap()).unwrap(), b"secret");
    }

    #[test]
    fn incomplete_then_reject_oversize() {
        assert_eq!(parse(b"CONNECT a.b:443 HTTP/1.1\r\n"), ParseOutcome::Incomplete);
        let big = vec![b'a'; MAX_HEAD];
        let mut v = b"CONNECT ".to_vec();
        v.extend(big);
        assert_eq!(parse(&v), ParseOutcome::Reject(Reason::MalformedRequest));
    }

    #[test]
    fn strictness() {
        let r = |b: &[u8]| parse(b);
        assert_eq!(r(b"GET http://x/ HTTP/1.1\r\n\r\n"), ParseOutcome::Reject(Reason::PlainHttpUnsupported));
        assert_eq!(r(b"GET http://x/ HTTP/1.1\r\n"), ParseOutcome::Reject(Reason::PlainHttpUnsupported));
        assert_eq!(r(b"connect a.b:443 HTTP/1.1\r\n\r\n"), ParseOutcome::Reject(Reason::PlainHttpUnsupported));
        assert_eq!(r(b"CONNECT a.b:443 HTTP/1.1\n\n"), ParseOutcome::Incomplete);
        assert_eq!(r(b"CONNECT a.b:443 HTTP/1.1\nX: y\r\n\r\n"), ParseOutcome::Reject(Reason::MalformedRequest));
        assert_eq!(r(b"CONNECT a.b:443  HTTP/1.1\r\n\r\n"), ParseOutcome::Reject(Reason::MalformedRequest));
        assert_eq!(r(b"CONNECT a.b HTTP/1.1\r\n\r\n"), ParseOutcome::Reject(Reason::MalformedRequest));
        assert_eq!(r(b"CONNECT a.b:0443 HTTP/1.1\r\n\r\n"), ParseOutcome::Reject(Reason::MalformedRequest));
        assert_eq!(r(b"CONNECT a.b:65536 HTTP/1.1\r\n\r\n"), ParseOutcome::Reject(Reason::MalformedRequest));
        assert_eq!(r(b"CONNECT a.b:443 HTTP/2\r\n\r\n"), ParseOutcome::Reject(Reason::MalformedRequest));
        assert_eq!(r(b"CONNECT a.b:443 HTTP/1.1\r\n folded\r\n\r\n"), ParseOutcome::Reject(Reason::MalformedRequest));
        assert_eq!(
            r(b"CONNECT a.b:443 HTTP/1.1\r\nProxy-Authorization: a\r\nProxy-Authorization: b\r\n\r\n"),
            ParseOutcome::Reject(Reason::MalformedRequest)
        );
        // NUL inside the authority is not rejected here: the canonicaliser does it.
        let n = done(b"CONNECT evil\x00.google.com:443 HTTP/1.1\r\n\r\n");
        assert_eq!(n.host, b"evil\x00.google.com");
    }
}
