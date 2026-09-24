//! Path canonicalisation (I6), used by the L7 pipeline: the only way to a
//! [`CanonicalPath`].

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalPath {
    path: String,
    query: Option<String>,
}

impl CanonicalPath {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn path_byte_ok(b: u8) -> bool {
    // RFC 3986 pchar minus '%' (handled separately) plus '/'.
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
        )
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Canonicalise an origin-form request target. Percent-escapes of unreserved
/// characters are decoded; other escapes are kept in upper case; encoded
/// `/`, `\`, NUL and `.` are rejected; `.` and `..` segments, empty segments,
/// backslashes and fragments are rejected rather than resolved.
pub fn canon_path(raw: &[u8]) -> Result<CanonicalPath, Reject> {
    if raw.is_empty() {
        return Err(Reject::Empty);
    }
    if raw.len() > 8192 {
        return Err(Reject::TooLong);
    }
    if raw[0] != b'/' {
        return Err(Reject::NonCanonicalPath);
    }
    let (p, q) = match raw.iter().position(|&b| b == b'?') {
        Some(i) => (&raw[..i], Some(&raw[i + 1..])),
        None => (raw, None),
    };
    let mut out = String::with_capacity(p.len());
    let mut i = 0;
    while i < p.len() {
        let b = p[i];
        if b == b'%' {
            let (h, l) = match (p.get(i + 1).copied().and_then(hex_val), p.get(i + 2).copied().and_then(hex_val)) {
                (Some(h), Some(l)) => (h, l),
                _ => return Err(Reject::NonCanonicalPath),
            };
            let v = (h << 4) | l;
            match v {
                b'/' | b'\\' | 0 => return Err(Reject::EncodedSeparator),
                b'.' => return Err(Reject::DotSegment),
                v if is_unreserved(v) => out.push(v as char),
                v => out.push_str(&format!("%{v:02X}")),
            }
            i += 3;
            continue;
        }
        if b == b'\\' {
            return Err(Reject::ForbiddenByte(b));
        }
        if !path_byte_ok(b) {
            return Err(Reject::ForbiddenByte(b));
        }
        out.push(b as char);
        i += 1;
    }
    for (idx, seg) in out.split('/').enumerate().skip(1) {
        if seg == "." || seg == ".." {
            return Err(Reject::DotSegment);
        }
        // An empty segment is only allowed as the trailing slash or the root.
        if seg.is_empty() && idx != out.split('/').count() - 1 {
            return Err(Reject::NonCanonicalPath);
        }
    }
    let query = match q {
        None => None,
        Some(q) => {
            if let Some(&b) = q.iter().find(|&&b| b < 0x21 || b == 0x7f || b == b'#' || b >= 0x80) {
                return Err(Reject::ForbiddenByte(b));
            }
            Some(String::from_utf8(q.to_vec()).map_err(|_| Reject::NonCanonicalPath)?)
        }
    };
    Ok(CanonicalPath { path: out, query })
}
