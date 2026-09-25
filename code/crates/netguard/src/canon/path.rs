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

/// Characters that compatibility normalisation (NFKC) turns into `.`, and
/// into `/` or `\`: a server that normalises would see a dot segment or a
/// separator the broker did not.
const DOT_LIKE: &[char] = &['\u{FF0E}', '\u{FE52}', '\u{2024}'];
const SLASH_LIKE: &[char] = &['\u{FF0F}', '\u{FF3C}', '\u{2215}', '\u{2216}', '\u{2044}', '\u{FE68}', '\u{29F5}'];

fn pct_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            out.push((hex_val(*b.get(i + 1)?)? << 4) | hex_val(*b.get(i + 2)?)?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(out)
}

/// A segment must stay a plain segment however many times (up to three) a
/// server percent-decodes it: no dot segment, also behind `;params` or an
/// escape (Tomcat's `..;/`), no separator, no look-alike of either, and
/// valid UTF-8 (no overlong `C0 AE`). Found by the category 8 differential
/// test (conformance `m4_differential`).
fn segment_check(seg: &str) -> Result<(), Reject> {
    let mut cur = seg.to_string();
    for level in 0..3 {
        if level > 0 && (cur.contains('/') || cur.contains('\\')) {
            return Err(Reject::EncodedSeparator);
        }
        if cur.chars().any(|c| SLASH_LIKE.contains(&c)) {
            return Err(Reject::EncodedSeparator);
        }
        let mapped: String = cur.chars().map(|c| if DOT_LIKE.contains(&c) { '.' } else { c }).collect();
        let head = mapped.split([';', '%']).next().unwrap_or("");
        if head == "." || head == ".." {
            return Err(Reject::DotSegment);
        }
        if !cur.contains('%') {
            break;
        }
        let Some(next) = pct_decode(&cur) else { break };
        cur = String::from_utf8(next).map_err(|_| Reject::NonCanonicalPath)?;
    }
    Ok(())
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
        segment_check(seg)?;
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
