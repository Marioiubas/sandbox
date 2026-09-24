//! The single canonicaliser (I6).
//!
//! Every hostname from any source (CONNECT authority, SOCKS5 domain, TLS SNI,
//! and later `Host`, `:authority`, redirect `Location`, git remotes, MCP URLs,
//! policy patterns) becomes a policy-visible value only through
//! [`canon_host`]; HTTP paths only through [`canon_path`]. Both are pure,
//! reject rather than guess, and never call a resolver. [`CanonicalHost`] and
//! [`CanonicalPath`] have private fields, so no other code can mint one.
//!
//! Rejections map to [`audit::Reason`] so every deny is logged with a reason.

use audit::Reason;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why input could not be canonicalised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Empty,
    TooLong,
    ForbiddenByte(u8),
    TrailingDot,
    BadLabel,
    MixedIdna,
    IdnaRoundTrip,
    AmbiguousIpLiteral,
    MappedV6,
    NonCanonicalPath,
    EncodedSeparator,
    DotSegment,
}

impl Reject {
    pub fn reason(&self) -> Reason {
        match self {
            Reject::Empty => Reason::EmptyHost,
            Reject::TooLong => Reason::HostTooLong,
            Reject::ForbiddenByte(_) => Reason::ForbiddenByte,
            Reject::TrailingDot => Reason::TrailingDot,
            Reject::BadLabel => Reason::BadLabel,
            Reject::MixedIdna => Reason::MixedIdna,
            Reject::IdnaRoundTrip => Reason::IdnaRoundTrip,
            Reject::AmbiguousIpLiteral => Reason::AmbiguousIpLiteral,
            Reject::MappedV6 => Reason::MappedV6,
            Reject::NonCanonicalPath => Reason::NonCanonicalPath,
            Reject::EncodedSeparator => Reason::EncodedSeparator,
            Reject::DotSegment => Reason::DotSegment,
        }
    }
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reject::ForbiddenByte(b) => write!(f, "forbidden_byte(0x{b:02x})"),
            other => f.write_str(other.reason().as_str()),
        }
    }
}

impl std::error::Error for Reject {}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum HostKind {
    /// A DNS name in lowercase LDH A-label form.
    Name {
        registrable: String,
    },
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

/// A hostname in its one canonical form. Only this module constructs it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalHost {
    /// Names: lowercase A-labels. V4: dotted quad. V6: RFC 5952 text in brackets.
    ascii: String,
    kind: HostKind,
}

impl CanonicalHost {
    /// The canonical text, as it appears in an authority (`[..]` for IPv6).
    pub fn as_str(&self) -> &str {
        &self.ascii
    }

    pub fn kind(&self) -> &HostKind {
        &self.kind
    }

    pub fn is_ip_literal(&self) -> bool {
        !matches!(self.kind, HostKind::Name { .. })
    }

    /// The literal address for IP hosts.
    pub fn ip(&self) -> Option<IpAddr> {
        match self.kind {
            HostKind::V4(a) => Some(IpAddr::V4(a)),
            HostKind::V6(a) => Some(IpAddr::V6(a)),
            HostKind::Name { .. } => None,
        }
    }

    /// The registrable domain (eTLD+1) for names; the name itself when it is
    /// a public suffix or single label.
    pub fn registrable(&self) -> Option<&str> {
        match &self.kind {
            HostKind::Name { registrable } => Some(registrable),
            _ => None,
        }
    }

    /// Canonical host for an address received in binary form (SOCKS5 ATYP 1
    /// or 4). Mapped and compatible IPv6 forms are rejected exactly as their
    /// text forms are, so every ingress mode decides alike.
    pub fn from_ip(ip: IpAddr) -> Result<CanonicalHost, Reject> {
        match ip {
            IpAddr::V4(a) => Ok(CanonicalHost { ascii: a.to_string(), kind: HostKind::V4(a) }),
            IpAddr::V6(a) => {
                if is_mapped_or_compatible(&a) {
                    return Err(Reject::MappedV6);
                }
                Ok(CanonicalHost { ascii: format!("[{a}]"), kind: HostKind::V6(a) })
            }
        }
    }
}

impl fmt::Display for CanonicalHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.ascii)
    }
}

impl fmt::Debug for CanonicalHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanonicalHost({})", self.ascii)
    }
}

const MAX_HOST: usize = 253;
const MAX_LABEL: usize = 63;

/// Bytes rejected anywhere in a hostname. The report lists NUL, CR/LF and `%`;
/// the rest block userinfo, path and fragment confusion. Every control byte
/// and DEL is also rejected. `[`, `]` and `:` are only valid as the IPv6
/// bracket syntax, handled before this check.
fn forbidden_host_byte(b: u8) -> bool {
    b < 0x21 || b == 0x7f || matches!(b, b'%' | b'\\' | b'/' | b'@' | b'?' | b'#' | b':' | b'[' | b']' | b'*')
}

fn is_mapped_or_compatible(a: &Ipv6Addr) -> bool {
    if a.to_ipv4_mapped().is_some() {
        return true;
    }
    // Deprecated IPv4-compatible ::a.b.c.d (first 96 bits zero), except :: and ::1.
    let seg = a.segments();
    seg[..6].iter().all(|s| *s == 0) && !(seg[6] == 0 && seg[7] <= 1)
}

/// Canonicalise untrusted host bytes.
pub fn canon_host(raw: &[u8]) -> Result<CanonicalHost, Reject> {
    if raw.is_empty() {
        return Err(Reject::Empty);
    }
    if raw.len() > MAX_HOST + 2 {
        return Err(Reject::TooLong);
    }
    // Bracketed IPv6 literal.
    if raw[0] == b'[' {
        let inner = raw.strip_prefix(b"[").and_then(|r| r.strip_suffix(b"]")).ok_or(Reject::ForbiddenByte(b'['))?;
        if let Some(&b) = inner.iter().find(|&&b| !(b.is_ascii_hexdigit() || b == b':' || b == b'.')) {
            return Err(Reject::ForbiddenByte(b));
        }
        let text = std::str::from_utf8(inner).map_err(|_| Reject::AmbiguousIpLiteral)?;
        let a: Ipv6Addr = text.parse().map_err(|_| Reject::AmbiguousIpLiteral)?;
        return CanonicalHost::from_ip(IpAddr::V6(a));
    }
    if raw.len() > MAX_HOST {
        return Err(Reject::TooLong);
    }
    if let Some(&b) = raw.iter().find(|&&b| b < 0x80 && forbidden_host_byte(b)) {
        return Err(Reject::ForbiddenByte(b));
    }
    if raw.last() == Some(&b'.') {
        return Err(Reject::TrailingDot);
    }
    let ascii = if raw.is_ascii() { ascii_name(raw)? } else { unicode_name(raw)? };
    // IP literal detection on the ASCII form (WHATWG "ends in a number").
    if let Some(v4) = ipv4_literal(&ascii)? {
        return Ok(CanonicalHost { ascii: v4.to_string(), kind: HostKind::V4(v4) });
    }
    check_ldh(&ascii)?;
    let registrable = psl::domain_str(&ascii).unwrap_or(&ascii).to_string();
    Ok(CanonicalHost { ascii, kind: HostKind::Name { registrable } })
}

/// ASCII input: lowercase, and require any `xn--` label to round-trip.
fn ascii_name(raw: &[u8]) -> Result<String, Reject> {
    let lower = String::from_utf8(raw.to_ascii_lowercase()).map_err(|_| Reject::BadLabel)?;
    if lower.split('.').any(|l| l.starts_with("xn--")) {
        let uts46 = idna::uts46::Uts46::new();
        let (unicode, res) =
            uts46.to_unicode(lower.as_bytes(), idna::uts46::AsciiDenyList::STD3, idna::uts46::Hyphens::CheckFirstLast);
        res.map_err(|_| Reject::IdnaRoundTrip)?;
        let again = to_ascii(unicode.as_bytes()).map_err(|_| Reject::IdnaRoundTrip)?;
        if again != lower {
            return Err(Reject::IdnaRoundTrip);
        }
    }
    Ok(lower)
}

/// Non-ASCII input: one UTS 46 mapping to A-labels. Input that already mixes
/// in `xn--` labels, or uses non-ASCII label separators, is ambiguous.
fn unicode_name(raw: &[u8]) -> Result<String, Reject> {
    let text = std::str::from_utf8(raw).map_err(|_| Reject::BadLabel)?;
    if text.chars().any(|c| matches!(c, '\u{3002}' | '\u{FF0E}' | '\u{FF61}')) {
        return Err(Reject::BadLabel);
    }
    if text.split('.').any(|l| l.to_ascii_lowercase().starts_with("xn--")) {
        return Err(Reject::MixedIdna);
    }
    let ascii = to_ascii(raw).map_err(|_| Reject::BadLabel)?;
    if ascii.len() > MAX_HOST {
        return Err(Reject::TooLong);
    }
    Ok(ascii)
}

fn to_ascii(bytes: &[u8]) -> Result<String, ()> {
    idna::uts46::Uts46::new()
        .to_ascii(
            bytes,
            idna::uts46::AsciiDenyList::STD3,
            idna::uts46::Hyphens::CheckFirstLast,
            idna::uts46::DnsLength::Verify,
        )
        .map(|c| c.into_owned())
        .map_err(|_| ())
}

fn is_numberish(label: &str) -> bool {
    !label.is_empty()
        && (label.bytes().all(|b| b.is_ascii_digit())
            || ((label.starts_with("0x") || label.starts_with("0X"))
                && label[2..].bytes().all(|b| b.is_ascii_hexdigit())))
}

/// Strict dotted-quad or nothing. If the last label looks like a number, the
/// host must be exactly four decimal octets without leading zeros; every other
/// numeric form (decimal integer, hex, octal, short forms) is ambiguous across
/// parsers and rejected.
fn ipv4_literal(ascii: &str) -> Result<Option<Ipv4Addr>, Reject> {
    let labels: Vec<&str> = ascii.split('.').collect();
    let last = labels.last().copied().unwrap_or("");
    if !is_numberish(last) {
        return Ok(None);
    }
    if labels.len() != 4 {
        return Err(Reject::AmbiguousIpLiteral);
    }
    let mut octets = [0u8; 4];
    for (i, l) in labels.iter().enumerate() {
        let strict = !l.is_empty()
            && l.len() <= 3
            && l.bytes().all(|b| b.is_ascii_digit())
            && !(l.len() > 1 && l.starts_with('0'));
        if !strict {
            return Err(Reject::AmbiguousIpLiteral);
        }
        octets[i] = l.parse::<u8>().map_err(|_| Reject::AmbiguousIpLiteral)?;
    }
    Ok(Some(Ipv4Addr::from(octets)))
}

fn check_ldh(ascii: &str) -> Result<(), Reject> {
    if ascii.is_empty() {
        return Err(Reject::Empty);
    }
    if ascii.len() > MAX_HOST {
        return Err(Reject::TooLong);
    }
    for label in ascii.split('.') {
        let ok = !label.is_empty()
            && label.len() <= MAX_LABEL
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err(Reject::BadLabel);
        }
    }
    Ok(())
}

mod addr;
mod path;
mod pattern;

pub use addr::{AddrClass, classify_addr};
pub use path::{CanonicalPath, canon_path};
pub use pattern::{HostPattern, PatternError};

#[cfg(test)]
mod props;
#[cfg(test)]
mod tests;
