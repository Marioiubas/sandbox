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

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// Address classes. Everything but `Public` is denied unless a grant names
/// the class or the literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AddrClass {
    Public,
    Loopback,
    LinkLocal,
    Metadata,
    Private,
    Reserved,
}

impl AddrClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddrClass::Public => "public",
            AddrClass::Loopback => "loopback",
            AddrClass::LinkLocal => "link_local",
            AddrClass::Metadata => "metadata",
            AddrClass::Private => "private",
            AddrClass::Reserved => "reserved",
        }
    }

    pub fn deny_reason(&self) -> Option<Reason> {
        match self {
            AddrClass::Public => None,
            AddrClass::Loopback => Some(Reason::LoopbackAddr),
            AddrClass::LinkLocal => Some(Reason::LinkLocalAddr),
            AddrClass::Metadata => Some(Reason::MetadataAddr),
            AddrClass::Private => Some(Reason::PrivateAddr),
            AddrClass::Reserved => Some(Reason::ReservedAddr),
        }
    }

    pub fn parse(s: &str) -> Option<AddrClass> {
        Some(match s {
            "public" => AddrClass::Public,
            "loopback" => AddrClass::Loopback,
            "link_local" => AddrClass::LinkLocal,
            "metadata" => AddrClass::Metadata,
            "private" => AddrClass::Private,
            "reserved" => AddrClass::Reserved,
            _ => return None,
        })
    }
}

/// Well-known cloud metadata endpoints (AWS/GCP/Azure 169.254.169.254, AWS
/// ECS 169.254.170.2, Alibaba 100.100.100.200, Oracle 192.0.0.192, AWS IMDS
/// IPv6 fd00:ec2::254).
fn is_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            matches!(a.octets(), [169, 254, 169, 254] | [169, 254, 170, 2] | [100, 100, 100, 200] | [192, 0, 0, 192])
        }
        IpAddr::V6(a) => a == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
    }
}

pub fn classify_addr(ip: IpAddr) -> AddrClass {
    if is_metadata(ip) {
        return AddrClass::Metadata;
    }
    match ip {
        IpAddr::V4(a) => classify_v4(a),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return classify_addr(IpAddr::V4(v4));
            }
            let seg = a.segments();
            // NAT64 well-known prefix 64:ff9b::/96 reaches embedded IPv4.
            if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6].iter().all(|s| *s == 0) {
                let v4 = Ipv4Addr::new((seg[6] >> 8) as u8, seg[6] as u8, (seg[7] >> 8) as u8, seg[7] as u8);
                return classify_addr(IpAddr::V4(v4));
            }
            if a.is_loopback() {
                AddrClass::Loopback
            } else if a.is_unspecified() || a.is_multicast() || is_mapped_or_compatible(&a) {
                AddrClass::Reserved
            } else if (seg[0] & 0xffc0) == 0xfe80 {
                AddrClass::LinkLocal
            } else if (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfec0 {
                AddrClass::Private
            } else if seg[0] == 0x2001 && seg[1] == 0x0db8 {
                AddrClass::Reserved
            } else {
                AddrClass::Public
            }
        }
    }
}

fn classify_v4(a: Ipv4Addr) -> AddrClass {
    let o = a.octets();
    if a.is_loopback() {
        AddrClass::Loopback
    } else if a.is_link_local() {
        AddrClass::LinkLocal
    } else if a.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64) {
        AddrClass::Private
    } else if o[0] == 0
        || a.is_multicast()
        || o[0] >= 240
        || a.is_broadcast()
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
    {
        AddrClass::Reserved
    } else {
        AddrClass::Public
    }
}

// ---------------------------------------------------------------------------
// Host patterns (policy side, same canonicaliser)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostPattern {
    /// Exactly this canonical host.
    Exact(CanonicalHost),
    /// Any name with at least one more label under this canonical name
    /// (`*.example.com` matches `a.example.com`, never `example.com`).
    Subdomains(CanonicalHost),
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    #[error("host pattern does not canonicalise: {0}")]
    Canon(Reject),
    #[error("catch-all or bare wildcard patterns are not allowed")]
    CatchAll,
    #[error("wildcard over a public suffix ({0}) is not allowed")]
    PublicSuffixWildcard(String),
    #[error("wildcards apply to names, not IP literals")]
    IpWildcard,
}

impl HostPattern {
    /// Compile a policy host string with the same canonicaliser used at
    /// runtime, so policy text and runtime values agree by construction.
    pub fn parse(s: &str) -> Result<HostPattern, PatternError> {
        if let Some(rest) = s.strip_prefix("*.") {
            if rest.is_empty() || rest.contains('*') {
                return Err(PatternError::CatchAll);
            }
            let base = canon_host(rest.as_bytes()).map_err(PatternError::Canon)?;
            if base.is_ip_literal() {
                return Err(PatternError::IpWildcard);
            }
            if psl::suffix_str(base.as_str()) == Some(base.as_str()) {
                return Err(PatternError::PublicSuffixWildcard(base.as_str().to_string()));
            }
            return Ok(HostPattern::Subdomains(base));
        }
        if s.contains('*') {
            return Err(PatternError::CatchAll);
        }
        canon_host(s.as_bytes()).map(HostPattern::Exact).map_err(PatternError::Canon)
    }

    /// Label-boundary match on canonical values only.
    pub fn matches(&self, host: &CanonicalHost) -> bool {
        match self {
            HostPattern::Exact(h) => h == host,
            HostPattern::Subdomains(base) => {
                if host.is_ip_literal() {
                    return false;
                }
                let (h, b) = (host.as_str(), base.as_str());
                h.len() > b.len() + 1 && h.ends_with(b) && h.as_bytes()[h.len() - b.len() - 1] == b'.'
            }
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::Exact(h) => write!(f, "{h}"),
            HostPattern::Subdomains(h) => write!(f, "*.{h}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Paths (used by the L7 pipeline from M1; specified by I6 now)
// ---------------------------------------------------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> String {
        canon_host(s.as_bytes()).unwrap_or_else(|e| panic!("{s:?} rejected: {e}")).as_str().to_string()
    }
    fn rej(s: &[u8]) -> Reject {
        match canon_host(s) {
            Ok(h) => panic!("{:?} accepted as {h:?}", String::from_utf8_lossy(s)),
            Err(e) => e,
        }
    }

    #[test]
    fn names_are_lowercased_ldh() {
        assert_eq!(ok("API.GitHub.com"), "api.github.com");
        assert_eq!(ok("localhost"), "localhost");
        assert_eq!(ok("a-b.example"), "a-b.example");
        assert_eq!(ok("1e100.net"), "1e100.net");
        assert_eq!(ok("0x7f.example.com"), "0x7f.example.com");
    }

    #[test]
    fn registrable_domain() {
        let h = canon_host(b"a.b.example.co.uk").unwrap();
        assert_eq!(h.registrable(), Some("example.co.uk"));
        let h = canon_host(b"api.github.com").unwrap();
        assert_eq!(h.registrable(), Some("github.com"));
    }

    #[test]
    fn nul_crlf_percent_and_friends_rejected() {
        assert_eq!(rej(b"attacker.example\x00.google.com"), Reject::ForbiddenByte(0));
        assert_eq!(rej(b"example.com\r\nX: y"), Reject::ForbiddenByte(b'\r'));
        assert_eq!(rej(b"example.com\n"), Reject::ForbiddenByte(b'\n'));
        assert_eq!(rej(b"exa%6dple.com"), Reject::ForbiddenByte(b'%'));
        assert_eq!(rej(b"user@example.com"), Reject::ForbiddenByte(b'@'));
        assert_eq!(rej(b"example.com\\@evil.com"), Reject::ForbiddenByte(b'\\'));
        assert_eq!(rej(b"example.com/x"), Reject::ForbiddenByte(b'/'));
        assert_eq!(rej(b"example.com:443"), Reject::ForbiddenByte(b':'));
        assert_eq!(rej(b"exa mple.com"), Reject::ForbiddenByte(b' '));
        assert_eq!(rej(b"*.example.com"), Reject::ForbiddenByte(b'*'));
        assert_eq!(rej(b""), Reject::Empty);
    }

    #[test]
    fn trailing_dot_and_empty_labels() {
        assert_eq!(rej(b"example.com."), Reject::TrailingDot);
        assert_eq!(rej(b"example..com"), Reject::BadLabel);
        assert_eq!(rej(b".example.com"), Reject::BadLabel);
        assert_eq!(rej(b"-bad.example"), Reject::BadLabel);
        assert_eq!(rej(b"bad-.example"), Reject::BadLabel);
        assert_eq!(rej(b"under_score.example"), Reject::BadLabel);
        let long = format!("{}.com", "a".repeat(64));
        assert_eq!(rej(long.as_bytes()), Reject::BadLabel);
        let too_long = vec![b'a'; 254];
        assert_eq!(rej(&too_long), Reject::TooLong);
    }

    #[test]
    fn ip_literals_strict_only() {
        assert_eq!(ok("8.8.8.8"), "8.8.8.8");
        assert!(canon_host(b"8.8.8.8").unwrap().is_ip_literal());
        for bad in [
            &b"2130706433"[..],
            b"0x7f000001",
            b"0x7f.0.0.1",
            b"0177.0.0.1",
            b"127.1",
            b"127.0.1",
            b"1.2.3.4.5",
            b"256.1.1.1",
            b"01.2.3.4",
            b"example.123",
            b"0x",
        ] {
            assert_eq!(rej(bad), Reject::AmbiguousIpLiteral, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn ipv6_literals() {
        assert_eq!(ok("[::1]"), "[::1]");
        assert_eq!(ok("[2001:DB8:0:0:0:0:0:1]"), "[2001:db8::1]");
        assert_eq!(rej(b"[::ffff:127.0.0.1]"), Reject::MappedV6);
        assert_eq!(rej(b"[::ffff:7f00:1]"), Reject::MappedV6);
        assert_eq!(rej(b"[::127.0.0.1]"), Reject::MappedV6);
        assert_eq!(rej(b"[fe80::1%25eth0]"), Reject::ForbiddenByte(b'%'));
        assert_eq!(rej(b"::1"), Reject::ForbiddenByte(b':'));
        assert_eq!(rej(b"[::1"), Reject::ForbiddenByte(b'['));
        assert_eq!(rej(b"[not-an-ip]"), Reject::ForbiddenByte(b'n'));
    }

    #[test]
    fn idna() {
        assert_eq!(ok("bücher.example"), "xn--bcher-kva.example");
        assert_eq!(ok("xn--bcher-kva.example"), "xn--bcher-kva.example");
        assert_eq!(ok("XN--BCHER-KVA.example"), "xn--bcher-kva.example");
        assert_eq!(rej("bücher.xn--bcher-kva.example".as_bytes()), Reject::MixedIdna);
        assert_eq!(rej(b"xn--zz.example"), Reject::IdnaRoundTrip);
        assert_eq!(rej("example\u{3002}com".as_bytes()), Reject::BadLabel);
        assert_eq!(rej(b"\xff\xfe.example"), Reject::BadLabel);
        // Idempotence on the converted form.
        let h = canon_host("bücher.example".as_bytes()).unwrap();
        assert_eq!(canon_host(h.as_str().as_bytes()).unwrap(), h);
    }

    #[test]
    fn address_classes() {
        let c = |s: &str| classify_addr(s.parse().unwrap());
        assert_eq!(c("169.254.169.254"), AddrClass::Metadata);
        assert_eq!(c("169.254.170.2"), AddrClass::Metadata);
        assert_eq!(c("100.100.100.200"), AddrClass::Metadata);
        assert_eq!(c("fd00:ec2::254"), AddrClass::Metadata);
        assert_eq!(c("169.254.1.1"), AddrClass::LinkLocal);
        assert_eq!(c("127.0.0.1"), AddrClass::Loopback);
        assert_eq!(c("10.1.2.3"), AddrClass::Private);
        assert_eq!(c("172.16.0.1"), AddrClass::Private);
        assert_eq!(c("192.168.1.1"), AddrClass::Private);
        assert_eq!(c("100.64.0.1"), AddrClass::Private);
        assert_eq!(c("0.0.0.0"), AddrClass::Reserved);
        assert_eq!(c("224.0.0.1"), AddrClass::Reserved);
        assert_eq!(c("8.8.8.8"), AddrClass::Public);
        assert_eq!(c("::1"), AddrClass::Loopback);
        assert_eq!(c("::ffff:169.254.169.254"), AddrClass::Metadata);
        assert_eq!(c("::ffff:10.0.0.1"), AddrClass::Private);
        assert_eq!(c("64:ff9b::a00:1"), AddrClass::Private);
        assert_eq!(c("64:ff9b::a9fe:a9fe"), AddrClass::Metadata);
        assert_eq!(c("fe80::1"), AddrClass::LinkLocal);
        assert_eq!(c("fc00::1"), AddrClass::Private);
        assert_eq!(c("2606:4700::1111"), AddrClass::Public);
    }

    #[test]
    fn patterns_respect_label_boundaries() {
        let p = HostPattern::parse("*.Example.com").unwrap();
        assert!(p.matches(&canon_host(b"a.example.com").unwrap()));
        assert!(p.matches(&canon_host(b"a.b.example.com").unwrap()));
        assert!(!p.matches(&canon_host(b"example.com").unwrap()));
        assert!(!p.matches(&canon_host(b"evilexample.com").unwrap()));
        assert!(!p.matches(&canon_host(b"example.com.evil").unwrap()));
        let e = HostPattern::parse("API.github.com").unwrap();
        assert!(e.matches(&canon_host(b"api.github.com").unwrap()));
        assert!(!e.matches(&canon_host(b"x.api.github.com").unwrap()));
        assert_eq!(HostPattern::parse("*"), Err(PatternError::CatchAll));
        assert_eq!(HostPattern::parse("*."), Err(PatternError::CatchAll));
        assert_eq!(HostPattern::parse("a.*.com"), Err(PatternError::CatchAll));
        assert!(matches!(HostPattern::parse("*.com"), Err(PatternError::PublicSuffixWildcard(_))));
        assert!(matches!(HostPattern::parse("*.github.io"), Err(PatternError::PublicSuffixWildcard(_))));
        assert_eq!(HostPattern::parse("*.1.2.3.4"), Err(PatternError::IpWildcard));
        assert!(HostPattern::parse("example.com.").is_err());
    }

    #[test]
    fn paths() {
        let p = |s: &str| canon_path(s.as_bytes());
        assert_eq!(p("/repos/acme/web/pulls").unwrap().path(), "/repos/acme/web/pulls");
        assert_eq!(p("/a/%7euser").unwrap().path(), "/a/~user");
        assert_eq!(p("/a/%c3%bc").unwrap().path(), "/a/%C3%BC");
        assert_eq!(p("/a/b/").unwrap().path(), "/a/b/");
        assert_eq!(p("/").unwrap().path(), "/");
        let q = p("/search?q=a&b=c").unwrap();
        assert_eq!((q.path(), q.query()), ("/search", Some("q=a&b=c")));
        assert_eq!(p("/a/%2f/b"), Err(Reject::EncodedSeparator));
        assert_eq!(p("/a/%5c"), Err(Reject::EncodedSeparator));
        assert_eq!(p("/a/%00"), Err(Reject::EncodedSeparator));
        assert_eq!(p("/a/%2e%2e/b"), Err(Reject::DotSegment));
        assert_eq!(p("/a/../b"), Err(Reject::DotSegment));
        assert_eq!(p("/a/./b"), Err(Reject::DotSegment));
        assert_eq!(p("/a//b"), Err(Reject::NonCanonicalPath));
        assert_eq!(p("/a\\b"), Err(Reject::ForbiddenByte(b'\\')));
        assert_eq!(p("/a#frag"), Err(Reject::ForbiddenByte(b'#')));
        assert_eq!(p("/a%zz"), Err(Reject::NonCanonicalPath));
        assert_eq!(p("/a%4"), Err(Reject::NonCanonicalPath));
        assert_eq!(p("a/b"), Err(Reject::NonCanonicalPath));
        assert_eq!(p("http://x/a"), Err(Reject::NonCanonicalPath));
        assert_eq!(p("/a b"), Err(Reject::ForbiddenByte(b' ')));
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use proptest::prelude::*;

    fn label() -> impl Strategy<Value = String> {
        "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?"
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// canon(canon(x)) == canon(x) for arbitrary bytes.
        #[test]
        fn idempotent_on_arbitrary_bytes(raw in proptest::collection::vec(any::<u8>(), 0..80)) {
            if let Ok(h) = canon_host(&raw) {
                prop_assert_eq!(canon_host(h.as_str().as_bytes()), Ok(h));
            }
        }

        /// Accepted names contain only LDH bytes and dots; never a forbidden byte.
        #[test]
        fn accepted_output_is_ldh(raw in proptest::collection::vec(any::<u8>(), 0..80)) {
            if let Ok(h) = canon_host(&raw) {
                let s = h.as_str();
                if let HostKind::Name { .. } = h.kind() {
                    prop_assert!(s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'));
                }
                prop_assert!(!s.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'%' || b == b'@'));
            }
        }

        /// Hostile structure: a valid name with a forbidden byte spliced in is
        /// always rejected.
        #[test]
        fn spliced_forbidden_byte_rejected(a in label(), b in label(), pos in 0usize..20,
                                           bad in prop::sample::select(vec![0u8, b'\r', b'\n', b'%', b'@', b'/', b'\\', b' ', b'#', b'?', b':'])) {
            let mut v = format!("{a}.{b}.com").into_bytes();
            let at = pos % (v.len() + 1);
            v.insert(at, bad);
            prop_assert!(canon_host(&v).is_err());
        }

        /// Wildcard patterns match only at label boundaries.
        #[test]
        fn wildcard_label_boundary(sub in label(), base in label(), glue in label()) {
            // Generated labels can accidentally form `xn--` A-labels, which
            // must be valid punycode; those are covered by the IDNA tests.
            prop_assume!(![&sub, &base, &format!("{glue}{base}")].iter().any(|l| l.starts_with("xn--")));
            let base_name = format!("{base}.example");
            let p = HostPattern::parse(&format!("*.{base_name}")).unwrap();
            let child = canon_host(format!("{sub}.{base_name}").as_bytes()).unwrap();
            prop_assert!(p.matches(&child));
            let glued = canon_host(format!("{glue}{base_name}").as_bytes()).unwrap();
            prop_assert!(!p.matches(&glued));
            let same = canon_host(base_name.as_bytes()).unwrap();
            prop_assert!(!p.matches(&same));
        }

        /// Compile-time (pattern) and runtime canonicalisation agree under case changes.
        #[test]
        fn pattern_and_runtime_agree(a in label(), b in label(), upper in any::<bool>()) {
            prop_assume!(!a.starts_with("xn--") && !b.starts_with("xn--"));
            let name = format!("{a}.{b}.example");
            let written = if upper { name.to_uppercase() } else { name.clone() };
            let p = HostPattern::parse(&written).unwrap();
            prop_assert!(p.matches(&canon_host(name.to_uppercase().as_bytes()).unwrap()));
        }

        /// Paths: accepted output never contains dot segments or encoded separators.
        #[test]
        fn path_output_is_safe(raw in proptest::collection::vec(any::<u8>(), 0..60)) {
            let mut v = vec![b'/'];
            v.extend(raw);
            if let Ok(p) = canon_path(&v) {
                prop_assert!(!p.path().split('/').any(|s| s == "." || s == ".."));
                let lower = p.path().to_ascii_lowercase();
                prop_assert!(!lower.contains("%2f") && !lower.contains("%5c") && !lower.contains("%00") && !lower.contains("%2e"));
                prop_assert_eq!(canon_path(p.path().as_bytes()).map(|x| x.path().to_string()), Ok(p.path().to_string()));
            }
        }
    }
}
