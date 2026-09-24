//! The enumerated deny reasons shared by netguard, tls, policy, launcher and
//! audit. `broker why` renders them; conformance probes assert them.

use serde::{Deserialize, Serialize};

/// Why a decision denied (or why a launch was refused).
///
/// Serialised in snake_case; the names are part of the audit format and of
/// the public bypass corpus, so renaming one is a format change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    // ---- canonicaliser (netguard::canon), I6 ----
    EmptyHost,
    HostTooLong,
    ForbiddenByte,
    TrailingDot,
    BadLabel,
    MixedIdna,
    IdnaRoundTrip,
    AmbiguousIpLiteral,
    MappedV6,
    NonCanonicalPath,
    EncodedSeparator,
    DotSegment,

    // ---- policy / admission ----
    /// The canonical name matches no egress grant (includes empty allowlists).
    HostNotAllowed,
    /// The name is allowed but not on this port.
    PortNotAllowed,
    /// The destination was an IP literal and no grant names it.
    IpLiteral,
    /// A resolved or literal address is cloud metadata (169.254.169.254 and peers).
    MetadataAddr,
    /// Link-local address.
    LinkLocalAddr,
    /// RFC 1918 / ULA / CGNAT address.
    PrivateAddr,
    /// Loopback address.
    LoopbackAddr,
    /// Unspecified, multicast, broadcast, documentation or reserved address.
    ReservedAddr,
    /// IPv6 egress is not proxied yet, so AAAA-only destinations are denied.
    Ipv6NotProxied,
    /// A known DNS-over-HTTPS / DNS-over-TLS endpoint, blocked by name.
    DohEndpoint,

    // ---- broker DNS ----
    ResolveFailed,
    NoAddresses,

    // ---- ingress (netguard) ----
    /// The client spoke something other than HTTP CONNECT or SOCKS5.
    ProtocolUnsupported,
    /// SOCKS4/4a is refused outright (hostname forms bypassed srt).
    Socks4Refused,
    /// SOCKS5 BIND or UDP ASSOCIATE.
    SocksCommandUnsupported,
    /// Plain-HTTP proxy request (absolute-form GET); L7 arrives in M1.
    PlainHttpUnsupported,
    /// Malformed CONNECT or SOCKS5 framing.
    MalformedRequest,
    /// macOS loopback ingress without a session sentinel.
    ProxyAuthRequired,
    /// A sentinel that is not this session's.
    BadSentinel,

    // ---- tls (L4 SNI check) ----
    /// The first bytes after CONNECT were not a TLS ClientHello with SNI.
    SniLess,
    /// SNI does not canonicalise to the admitted CONNECT host.
    ConnectSniMismatch,

    // ---- upstream ----
    UpstreamConnectFailed,

    // ---- audit ----
    /// The audit append failed, so the decision became a deny (I9).
    AuditUnavailable,

    // ---- launch (I2) ----
    LaunchRefused,
}

impl Reason {
    /// Every reason, for exhaustive tests and documentation.
    pub const ALL: &'static [Reason] = &[
        Reason::EmptyHost,
        Reason::HostTooLong,
        Reason::ForbiddenByte,
        Reason::TrailingDot,
        Reason::BadLabel,
        Reason::MixedIdna,
        Reason::IdnaRoundTrip,
        Reason::AmbiguousIpLiteral,
        Reason::MappedV6,
        Reason::NonCanonicalPath,
        Reason::EncodedSeparator,
        Reason::DotSegment,
        Reason::HostNotAllowed,
        Reason::PortNotAllowed,
        Reason::IpLiteral,
        Reason::MetadataAddr,
        Reason::LinkLocalAddr,
        Reason::PrivateAddr,
        Reason::LoopbackAddr,
        Reason::ReservedAddr,
        Reason::Ipv6NotProxied,
        Reason::DohEndpoint,
        Reason::ResolveFailed,
        Reason::NoAddresses,
        Reason::ProtocolUnsupported,
        Reason::Socks4Refused,
        Reason::SocksCommandUnsupported,
        Reason::PlainHttpUnsupported,
        Reason::MalformedRequest,
        Reason::ProxyAuthRequired,
        Reason::BadSentinel,
        Reason::SniLess,
        Reason::ConnectSniMismatch,
        Reason::UpstreamConnectFailed,
        Reason::AuditUnavailable,
        Reason::LaunchRefused,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Reason::EmptyHost => "empty_host",
            Reason::HostTooLong => "host_too_long",
            Reason::ForbiddenByte => "forbidden_byte",
            Reason::TrailingDot => "trailing_dot",
            Reason::BadLabel => "bad_label",
            Reason::MixedIdna => "mixed_idna",
            Reason::IdnaRoundTrip => "idna_round_trip",
            Reason::AmbiguousIpLiteral => "ambiguous_ip_literal",
            Reason::MappedV6 => "mapped_v6",
            Reason::NonCanonicalPath => "non_canonical_path",
            Reason::EncodedSeparator => "encoded_separator",
            Reason::DotSegment => "dot_segment",
            Reason::HostNotAllowed => "host_not_allowed",
            Reason::PortNotAllowed => "port_not_allowed",
            Reason::IpLiteral => "ip_literal",
            Reason::MetadataAddr => "metadata_addr",
            Reason::LinkLocalAddr => "link_local_addr",
            Reason::PrivateAddr => "private_addr",
            Reason::LoopbackAddr => "loopback_addr",
            Reason::ReservedAddr => "reserved_addr",
            Reason::Ipv6NotProxied => "ipv6_not_proxied",
            Reason::DohEndpoint => "doh_endpoint",
            Reason::ResolveFailed => "resolve_failed",
            Reason::NoAddresses => "no_addresses",
            Reason::ProtocolUnsupported => "protocol_unsupported",
            Reason::Socks4Refused => "socks4_refused",
            Reason::SocksCommandUnsupported => "socks_command_unsupported",
            Reason::PlainHttpUnsupported => "plain_http_unsupported",
            Reason::MalformedRequest => "malformed_request",
            Reason::ProxyAuthRequired => "proxy_auth_required",
            Reason::BadSentinel => "bad_sentinel",
            Reason::SniLess => "sni_less",
            Reason::ConnectSniMismatch => "connect_sni_mismatch",
            Reason::UpstreamConnectFailed => "upstream_connect_failed",
            Reason::AuditUnavailable => "audit_unavailable",
            Reason::LaunchRefused => "launch_refused",
        }
    }

    /// The pipeline stage that produced the reason (Request and Session
    /// Lifecycle, Flow 5).
    pub fn stage(&self) -> &'static str {
        use Reason::*;
        match self {
            EmptyHost | HostTooLong | ForbiddenByte | TrailingDot | BadLabel | MixedIdna | IdnaRoundTrip
            | AmbiguousIpLiteral | MappedV6 | NonCanonicalPath | EncodedSeparator | DotSegment => "canonicaliser",
            HostNotAllowed | PortNotAllowed | IpLiteral | MetadataAddr | LinkLocalAddr | PrivateAddr | LoopbackAddr
            | ReservedAddr | Ipv6NotProxied | DohEndpoint => "policy",
            ResolveFailed | NoAddresses => "dns",
            ProtocolUnsupported
            | Socks4Refused
            | SocksCommandUnsupported
            | PlainHttpUnsupported
            | MalformedRequest
            | ProxyAuthRequired
            | BadSentinel => "ingress",
            SniLess | ConnectSniMismatch => "tls",
            UpstreamConnectFailed => "upstream",
            AuditUnavailable => "audit",
            LaunchRefused => "launcher",
        }
    }

    /// The trust boundary at which the decision was made (Trust Boundaries).
    pub fn boundary(&self) -> &'static str {
        match self {
            Reason::LaunchRefused => "TB2",
            Reason::UpstreamConnectFailed => "TB4",
            _ => "TB3",
        }
    }

    /// One-line human explanation for `broker why`.
    pub fn explain(&self) -> &'static str {
        use Reason::*;
        match self {
            EmptyHost => "the destination host was empty",
            HostTooLong => "the destination host exceeded 253 bytes",
            ForbiddenByte => "the host contained a forbidden byte (NUL, CR, LF, %, whitespace, /, \\, @, ?, #)",
            TrailingDot => "the host ended with a dot; trailing dots are rejected, not stripped",
            BadLabel => "a host label was not letters, digits and inner hyphens (1-63 bytes)",
            MixedIdna => "the host mixed Unicode labels with xn-- labels",
            IdnaRoundTrip => "an xn-- label did not round-trip through IDNA",
            AmbiguousIpLiteral => "the host was a non-canonical IP literal (decimal, octal, hex or short form)",
            MappedV6 => "the host was an IPv4-mapped or IPv4-compatible IPv6 literal",
            NonCanonicalPath => "the path was not in canonical origin form",
            EncodedSeparator => "the path contained an encoded separator",
            DotSegment => "the path contained a dot segment",
            HostNotAllowed => "no egress grant matches this host (empty lists deny)",
            PortNotAllowed => "the host is granted, but not on this port",
            IpLiteral => "IP-literal destinations are denied unless a grant names the literal",
            MetadataAddr => "the address is a cloud metadata endpoint",
            LinkLocalAddr => "the address is link-local",
            PrivateAddr => "the address is private (RFC 1918, ULA or CGNAT)",
            LoopbackAddr => "the address is loopback",
            ReservedAddr => "the address is unspecified, multicast, broadcast or reserved",
            Ipv6NotProxied => "the destination only resolved to IPv6, which is not proxied yet",
            DohEndpoint => "the host is a DNS-over-HTTPS/TLS endpoint, blocked by name",
            ResolveFailed => "the broker resolver could not resolve the name",
            NoAddresses => "the name resolved to no usable address",
            ProtocolUnsupported => "the client spoke neither HTTP CONNECT nor SOCKS5",
            Socks4Refused => "SOCKS4/4a is refused",
            SocksCommandUnsupported => "only SOCKS5 CONNECT is supported (no BIND, no UDP)",
            PlainHttpUnsupported => "plain-HTTP proxying is not supported; use HTTPS via CONNECT",
            MalformedRequest => "the proxy request was malformed",
            ProxyAuthRequired => "the proxy connection carried no session sentinel",
            BadSentinel => "the proxy credential is not this session's sentinel",
            SniLess => "the tunnel did not start with a TLS ClientHello carrying SNI",
            ConnectSniMismatch => "the TLS SNI does not match the admitted CONNECT host",
            UpstreamConnectFailed => "the broker could not connect to the resolved address",
            AuditUnavailable => "the audit log could not record the decision, so it was denied",
            LaunchRefused => "a required isolation layer or the proxy was not available",
        }
    }
}

impl From<Reason> for String {
    fn from(r: Reason) -> String {
        r.as_str().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_name_matches_as_str() {
        for r in Reason::ALL {
            let json = serde_json::to_string(r).unwrap();
            assert_eq!(json, format!("\"{}\"", r.as_str()));
            assert!(!r.explain().is_empty());
            assert!(!r.stage().is_empty());
        }
    }
}
