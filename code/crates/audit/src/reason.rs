//! The enumerated deny reasons shared by netguard, tls, policy, launcher and
//! audit. `broker why` renders them; conformance probes assert them.

use serde::{Deserialize, Serialize};

/// Why a decision denied (or why a launch was refused).
///
/// Serialised in snake_case; the names are part of the audit format and of
/// the public bypass corpus, so renaming one is a format change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

    // ---- L7 (terminated hosts, M1) ----
    /// The Host header or absolute-form authority differs from CONNECT/SNI.
    HostHeaderMismatch,
    /// The host is granted, but no method/path or protocol rule allows the
    /// request (ADR-006: unmatched L7 requests deny).
    L7NoRuleMatched,
    /// WebSocket or other protocol upgrade on a terminated host.
    UpgradeNotAllowed,
    /// The request head exceeded the broker's size or field-count limit.
    HeadTooLarge,
    /// The request body exceeded the inspection limit.
    BodyTooLarge,
    /// A content encoding the broker cannot inspect.
    UnsupportedEncoding,
    /// A git smart-HTTP request that could not be parsed strictly.
    GitParseError,
    /// git: the repository is not granted for this operation.
    GitRepoNotAllowed,
    /// git: the ref is not granted for push.
    GitRefNotAllowed,
    /// git: a force update (non-fast-forward, delete or undeterminable).
    GitForcePush,
    /// GitHub API: a route the adapter does not map to a verb.
    GithubRouteUnknown,
    /// GitHub API: GraphQL is not mapped yet (mutations could hide).
    GithubGraphqlUnsupported,
    /// GitHub API: the verb is not granted.
    GithubVerbNotAllowed,
    /// GitHub API: the verb is granted, but not on this repository.
    GithubRepoNotAllowed,
    /// MCP: no pinned server by that name in user or org policy.
    McpServerUnknown,
    /// MCP: the server's manifest was never approved.
    McpManifestUnapproved,
    /// MCP: the server's manifest differs from the approved one (rug pull).
    McpManifestChanged,
    /// MCP: the tool is not in the pinned manifest.
    McpToolUnknown,
    /// MCP: the tool is denied by policy.
    McpToolNotAllowed,
    /// MCP: a method the guard does not relay.
    McpMethodNotAllowed,
    /// MCP: a frame that is not strict JSON-RPC 2.0, or too large.
    McpMalformed,
    /// MCP: the pinned server could not be started or pinned.
    McpLaunchFailed,

    // ---- credentials (M1, I1/I7) ----
    /// A credential the broker did not issue (I7).
    ForeignCredential,
    /// A broker sentinel sent to a host it is not bound to.
    SentinelWrongHost,
    /// More than one credential rule allowed the request.
    AmbiguousCredential,
    /// The credential could not be minted or loaded; nothing was forwarded.
    MintFailed,
    /// The response contained an injected secret and was cut (I1).
    SecretReflected,

    // ---- Cedar policy (M2) ----
    /// No Cedar permit matched (and no more specific reason applies).
    PolicyDenied,
    /// The base policy allowed it, but the approved repo layer did not (I4).
    RepoPolicyDenied,
    /// The request could not be evaluated (schema-invalid or an error): deny.
    PolicyError,
    /// The task's grants have expired.
    TaskExpired,
    /// A credential would be attached outside its declared hosts.
    CredentialHostCeiling,
    /// Untrusted input and a sensitive read are both live; writes need approval.
    RuleOfTwo,
    /// An MCP server whose tool manifest changed is unpinned.
    McpUnpinned,
    /// The action needs an out-of-band approval (publish, merge).
    NeedsApproval,
    /// The org ceiling forbids paste sites.
    CeilingPasteSite,
    /// The org ceiling forbids tunnel services.
    CeilingTunnel,

    // ---- upstream ----
    UpstreamConnectFailed,
    /// The upstream certificate failed verification.
    UpstreamTls,

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
        Reason::HostHeaderMismatch,
        Reason::L7NoRuleMatched,
        Reason::UpgradeNotAllowed,
        Reason::HeadTooLarge,
        Reason::BodyTooLarge,
        Reason::UnsupportedEncoding,
        Reason::GitParseError,
        Reason::GitRepoNotAllowed,
        Reason::GitRefNotAllowed,
        Reason::GitForcePush,
        Reason::GithubRouteUnknown,
        Reason::GithubGraphqlUnsupported,
        Reason::GithubVerbNotAllowed,
        Reason::GithubRepoNotAllowed,
        Reason::McpServerUnknown,
        Reason::McpManifestUnapproved,
        Reason::McpManifestChanged,
        Reason::McpToolUnknown,
        Reason::McpToolNotAllowed,
        Reason::McpMethodNotAllowed,
        Reason::McpMalformed,
        Reason::McpLaunchFailed,
        Reason::ForeignCredential,
        Reason::SentinelWrongHost,
        Reason::AmbiguousCredential,
        Reason::MintFailed,
        Reason::SecretReflected,
        Reason::PolicyDenied,
        Reason::RepoPolicyDenied,
        Reason::PolicyError,
        Reason::TaskExpired,
        Reason::CredentialHostCeiling,
        Reason::RuleOfTwo,
        Reason::McpUnpinned,
        Reason::NeedsApproval,
        Reason::CeilingPasteSite,
        Reason::CeilingTunnel,
        Reason::UpstreamConnectFailed,
        Reason::UpstreamTls,
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
            Reason::HostHeaderMismatch => "host_header_mismatch",
            Reason::L7NoRuleMatched => "l7_no_rule_matched",
            Reason::UpgradeNotAllowed => "upgrade_not_allowed",
            Reason::HeadTooLarge => "head_too_large",
            Reason::BodyTooLarge => "body_too_large",
            Reason::UnsupportedEncoding => "unsupported_encoding",
            Reason::GitParseError => "git_parse_error",
            Reason::GitRepoNotAllowed => "git_repo_not_allowed",
            Reason::GitRefNotAllowed => "git_ref_not_allowed",
            Reason::GitForcePush => "git_force_push",
            Reason::GithubRouteUnknown => "github_route_unknown",
            Reason::GithubGraphqlUnsupported => "github_graphql_unsupported",
            Reason::GithubVerbNotAllowed => "github_verb_not_allowed",
            Reason::GithubRepoNotAllowed => "github_repo_not_allowed",
            Reason::McpServerUnknown => "mcp_server_unknown",
            Reason::McpManifestUnapproved => "mcp_manifest_unapproved",
            Reason::McpManifestChanged => "mcp_manifest_changed",
            Reason::McpToolUnknown => "mcp_tool_unknown",
            Reason::McpToolNotAllowed => "mcp_tool_not_allowed",
            Reason::McpMethodNotAllowed => "mcp_method_not_allowed",
            Reason::McpMalformed => "mcp_malformed",
            Reason::McpLaunchFailed => "mcp_launch_failed",
            Reason::ForeignCredential => "foreign_credential",
            Reason::SentinelWrongHost => "sentinel_wrong_host",
            Reason::AmbiguousCredential => "ambiguous_credential",
            Reason::MintFailed => "mint_failed",
            Reason::SecretReflected => "secret_reflected",
            Reason::PolicyDenied => "policy_denied",
            Reason::RepoPolicyDenied => "repo_policy_denied",
            Reason::PolicyError => "policy_error",
            Reason::TaskExpired => "task_expired",
            Reason::CredentialHostCeiling => "credential_host_ceiling",
            Reason::RuleOfTwo => "rule_of_two",
            Reason::McpUnpinned => "mcp_unpinned",
            Reason::NeedsApproval => "needs_approval",
            Reason::CeilingPasteSite => "ceiling_paste_site",
            Reason::CeilingTunnel => "ceiling_tunnel",
            Reason::UpstreamConnectFailed => "upstream_connect_failed",
            Reason::UpstreamTls => "upstream_tls",
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
            HostHeaderMismatch
            | L7NoRuleMatched
            | UpgradeNotAllowed
            | HeadTooLarge
            | BodyTooLarge
            | UnsupportedEncoding
            | GitParseError
            | GitRepoNotAllowed
            | GitRefNotAllowed
            | GitForcePush
            | GithubRouteUnknown
            | GithubGraphqlUnsupported
            | GithubVerbNotAllowed
            | GithubRepoNotAllowed => "l7",
            ForeignCredential | SentinelWrongHost | AmbiguousCredential | MintFailed | SecretReflected => "credentials",
            McpServerUnknown
            | McpManifestUnapproved
            | McpManifestChanged
            | McpToolUnknown
            | McpToolNotAllowed
            | McpMethodNotAllowed
            | McpMalformed
            | McpLaunchFailed => "mcp",
            PolicyDenied
            | RepoPolicyDenied
            | PolicyError
            | TaskExpired
            | CredentialHostCeiling
            | RuleOfTwo
            | McpUnpinned
            | NeedsApproval
            | CeilingPasteSite
            | CeilingTunnel => "policy",
            UpstreamConnectFailed | UpstreamTls => "upstream",
            AuditUnavailable => "audit",
            LaunchRefused => "launcher",
        }
    }

    /// The trust boundary at which the decision was made (Trust Boundaries).
    pub fn boundary(&self) -> &'static str {
        match self {
            Reason::LaunchRefused => "TB2",
            Reason::UpstreamConnectFailed
            | Reason::UpstreamTls
            | Reason::MintFailed
            | Reason::AmbiguousCredential
            | Reason::SecretReflected => "TB4",
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
            HostHeaderMismatch => "the Host header or request authority differs from the CONNECT host and SNI",
            L7NoRuleMatched => "the host is granted, but no method/path or protocol rule allows this request",
            UpgradeNotAllowed => "protocol upgrades (WebSocket, h2c) are not brokered on terminated hosts",
            HeadTooLarge => "the request head exceeded the broker's limit (64 KiB, 128 fields)",
            BodyTooLarge => "the request body exceeded the broker's inspection limit",
            UnsupportedEncoding => "the body used a content encoding the broker cannot inspect",
            GitParseError => "the git smart-HTTP request could not be parsed strictly",
            GitRepoNotAllowed => "the repository is not granted for this git operation",
            GitRefNotAllowed => "the ref is not granted for push",
            GitForcePush => {
                "the update is a force push (non-fast-forward, delete or undeterminable) and force is not granted"
            }
            GithubRouteUnknown => "the GitHub API route is not mapped to a verb, so it is denied",
            GithubGraphqlUnsupported => "GitHub GraphQL requests are denied until they can be mapped to verbs",
            GithubVerbNotAllowed => "the GitHub verb (for example pr.merge) is not granted",
            GithubRepoNotAllowed => "the GitHub verb is granted, but not on this repository",
            McpServerUnknown => "no pinned MCP server by that name is defined in user or org policy",
            McpManifestUnapproved => "the MCP server's tool manifest has not been approved (`broker mcp approve`)",
            McpManifestChanged => "the MCP server's tool manifest changed since approval; its grants are revoked",
            McpToolUnknown => "the tool is not in the MCP server's pinned manifest",
            McpToolNotAllowed => "policy does not allow this MCP tool",
            McpMethodNotAllowed => "the MCP method is not relayed by the broker",
            McpMalformed => "the MCP message is not strict JSON-RPC 2.0 or is too large",
            McpLaunchFailed => "the pinned MCP server could not be started or pinned",
            ForeignCredential => "the request carried a credential the broker did not issue",
            SentinelWrongHost => "a broker sentinel was sent to a host it is not bound to",
            AmbiguousCredential => "more than one credential rule allowed the request",
            MintFailed => "the broker could not mint or load the credential, so nothing was forwarded",
            SecretReflected => "the response contained an injected secret and was cut",
            PolicyDenied => "no Cedar permit allows this request (default deny)",
            RepoPolicyDenied => "user and org policy allow this, but the approved repository policy narrows it away",
            PolicyError => "the request could not be evaluated against the policy, so it was denied",
            TaskExpired => "the task's grants have expired",
            CredentialHostCeiling => "the credential may not be attached to this host (org ceiling)",
            RuleOfTwo => "untrusted input and a sensitive read are both live; writes need out-of-band approval",
            McpUnpinned => "the MCP server's tool manifest changed and it is no longer pinned",
            NeedsApproval => "this action needs an out-of-band approval",
            CeilingPasteSite => "paste sites are outside the org ceiling",
            CeilingTunnel => "tunnel services are outside the org ceiling",
            UpstreamConnectFailed => "the broker could not connect to the resolved address",
            UpstreamTls => "the upstream certificate failed verification",
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
