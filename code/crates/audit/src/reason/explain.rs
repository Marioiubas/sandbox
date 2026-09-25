//! The one-line explanation of every reason, as `broker why` prints it.

use super::Reason;

impl Reason {
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
            S3RouteUnknown => {
                "the S3 request is not an object read, listing, write or delete the adapter maps (bucket settings, ACLs, copies, presigned URLs and signed-chunk uploads are denied)"
            }
            S3PrefixNotAllowed => "the S3 operation is not granted on this bucket and key prefix",
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
