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
    // Found by the nightly fuzz run (2026-09-25): a soft hyphen in front of
    // an A-label is dropped by the mapping, so the non-ASCII path produced
    // a name the ASCII path rejects (canonicalisation was not a fixed point).
    assert_eq!(rej("\u{ad}xn--xn--xn-n-nmm".as_bytes()), Reject::IdnaRoundTrip);
    assert_eq!(rej(b"xn--xn--xn-n-nmm"), Reject::IdnaRoundTrip);
    // A soft hyphen elsewhere is ignorable and maps away consistently.
    assert_eq!(canon_host("ex\u{ad}ample.com".as_bytes()).unwrap().as_str(), "example.com");
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
    // Dot segments behind path parameters or escapes (Tomcat `..;/`; found
    // by the category 8 differential test).
    for bad in [
        "/a/..;/b",
        "/a/..;x/b",
        "/a/.;/b",
        "/a/..%3B/b",
        "/a/..%253B/b",
        "/a/.%20/b",
        "/a/%252e%252e/b",
        "/a/%EF%BC%8E%EF%BC%8E/b",
    ] {
        assert_eq!(p(bad), Err(Reject::DotSegment), "{bad}");
    }
    for bad in ["/a/%252F/b", "/a/%255C/b", "/a/x%EF%BC%8Fy", "/a/x%E2%88%95y", "/a/;;,..%25%255C../;/L;"] {
        assert_eq!(p(bad), Err(Reject::EncodedSeparator), "{bad}");
    }
    for bad in ["/a/%C0%AE%C0%AE/b", "/a/%25C0%25AE/b", "/a/%FF"] {
        assert_eq!(p(bad), Err(Reject::NonCanonicalPath), "{bad}");
    }
    assert!(p("/a/..%00x").is_err());
    for ok in ["/a/..b", "/a/...", "/a/x..;y", "/a/.well-known/x", "/a/;/b", "/a/x%20y", "/a/%C3%A9", "/a/100%25"] {
        assert!(p(ok).is_ok(), "{ok}");
    }
    assert_eq!(p("/a//b"), Err(Reject::NonCanonicalPath));
    assert_eq!(p("/a\\b"), Err(Reject::ForbiddenByte(b'\\')));
    assert_eq!(p("/a#frag"), Err(Reject::ForbiddenByte(b'#')));
    assert_eq!(p("/a%zz"), Err(Reject::NonCanonicalPath));
    assert_eq!(p("/a%4"), Err(Reject::NonCanonicalPath));
    assert_eq!(p("a/b"), Err(Reject::NonCanonicalPath));
    assert_eq!(p("http://x/a"), Err(Reject::NonCanonicalPath));
    assert_eq!(p("/a b"), Err(Reject::ForbiddenByte(b' ')));
}

// --- Adversarial review (review-tls): address classes -----------------------

/// Cloud credential and metadata endpoints must be `Metadata` (denied unless a
/// grant names that class), like the ECS endpoint 169.254.170.2 already is.
/// These are classified `Private` or `LinkLocal` instead, so a grant that
/// allows `private` (the documented way to reach intranet hosts) also admits
/// the EKS Pod Identity credential endpoint over IPv6 and the GCP metadata
/// server on IPv6-only VMs, for any admitted name that resolves to them.
/// Sources: AWS EKS docs (Pod Identity Agent on 169.254.170.23 and
/// [fd00:ec2::23]); GCP docs (metadata server at fd20:ce::254 on IPv6-only
/// instances).
#[test]
fn review_cloud_credential_endpoints_are_metadata() {
    let endpoints = [
        "fd00:ec2::23",   // AWS EKS Pod Identity Agent (IPv6): serves AWS credentials
        "169.254.170.23", // AWS EKS Pod Identity Agent (IPv4)
        "fd20:ce::254",   // GCP metadata server (IPv6-only VMs)
    ];
    let wrong: Vec<String> = endpoints
        .iter()
        .map(|s| (s, classify_addr(s.parse().unwrap())))
        .filter(|(_, c)| *c != AddrClass::Metadata)
        .map(|(s, c)| format!("{s} => {}", c.as_str()))
        .collect();
    assert!(wrong.is_empty(), "credential endpoints not classified as metadata: {wrong:?}");
}

/// RFC 8215 reserves 64:ff9b:1::/48 for local-use IPv4/IPv6 translation: a
/// translator maps these addresses to an embedded IPv4 address exactly as it
/// does for the well-known prefix 64:ff9b::/96, which `classify_addr` already
/// classifies by the embedded address. The local-use prefix is classified
/// `Public`, so an address that a local NAT64/CLAT translates to
/// 169.254.169.254, loopback or RFC 1918 passes as public. Where the IPv4
/// address sits depends on the prefix length the operator chose, so the safe
/// answer is "not public" (std's unstable `Ipv6Addr::is_global` also
/// excludes 64:ff9b:1::/48).
#[test]
fn review_local_use_nat64_prefix_is_not_public() {
    let addrs = [
        "64:ff9b:1::a9fe:a9fe", // /96 inside the local-use prefix: 169.254.169.254
        "64:ff9b:1::7f00:1",    // 127.0.0.1
        "64:ff9b:1::a00:1",     // 10.0.0.1
    ];
    let public: Vec<&str> =
        addrs.iter().copied().filter(|s| classify_addr(s.parse().unwrap()) == AddrClass::Public).collect();
    assert!(public.is_empty(), "local-use NAT64 addresses classified public: {public:?}");
}

/// Azure WireServer (168.63.129.16) serves the VM's agent configuration and
/// certificates: metadata, like IMDS.
#[test]
fn azure_wireserver_is_metadata() {
    let ip: std::net::IpAddr = "168.63.129.16".parse().unwrap();
    assert_eq!(classify_addr(ip), AddrClass::Metadata);
    let mapped: std::net::IpAddr = "64:ff9b::a83f:8110".parse().unwrap();
    assert_eq!(classify_addr(mapped), AddrClass::Metadata, "through the NAT64 well-known prefix too");
}
