use super::*;
use netguard::canon_host;

fn entry(host: &str) -> EgressEntry {
    EgressEntry { host: host.into(), ..Default::default() }
}
fn h(s: &str) -> CanonicalHost {
    canon_host(s.as_bytes()).unwrap()
}

#[test]
fn empty_policy_denies_everything() {
    let p = EgressPolicy::compile([("user", &[][..])]).unwrap();
    assert!(p.is_empty());
    assert_eq!(p.admit_host(&h("api.github.com"), 443).unwrap_err().0, Reason::HostNotAllowed);
    assert_eq!(p.admit_host(&h("8.8.8.8"), 443).unwrap_err().0, Reason::IpLiteral);
}

#[test]
fn name_port_and_classes() {
    let entries = vec![
        entry("api.github.com"),
        EgressEntry { host: "*.example.com".into(), ports: Some(vec![443, 8443]), ..Default::default() },
        EgressEntry { host: "no-ports.test".into(), ports: Some(vec![]), ..Default::default() },
        EgressEntry { host: "local.test".into(), allow_addr_classes: vec!["loopback".into()], ..Default::default() },
    ];
    let p = EgressPolicy::compile([("user", entries.as_slice())]).unwrap();
    let a = p.admit_host(&h("API.GitHub.com"), 443).unwrap();
    assert_eq!(a.policy_ids, vec!["user:egress[0]"]);
    assert_eq!(p.admit_host(&h("api.github.com"), 22).unwrap_err().0, Reason::PortNotAllowed);
    assert_eq!(p.admit_host(&h("github.com"), 443).unwrap_err().0, Reason::HostNotAllowed);
    assert!(p.admit_host(&h("a.example.com"), 8443).is_ok());
    assert_eq!(p.admit_host(&h("example.com"), 443).unwrap_err().0, Reason::HostNotAllowed);
    assert_eq!(p.admit_host(&h("no-ports.test"), 443).unwrap_err().0, Reason::PortNotAllowed);

    // Resolved-address checks.
    let a = p.admit_host(&h("api.github.com"), 443).unwrap();
    assert!(p.admit_addrs(&mut a.clone(), &["140.82.112.5".parse().unwrap()]).is_ok());
    assert_eq!(
        p.admit_addrs(&mut a.clone(), &["169.254.169.254".parse().unwrap()]).unwrap_err().0,
        Reason::MetadataAddr
    );
    assert_eq!(
        p.admit_addrs(&mut a.clone(), &["140.82.112.5".parse().unwrap(), "10.0.0.1".parse().unwrap()]).unwrap_err().0,
        Reason::PrivateAddr,
        "one bad address denies the whole name"
    );
    let l = p.admit_host(&h("local.test"), 443).unwrap();
    assert!(p.admit_addrs(&mut l.clone(), &["127.0.0.1".parse().unwrap()]).is_ok());
    assert_eq!(
        p.admit_addrs(&mut l.clone(), &["169.254.169.254".parse().unwrap()]).unwrap_err().0,
        Reason::MetadataAddr
    );
}

#[test]
fn explicit_ip_literal_grant() {
    let entries = vec![entry("10.1.2.3")];
    let p = EgressPolicy::compile([("user", entries.as_slice())]).unwrap();
    let a = p.admit_host(&h("10.1.2.3"), 443).unwrap();
    assert!(p.admit_addrs(&mut a.clone(), &["10.1.2.3".parse().unwrap()]).is_ok());
    assert_eq!(p.admit_host(&h("10.1.2.4"), 443).unwrap_err().0, Reason::IpLiteral);
}

#[test]
fn doh_is_denied_even_when_granted() {
    let entries = vec![entry("*.cloudflare-dns.com"), entry("dns.google")];
    let p = EgressPolicy::compile([("user", entries.as_slice())]).unwrap();
    assert_eq!(p.admit_host(&h("mozilla.cloudflare-dns.com"), 443).unwrap_err().0, Reason::DohEndpoint);
    assert_eq!(p.admit_host(&h("dns.google"), 443).unwrap_err().0, Reason::DohEndpoint);
}

#[test]
fn compile_errors() {
    for bad in ["*", "*.com", "exa\u{0}mple.com", "example.com.", "0x7f.1"] {
        let e = vec![entry(bad)];
        assert!(EgressPolicy::compile([("user", e.as_slice())]).is_err(), "{bad:?}");
    }
    let e = vec![EgressEntry { host: "a.com".into(), addrs: vec!["0177.0.0.1".into()], ..Default::default() }];
    assert!(EgressPolicy::compile([("user", e.as_slice())]).is_err(), "pinned addrs are canonicalised too");
    let e = vec![EgressEntry { host: "a.com".into(), ports: Some(vec![0]), ..Default::default() }];
    assert!(EgressPolicy::compile([("user", e.as_slice())]).is_err());
    let e =
        vec![EgressEntry { host: "a.com".into(), allow_addr_classes: vec!["everything".into()], ..Default::default() }];
    assert!(EgressPolicy::compile([("user", e.as_slice())]).is_err());
    let e = vec![
        EgressEntry { host: "a.com".into(), id: Some("x".into()), ..Default::default() },
        EgressEntry { host: "b.com".into(), id: Some("x".into()), ..Default::default() },
    ];
    assert!(EgressPolicy::compile([("user", e.as_slice())]).is_err());
}
