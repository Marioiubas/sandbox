//! Built-in DNS-over-HTTPS / DNS-over-TLS endpoints, blocked by name at host
//! admission even when a broader grant would match (forbid wins). The query
//! name is an exfiltration channel; a DoH endpoint is a resolver the broker
//! does not control.

use netguard::CanonicalHost;

/// Names (and all their subdomains) that are DoH/DoT resolvers.
pub const DOH_NAMES: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "8888.google",
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "doh.opendns.com",
    "dns.umbrella.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "dns-unfiltered.adguard.com",
    "doh.dns.sb",
    "dns.twnic.tw",
    "doh.libredns.gr",
    "ordns.he.net",
    "dns.alidns.com",
    "doh.pub",
    "dns.controld.com",
    "freedns.controld.com",
    "doh.mullvad.net",
    "dns.mullvad.net",
    "dns0.eu",
    "doh.xfinity.com",
];

pub fn is_doh_endpoint(host: &CanonicalHost) -> bool {
    if host.is_ip_literal() {
        return false;
    }
    let h = host.as_str();
    DOH_NAMES
        .iter()
        .any(|d| h == *d || (h.len() > d.len() + 1 && h.ends_with(d) && h.as_bytes()[h.len() - d.len() - 1] == b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netguard::canon_host;

    #[test]
    fn matches_names_and_subdomains_only() {
        let t = |s: &str| is_doh_endpoint(&canon_host(s.as_bytes()).unwrap());
        assert!(t("dns.google"));
        assert!(t("mozilla.cloudflare-dns.com"));
        assert!(t("cloudflare-dns.com"));
        assert!(!t("notcloudflare-dns.com"));
        assert!(!t("google.com"));
        assert!(!t("api.github.com"));
        for d in DOH_NAMES {
            assert!(canon_host(d.as_bytes()).is_ok(), "{d} must canonicalise");
        }
    }
}
