//! Built-in host categories for the org ceiling (Policy Miner Safeguards,
//! P3). A host is in a category when it equals a listed name or is a
//! subdomain of one (label boundary). An org bundle may extend the lists.

use crate::doh::DOH_NAMES;
use netguard::CanonicalHost;

/// Paste and anonymous file-drop services (exfiltration sinks).
pub const PASTE_NAMES: &[&str] = &[
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "hastebin.skyra.pw",
    "dpaste.org",
    "dpaste.com",
    "termbin.com",
    "0x0.st",
    "transfer.sh",
    "file.io",
    "paste.rs",
    "rentry.co",
    "rentry.org",
    "ix.io",
    "sprunge.us",
    "controlc.com",
    "justpaste.it",
    "privatebin.net",
    "ghostbin.site",
    "paste.gg",
    "pastes.dev",
    "bpa.st",
    "gist.github.com",
    "webhook.site",
    "requestbin.net",
    "pipedream.net",
];

/// Tunnel and ingress-forwarding services.
pub const TUNNEL_NAMES: &[&str] = &[
    "ngrok.io",
    "ngrok.app",
    "ngrok-free.app",
    "ngrok-free.dev",
    "ngrok.dev",
    "trycloudflare.com",
    "loca.lt",
    "localtunnel.me",
    "serveo.net",
    "pagekite.me",
    "localhost.run",
    "lhr.life",
    "bore.pub",
    "tunnelto.dev",
    "telebit.cloud",
    "localxpose.io",
    "pinggy.link",
];

fn in_list(host: &CanonicalHost, list: &[&str]) -> bool {
    let h = host.as_str();
    list.iter()
        .any(|n| h == *n || (h.len() > n.len() + 1 && h.ends_with(n) && h.as_bytes()[h.len() - n.len() - 1] == b'.'))
}

/// The categories of a canonical host.
pub fn categories(host: &CanonicalHost) -> Vec<&'static str> {
    let mut c = Vec::new();
    if host.is_ip_literal() {
        return c;
    }
    if in_list(host, DOH_NAMES) {
        c.push("doh");
    }
    if in_list(host, PASTE_NAMES) {
        c.push("paste");
    }
    if in_list(host, TUNNEL_NAMES) {
        c.push("tunnel");
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use netguard::canon_host;

    #[test]
    fn membership_is_label_bounded() {
        let c = |s: &str| categories(&canon_host(s.as_bytes()).unwrap());
        assert_eq!(c("pastebin.com"), vec!["paste"]);
        assert_eq!(c("www.pastebin.com"), vec!["paste"]);
        assert!(c("notpastebin.com").is_empty());
        assert_eq!(c("abc.ngrok-free.app"), vec!["tunnel"]);
        assert_eq!(c("mozilla.cloudflare-dns.com"), vec!["doh"]);
        assert!(c("api.github.com").is_empty());
        assert!(c("1.1.1.1").is_empty());
    }
}
