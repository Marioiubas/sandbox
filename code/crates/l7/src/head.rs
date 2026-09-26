//! Request-head checks on a terminated connection (pipeline steps 2-3).
//!
//! CONNECT target = SNI = `Host` (and any absolute-form authority), all
//! compared as canonical values (I6), which blunts domain fronting. The
//! path is canonicalised by the same canonicaliser; what cannot be is
//! denied. Upgrades are refused: frames after an upgrade are opaque.

use audit::Reason;
use http::{HeaderMap, HeaderName, Method, request::Parts};
use netguard::{CanonicalHost, CanonicalPath, canon_host, canon_path};

/// Split `host[:port]` (brackets for IPv6) from a Host header or authority.
fn split_authority(a: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = a.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        return match tail {
            "" => Some((&a[..h.len() + 2], None)),
            t => Some((&a[..h.len() + 2], Some(t.strip_prefix(':')?.parse().ok().filter(|p| *p != 0)?))),
        };
    }
    match a.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.len() > 5 {
                return None;
            }
            Some((h, Some(p.parse().ok().filter(|p| *p != 0)?)))
        }
        Some(_) => None,
        None => Some((a, None)),
    }
}

fn same_target(authority: &str, host: &CanonicalHost, port: u16) -> bool {
    let Some((h, p)) = split_authority(authority) else { return false };
    let Ok(c) = canon_host(h.as_bytes()) else { return false };
    c == *host && p.unwrap_or(443) == port
}

/// Request heads larger than this are refused (hyper's own buffer limit is
/// not a head limit on a TLS stream).
pub const MAX_HEAD_BYTES: usize = 64 << 10;
pub const MAX_HEAD_FIELDS: usize = 128;

/// Validate the head and return the canonical path.
pub fn check(parts: &Parts, host: &CanonicalHost, port: u16) -> Result<CanonicalPath, Reason> {
    let size: usize =
        parts.headers.iter().map(|(k, v)| k.as_str().len() + v.len() + 4).sum::<usize>() + parts.uri.to_string().len();
    if size > MAX_HEAD_BYTES || parts.headers.len() > MAX_HEAD_FIELDS {
        return Err(Reason::HeadTooLarge);
    }
    if parts.method == Method::CONNECT || parts.headers.contains_key(http::header::UPGRADE) {
        return Err(Reason::UpgradeNotAllowed);
    }
    // Frameworks (Rack's MethodOverride, others) run the method these name
    // instead of the request's: a POST the broker allowed could become a
    // DELETE upstream. Refused rather than stripped.
    if METHOD_OVERRIDE.iter().any(|h| parts.headers.contains_key(*h)) {
        return Err(Reason::MethodOverride);
    }
    if let Some(a) = parts.uri.authority()
        && (parts.uri.scheme_str() != Some("https") || !same_target(a.as_str(), host, port))
    {
        return Err(Reason::HostHeaderMismatch);
    }
    let mut hosts = parts.headers.get_all(http::header::HOST).iter();
    match (hosts.next(), hosts.next()) {
        (Some(v), None) => {
            let v = v.to_str().map_err(|_| Reason::HostHeaderMismatch)?;
            if !same_target(v, host, port) {
                return Err(Reason::HostHeaderMismatch);
            }
        }
        // HTTP/1.0 without Host is fine only when the URI carried the authority.
        (None, _) if parts.uri.authority().is_some() => {}
        _ => return Err(Reason::HostHeaderMismatch),
    }
    let pq = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("");
    canon_path(pq.as_bytes()).map_err(|r| r.reason())
}

/// Headers some servers read as the request's real method.
const METHOD_OVERRIDE: &[&str] = &["x-http-method-override", "x-http-method", "x-method-override"];

/// Headers that belong to one hop and are never forwarded.
const HOP_BY_HOP: &[&str] =
    &["connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"];

pub fn strip_hop_by_hop(h: &mut HeaderMap) {
    let listed: Vec<HeaderName> = h
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    for n in listed {
        h.remove(n);
    }
    for n in HOP_BY_HOP {
        h.remove(*n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn parts(uri: &str, host: Option<&str>) -> Parts {
        let mut b = http::Request::builder().method("GET").uri(uri);
        if let Some(h) = host {
            b = b.header("host", h);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn api() -> CanonicalHost {
        canon_host(b"api.github.com").unwrap()
    }

    #[test]
    fn fronting_is_denied() {
        assert_eq!(check(&parts("/repos", Some("api.github.com")), &api(), 443).unwrap().path(), "/repos");
        assert!(check(&parts("/repos", Some("API.GitHub.com:443")), &api(), 443).is_ok());
        assert!(check(&parts("https://api.github.com/x", None), &api(), 443).is_ok());
        let deny = [
            parts("/repos", Some("evil.example")),
            parts("/repos", Some("api.github.com:8443")),
            parts("/repos", Some("api.github.com.")),
            parts("/repos", Some("api.github.com%00")),
            parts("/repos", None),
            parts("https://evil.example/x", Some("api.github.com")),
            parts("http://api.github.com/x", Some("api.github.com")),
        ];
        for p in deny {
            assert_eq!(check(&p, &api(), 443).unwrap_err(), Reason::HostHeaderMismatch, "{:?}", p.uri);
        }
        let mut two = parts("/", Some("api.github.com"));
        two.headers.append("host", "evil.example".parse().unwrap());
        assert_eq!(check(&two, &api(), 443).unwrap_err(), Reason::HostHeaderMismatch);
        let v6 = canon_host(b"[2001:db8::1]").unwrap();
        assert!(check(&parts("/", Some("[2001:db8::1]:8443")), &v6, 8443).is_ok());
    }

    #[test]
    fn paths_and_upgrades() {
        assert_eq!(check(&parts("/a/%2e%2e/b", Some("api.github.com")), &api(), 443).unwrap_err(), Reason::DotSegment);
        assert_eq!(check(&parts("/a%2fb", Some("api.github.com")), &api(), 443).unwrap_err(), Reason::EncodedSeparator);
        let mut big = parts("/", Some("api.github.com"));
        big.headers.insert("x-big", "a".repeat(MAX_HEAD_BYTES).parse().unwrap());
        assert_eq!(check(&big, &api(), 443).unwrap_err(), Reason::HeadTooLarge);
        let mut many = parts("/", Some("api.github.com"));
        for i in 0..MAX_HEAD_FIELDS {
            many.headers
                .insert(http::HeaderName::from_bytes(format!("x-{i}").as_bytes()).unwrap(), "1".parse().unwrap());
        }
        assert_eq!(check(&many, &api(), 443).unwrap_err(), Reason::HeadTooLarge);
        let mut up = parts("/", Some("api.github.com"));
        up.headers.insert("upgrade", "websocket".parse().unwrap());
        assert_eq!(check(&up, &api(), 443).unwrap_err(), Reason::UpgradeNotAllowed);
        for name in ["X-HTTP-Method-Override", "x-http-method", "X-Method-Override"] {
            let mut o = parts("/", Some("api.github.com"));
            o.headers.insert(http::HeaderName::from_bytes(name.as_bytes()).unwrap(), "DELETE".parse().unwrap());
            assert_eq!(check(&o, &api(), 443).unwrap_err(), Reason::MethodOverride, "{name}");
        }
        let mut h = HeaderMap::new();
        h.insert("connection", "keep-alive, x-secret-hop".parse().unwrap());
        h.insert("x-secret-hop", "1".parse().unwrap());
        h.insert("te", "trailers".parse().unwrap());
        h.insert("x-keep", "1".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1);
    }

    proptest! {
        #[test]
        fn only_the_admitted_host_passes(name in "[a-z]{1,10}\\.[a-z]{2,5}") {
            let p = parts("/", Some(&name));
            let ok = check(&p, &api(), 443).is_ok();
            prop_assert_eq!(ok, name == "api.github.com");
        }
    }
}
