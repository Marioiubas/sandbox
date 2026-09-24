//! G2: collapse identifiers before counting, so every PR number or commit
//! SHA is not a separate rule. A segment becomes `*` when it is a decimal
//! number, a hex digest (7+ hex digits with a digit), a UUID, or a long
//! opaque token.

pub fn is_identifier(seg: &str) -> bool {
    let b = seg.as_bytes();
    if b.is_empty() {
        return false;
    }
    if b.iter().all(u8::is_ascii_digit) {
        return true;
    }
    let hex = b.iter().all(u8::is_ascii_hexdigit);
    if hex && b.len() >= 7 && b.iter().any(u8::is_ascii_digit) {
        return true;
    }
    if b.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
        && b.iter().all(|c| c.is_ascii_hexdigit() || *c == b'-')
    {
        return true;
    }
    let digits = b.iter().filter(|c| c.is_ascii_digit()).count();
    let alpha = b.iter().filter(|c| c.is_ascii_alphabetic()).count();
    b.len() >= 20 && digits >= 3 && alpha >= 3 && b.iter().all(|c| c.is_ascii_alphanumeric() || b"-_".contains(c))
}

/// A canonical path with identifier segments replaced by `*`.
pub fn template(path: &str) -> String {
    let rest = path.strip_prefix('/').unwrap_or(path);
    let segs: Vec<&str> = rest.split('/').map(|s| if is_identifier(s) { "*" } else { s }).collect();
    format!("/{}", segs.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_collapse() {
        assert_eq!(template("/repos/acme/web/pulls/1234"), "/repos/acme/web/pulls/*");
        assert_eq!(
            template("/repos/acme/web/commits/9fceb02d0ae598e95dc970b74767f19372d61af8"),
            "/repos/acme/web/commits/*"
        );
        assert_eq!(template("/v1/files/123e4567-e89b-12d3-a456-426614174000"), "/v1/files/*");
        assert_eq!(template("/v1/messages"), "/v1/messages");
        assert_eq!(template("/api/v2/deadbeef"), "/api/v2/deadbeef", "short hex words stay");
        assert_eq!(template("/"), "/");
    }
}
