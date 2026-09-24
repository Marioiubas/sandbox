//! Host patterns: the policy side of the same canonicaliser (I6).

use super::*;

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
