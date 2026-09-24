//! The two glob forms policy uses, both over canonical strings:
//! `*` matches any run of bytes except `/`; a whole `**` path segment
//! matches zero or more segments. No other metacharacters exist.

/// `*` within one `/`-separated component.
pub fn segment_glob(pat: &str, s: &str) -> bool {
    let (p, s) = (pat.as_bytes(), s.as_bytes());
    // Iterative wildcard match with backtracking to the last star.
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, si));
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some((sp, ss)) = star {
            // The star may not swallow a separator.
            if s[ss] == b'/' {
                return false;
            }
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// A path pattern such as `/v1/messages`, `/repos/*/*/issues` or `/api/**`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathPattern {
    text: String,
    segs: Vec<String>,
}

impl PathPattern {
    pub fn parse(s: &str) -> Result<PathPattern, String> {
        if !s.starts_with('/') {
            return Err(format!("path pattern {s:?} must start with /"));
        }
        if s.bytes().any(|b| b < 0x21 || b == 0x7f || b == b'?' || b == b'#' || b == b'%' || b == b'\\') {
            return Err(format!("path pattern {s:?} contains a forbidden byte"));
        }
        let segs: Vec<String> = s[1..].split('/').map(str::to_string).collect();
        for (i, seg) in segs.iter().enumerate() {
            if seg == "." || seg == ".." {
                return Err(format!("path pattern {s:?} contains a dot segment"));
            }
            if seg.contains("**") && seg != "**" {
                return Err(format!("path pattern {s:?}: ** must be a whole segment"));
            }
            if seg == "**" && i + 1 != segs.len() {
                return Err(format!("path pattern {s:?}: ** may only be the last segment"));
            }
            if seg.is_empty() && i + 1 != segs.len() {
                return Err(format!("path pattern {s:?} contains an empty segment"));
            }
        }
        Ok(PathPattern { text: s.to_string(), segs })
    }

    /// Match a canonical path (from `netguard::canon_path`), query excluded.
    pub fn matches(&self, path: &str) -> bool {
        let Some(rest) = path.strip_prefix('/') else { return false };
        let segs: Vec<&str> = rest.split('/').collect();
        match_segs(&self.segs, &segs)
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn segments(&self) -> &[String] {
        &self.segs
    }
}

/// Cedar `like` semantics: `*` matches any run of bytes, `/` included.
pub fn like_glob(pat: &str, s: &str) -> bool {
    let (p, s) = (pat.as_bytes(), s.as_bytes());
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, si));
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

fn match_segs(p: &[String], s: &[&str]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((first, rest)) if first == "**" => (0..=s.len()).any(|k| match_segs(rest, &s[k..])),
        Some((first, rest)) => match s.split_first() {
            Some((seg, srest)) => segment_glob(first, seg) && match_segs(rest, srest),
            None => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn segment_globs() {
        assert!(segment_glob("refs/heads/agent/*", "refs/heads/agent/x"));
        assert!(segment_glob("refs/heads/agent/*", "refs/heads/agent/"));
        assert!(!segment_glob("refs/heads/agent/*", "refs/heads/agent/x/y"));
        assert!(segment_glob("a*b*c", "aXXbYYc"));
        assert!(!segment_glob("a*b*c", "aXXbYY/c"));
        assert!(segment_glob("exact", "exact"));
        assert!(!segment_glob("exact", "exact2"));
    }

    #[test]
    fn path_patterns() {
        let p = PathPattern::parse("/v1/messages").unwrap();
        assert!(p.matches("/v1/messages"));
        assert!(!p.matches("/v1/messages/batches"));
        assert!(!p.matches("/v1/messagesX"));
        let p = PathPattern::parse("/repos/*/*/issues").unwrap();
        assert!(p.matches("/repos/acme/web/issues"));
        assert!(!p.matches("/repos/acme/issues"));
        let p = PathPattern::parse("/api/**").unwrap();
        assert!(p.matches("/api/"));
        assert!(p.matches("/api/a/b/c"));
        assert!(!p.matches("/apix/a"));
        let p = PathPattern::parse("/**").unwrap();
        assert!(p.matches("/"));
        assert!(p.matches("/anything/at/all"));
        assert!(like_glob("refs/heads/agent/*", "refs/heads/agent/a/b"));
        assert!(!like_glob("refs/heads/agent/*", "refs/heads/main"));
        for bad in ["v1", "/a/../b", "/a/**x", "/a//b", "/a?x", "/a%2f", "/a b", "/a/**/b"] {
            assert!(PathPattern::parse(bad).is_err(), "{bad}");
        }
    }

    /// Exponential reference implementation for differential testing.
    fn reference(p: &[u8], s: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => {
                (0..=s.len()).take_while(|&k| !s[..k].contains(&b'/')).any(|k| reference(rest, &s[k..]))
            }
            Some((c, rest)) => s.first() == Some(c) && reference(rest, &s[1..]),
        }
    }

    proptest! {
        #[test]
        fn matches_reference(p in "[ab/*]{0,8}", s in "[ab/]{0,10}") {
            prop_assert_eq!(segment_glob(&p, &s), reference(p.as_bytes(), s.as_bytes()), "{:?} {:?}", p, s);
        }

        #[test]
        fn star_never_crosses_a_separator(a in "[a-z]{0,5}", b in "[a-z]{0,5}") {
            let s = format!("pre/{a}/{b}");
            prop_assert!(!segment_glob("pre/*", &s));
            prop_assert!(segment_glob("pre/*/*", &s));
        }

        #[test]
        fn literal_pattern_matches_only_itself(s in "/[a-z0-9/]{0,20}", t in "/[a-z0-9/]{0,20}") {
            if let Ok(p) = PathPattern::parse(&s) {
                prop_assert_eq!(p.matches(&t), s == t);
            }
        }
    }
}
