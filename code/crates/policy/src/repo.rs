//! Repository identity for git rules: `host[:port]/owner/repo`, computed
//! from canonical values only (I6). The same function names a repository
//! whether it comes from policy text, the session's `.git/config` remote or
//! a request path, so they compare by construction.

use netguard::{CanonicalHost, canon_host};
use std::fmt;

/// A repository: canonical host, non-default port, lower-case owner and
/// name without `.git`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepoId {
    authority: String,
    owner: String,
    name: String,
}

fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn authority(host: &CanonicalHost, port: u16) -> String {
    if port == 443 { host.as_str().to_string() } else { format!("{}:{port}", host.as_str()) }
}

impl RepoId {
    pub fn new(host: &CanonicalHost, port: u16, owner: &str, name: &str) -> Option<RepoId> {
        // Lower-case first, so `Web.GIT` and `web` are one repository; one
        // `.git` suffix is URL syntax, and a name still ending in `.git`
        // after it is refused (parsing stays idempotent: fuzz target
        // `remote_url`).
        let lower = name.to_ascii_lowercase();
        let name = lower.strip_suffix(".git").unwrap_or(&lower);
        if !segment_ok(owner) || !segment_ok(name) || name.ends_with(".git") {
            return None;
        }
        Some(RepoId { authority: authority(host, port), owner: owner.to_ascii_lowercase(), name: name.to_string() })
    }

    /// Parse `host[:port]/owner/repo` (policy text).
    pub fn parse(s: &str) -> Option<RepoId> {
        let mut it = s.splitn(3, '/');
        let (auth, owner, name) = (it.next()?, it.next()?, it.next()?);
        let (host, port) = split_host_port(auth)?;
        RepoId::new(&canon_host(host.as_bytes()).ok()?, port, owner, name)
    }

    /// The repository a git remote URL names, as the sandbox's git will
    /// reach it: SSH forms map to HTTPS on 443 (the sandbox rewrites them),
    /// `https://` keeps its port. Userinfo is dropped; anything else fails.
    pub fn from_remote_url(url: &str) -> Option<RepoId> {
        let url = url.trim();
        let (auth, path, https) = if let Some(rest) = url.strip_prefix("https://") {
            let (auth, path) = rest.split_once('/')?;
            (auth, path, true)
        } else if let Some(rest) = url.strip_prefix("ssh://") {
            let (auth, path) = rest.split_once('/')?;
            (auth, path, false)
        } else if !url.contains("://") {
            // scp-like `[user@]host:owner/repo`
            let (auth, path) = url.split_once(':')?;
            (auth, path, false)
        } else {
            return None;
        };
        let auth = auth.rsplit_once('@').map(|(_, h)| h).unwrap_or(auth);
        let (host, port) = split_host_port(auth)?;
        let port = if https { port } else { 443 };
        let path = path.strip_suffix('/').unwrap_or(path);
        let mut segs = path.split('/');
        let (owner, name) = (segs.next()?, segs.next()?);
        if segs.next().is_some() {
            return None;
        }
        RepoId::new(&canon_host(host.as_bytes()).ok()?, port, owner, name)
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn name(&self) -> &str {
        &self.name
    }
}

fn split_host_port(auth: &str) -> Option<(&str, u16)> {
    match auth.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let port: u16 = p.parse().ok()?;
            (port != 0).then_some((h, port))
        }
        Some(_) => None, // bare IPv6 without brackets
        None => Some((auth, 443)),
    }
}

impl fmt::Display for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.authority, self.owner, self.name)
    }
}

/// `host/owner/repo` or `host/owner/*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoPattern {
    Exact(RepoId),
    Owner {
        authority: String,
        owner: String,
    },
    /// A pattern whose variable could not be resolved (for example
    /// `${repo_remote}` outside a git checkout): matches nothing.
    Nothing(String),
}

impl RepoPattern {
    pub fn parse(s: &str, repo_remote: Option<&RepoId>) -> Result<RepoPattern, String> {
        if s == "${repo_remote}" {
            return Ok(match repo_remote {
                Some(r) => RepoPattern::Exact(r.clone()),
                None => RepoPattern::Nothing(s.to_string()),
            });
        }
        if s.contains("${") {
            return Err(format!("unknown variable in repository pattern {s:?}"));
        }
        if let Some(prefix) = s.strip_suffix("/*") {
            let probe = RepoId::parse(&format!("{prefix}/x")).ok_or_else(|| format!("bad repository pattern {s:?}"))?;
            return Ok(RepoPattern::Owner { authority: probe.authority, owner: probe.owner });
        }
        RepoId::parse(s).map(RepoPattern::Exact).ok_or_else(|| format!("bad repository pattern {s:?}"))
    }

    pub fn matches(&self, r: &RepoId) -> bool {
        match self {
            RepoPattern::Exact(x) => x == r,
            RepoPattern::Owner { authority, owner } => &r.authority == authority && &r.owner == owner,
            RepoPattern::Nothing(_) => false,
        }
    }
}

/// A ref glob: `agent/*` means `refs/heads/agent/*`; `refs/...` is taken
/// as written. `*` has Cedar `like` semantics: any characters, `/`
/// included (so `agent/*` covers `agent/a/b`; ADR-022).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefPattern(String);

impl RefPattern {
    pub fn parse(s: &str) -> Result<RefPattern, String> {
        let full = if s.starts_with("refs/") { s.to_string() } else { format!("refs/heads/{s}") };
        let probe = full.replace('*', "x");
        if !valid_refname(&probe) {
            return Err(format!("bad ref pattern {s:?}"));
        }
        Ok(RefPattern(full))
    }

    pub fn matches(&self, refname: &str) -> bool {
        crate::glob::like_glob(&self.0, refname)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RefPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A strict subset of `git check-ref-format`: `refs/` prefix, at least two
/// more components, no control bytes, space, `~^:?*[\`, `..`, `@{`, `//`,
/// component starting with `.` or ending with `.lock`, trailing `/` or `.`.
pub fn valid_refname(r: &str) -> bool {
    if r.len() > 1024 || !r.starts_with("refs/") || r.ends_with('/') || r.ends_with('.') {
        return false;
    }
    if r.contains("..") || r.contains("@{") || r.contains("//") || r == "@" {
        return false;
    }
    if r.bytes().any(|b| b < 0x21 || b == 0x7f || b"~^:?*[\\".contains(&b)) {
        return false;
    }
    let comps: Vec<&str> = r.split('/').collect();
    comps.len() >= 3 && comps.iter().all(|c| !c.is_empty() && !c.starts_with('.') && !c.ends_with(".lock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_url_forms_agree() {
        let want = RepoId::parse("github.com/acme/web").unwrap();
        for u in [
            "https://github.com/acme/web.git",
            "https://github.com/Acme/Web",
            "https://x-access-token@github.com/acme/web.git/",
            "git@github.com:acme/web.git",
            "ssh://git@github.com/acme/web.git",
            "ssh://git@GitHub.com:22/acme/web",
        ] {
            assert_eq!(RepoId::from_remote_url(u).as_ref(), Some(&want), "{u}");
        }
        assert_eq!(want.to_string(), "github.com/acme/web");
        let p = RepoId::from_remote_url("https://git.test:8443/a/b.git").unwrap();
        assert_eq!(p.to_string(), "git.test:8443/a/b");
        for bad in [
            "https://github.com/acme",
            "https://github.com/acme/web/extra",
            "https://github.com/../web",
            "file:///tmp/repo",
            "https://git\u{0}hub.com/a/b",
            "https://github.com:0/a/b",
            "https://github.com/a%2fb/c",
            "/local/path",
        ] {
            assert!(RepoId::from_remote_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_git_suffix_in_any_case_names_the_same_repository() {
        // Regression (fuzz target `remote_url`, CI 2026-09-25): `.GIT` survived
        // the first parse and was stripped by the second.
        let a = RepoId::from_remote_url("https://github.com/Acme/Web.GIT").unwrap();
        assert_eq!(a, RepoId::parse("github.com/acme/web").unwrap());
        assert_eq!(RepoId::parse(&a.to_string()), Some(a));
        let odd = "fs.lggggggggggggggggggggggggggggggggggggggggggg.gitz";
        let r =
            RepoId::from_remote_url(&format!("https://{odd}/6/zs.lggggggggggggggggggggggggggggggggggggggggggg.GIT"));
        if let Some(r) = r {
            assert_eq!(RepoId::parse(&r.to_string()), Some(r));
        }
        for bad in ["github.com/acme/web.git.git", "github.com/acme/.git", "github.com/acme/x.GIT.git"] {
            assert_eq!(RepoId::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn patterns() {
        let r = RepoId::parse("github.com/acme/web").unwrap();
        assert!(RepoPattern::parse("github.com/acme/*", None).unwrap().matches(&r));
        assert!(!RepoPattern::parse("github.com/evil/*", None).unwrap().matches(&r));
        assert!(RepoPattern::parse("${repo_remote}", Some(&r)).unwrap().matches(&r));
        let none = RepoPattern::parse("${repo_remote}", None).unwrap();
        assert!(!none.matches(&r), "an unresolved variable grants nothing");
        assert!(RepoPattern::parse("${user}/x", None).is_err());
        assert!(RepoPattern::parse("github.com/*/*", None).is_err());
    }

    #[test]
    fn refs() {
        let p = RefPattern::parse("agent/*").unwrap();
        assert!(p.matches("refs/heads/agent/fix-1"));
        assert!(p.matches("refs/heads/agent/a/b"), "Cedar like: * spans components");
        assert!(!p.matches("refs/heads/main"));
        assert!(!p.matches("refs/tags/agent/x"));
        assert!(RefPattern::parse("refs/tags/v*").unwrap().matches("refs/tags/v1.2"));
        for bad in ["refs/heads/a..b", "refs/heads/x.lock", "refs/heads/@{x}", "refs/heads/a b", "refs/heads/.x"] {
            assert!(!valid_refname(bad), "{bad}");
        }
        assert!(valid_refname("refs/heads/agent/fix-123"));
        assert!(!valid_refname("refs/heads"));
        assert!(!valid_refname("HEAD"));
    }
}
