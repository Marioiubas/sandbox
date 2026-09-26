//! The GitHub API adapter (GitHub API Adapter): every REST request on a
//! GitHub API host maps to one verb, or it is denied. Routes are the ones
//! GitHub documents (docs.github.com/en/rest, checked 2026-09-24):
//!
//! - `GET|HEAD /repos/{o}/{r}[/…]` → `repo.read` (issue and PR bodies flagged);
//! - `POST /repos/{o}/{r}/pulls` → `pr.create`;
//! - `PUT /repos/{o}/{r}/pulls/{n}/merge` → `pr.merge`;
//! - `POST /repos/{o}/{r}/issues/{n}/comments` → `issue.comment`;
//! - `PUT|DELETE /repos/{o}/{r}/contents/{path}` → `contents.write`;
//! - `POST /gists` → `gist.create`;
//! - other `GET|HEAD` → `github.read` (search results flagged as bodies);
//!   only the routes in [`PUBLIC_READS`] are known to return public data,
//!   every other host-wide read may return private repositories.
//!
//! `POST /graphql` (`/api/graphql` on GitHub Enterprise) is parsed by
//! [`graphql`]. Anything else is unknown: deny.

pub mod graphql;
pub mod schema;
mod strict_json;

use audit::Reason;
use netguard::{CanonicalHost, canon_host};
use policy::RepoId;

/// Host-wide read routes (first path segment) that return no repository or
/// account data: API metadata, rate limits, license and gitignore
/// templates, codes of conduct, emojis.
pub const PUBLIC_READS: &[&str] =
    &["rate_limit", "meta", "zen", "octocat", "emojis", "versions", "licenses", "gitignore", "codes_of_conduct"];

/// Repository sub-routes whose data is public on a public repository
/// (first path segment after `/repos/{o}/{r}`; `""` is the repository
/// itself). Everything else (secret-scanning and code-scanning alerts,
/// draft advisories, Dependabot, hooks, keys, invitations, collaborators,
/// traffic, environments, Actions secrets and variables, …) returns
/// maintainer-only data even on a public repository.
pub const PUBLIC_ON_PUBLIC: &[&str] = &[
    "",
    "contents",
    "git",
    "commits",
    "branches",
    "tags",
    "releases",
    "readme",
    "languages",
    "license",
    "topics",
    "contributors",
    "stargazers",
    "subscribers",
    "forks",
    "issues",
    "pulls",
    "labels",
    "milestones",
    "comments",
    "events",
    "compare",
    "check-runs",
    "check-suites",
    "statuses",
    "deployments",
    "tarball",
    "zipball",
    "commits-activity",
];

/// Actions sub-routes public on a public repository (`actions/<this>`).
const PUBLIC_ACTIONS: &[&str] = &["runs", "workflows", "jobs", "artifacts"];

/// Repository sub-routes carrying text anyone can write on a public
/// repository: issues, pull requests, comments, reviews, events.
const BODY_ROUTES: &[&str] = &["issues", "pulls", "comments", "events"];

/// A mapped request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub verb: &'static str,
    pub repo: Option<RepoId>,
    /// The response carries attacker-writable text: issue, PR or comment
    /// bodies, events, search results, or files at a pull request's ref.
    pub bodies: bool,
    /// A host-wide read known to return only public data.
    pub public: bool,
    /// A repository read of data that is not public even when the
    /// repository is (`PUBLIC_ON_PUBLIC` does not list the route).
    pub restricted: bool,
}

/// A `ref` query naming a pull request's ref or a commit by hash reads
/// files a pull request's author wrote, not the maintainers' branches.
fn ref_is_untrusted(query: Option<&str>) -> bool {
    query.into_iter().flat_map(|q| q.split('&')).filter_map(|kv| kv.strip_prefix("ref=")).any(|v| {
        let v = v.to_ascii_lowercase();
        v.starts_with("refs/pull/")
            || v.starts_with("refs%2fpull%2f")
            || (v.len() >= 7 && v.len() <= 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
    })
}

/// The repository host for a GitHub API host, and the API path segments
/// after the REST prefix; `None` for a path outside the API.
fn split<'p>(host: &CanonicalHost, segs: &'p [&'p str]) -> Option<(CanonicalHost, &'p [&'p str])> {
    if host.as_str() == "api.github.com" {
        Some((canon_host(b"github.com").ok()?, segs))
    } else if segs.len() >= 2 && segs[0] == "api" && segs[1] == "v3" {
        Some((host.clone(), &segs[2..]))
    } else {
        None
    }
}

/// The host repositories live on for a GitHub API host (`github.com` for
/// api.github.com; a GitHub Enterprise host serves both).
pub fn repo_host(api_host: &CanonicalHost) -> Option<CanonicalHost> {
    if api_host.as_str() == "api.github.com" { canon_host(b"github.com").ok() } else { Some(api_host.clone()) }
}

/// A GraphQL request must say it is JSON (`application/json`, optionally
/// `charset=utf-8`), once: a form-encoded body could carry a different
/// `query` for a server that reads forms.
pub fn graphql_content_type_ok(h: &http::HeaderMap) -> bool {
    let vals: Vec<&http::HeaderValue> = h.get_all(http::header::CONTENT_TYPE).iter().collect();
    let [v] = vals.as_slice() else { return false };
    let Ok(s) = v.to_str() else { return false };
    let mut parts = s.split(';').map(str::trim);
    parts.next().is_some_and(|m| m.eq_ignore_ascii_case("application/json"))
        && parts.all(|p| p.eq_ignore_ascii_case("charset=utf-8") || p.eq_ignore_ascii_case("charset=\"utf-8\""))
}

/// The GraphQL endpoint: `Some(Ok(repository host))` for a `POST` without
/// a query string, `Some(Err(_))` for any other request to it, `None`
/// when `path` is not the GraphQL endpoint.
pub fn graphql_endpoint(
    host: &CanonicalHost,
    method: &str,
    path: &str,
    query: Option<&str>,
) -> Option<Result<CanonicalHost, Reason>> {
    let authority = if host.as_str() == "api.github.com" && path == "/graphql" {
        canon_host(b"github.com").ok()?
    } else if host.as_str() != "api.github.com" && path == "/api/graphql" {
        host.clone()
    } else {
        return None;
    };
    Some(match (method, query) {
        ("POST", None) => Ok(authority),
        // A query string could carry a second `query` a server might prefer.
        ("POST", Some(_)) => Err(Reason::GithubGraphqlInvalid),
        _ => Err(Reason::GithubGraphqlUnsupported),
    })
}

fn number(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Map a request on a GitHub API host (`api.github.com`, or a GitHub
/// Enterprise host under `/api/v3`) to its verb. `path` is canonical;
/// `query` is the raw query string (read for a `ref` only).
pub fn route(host: &CanonicalHost, method: &str, path: &str, query: Option<&str>) -> Result<Route, Reason> {
    let all: Vec<&str> = path.split('/').skip(1).filter(|s| !s.is_empty()).collect();
    let (authority, segs) = split(host, &all).ok_or(Reason::GithubRouteUnknown)?;
    let read = matches!(method, "GET" | "HEAD");
    let repo = |o: &str, r: &str| RepoId::new(&authority, 443, o, r).ok_or(Reason::GithubRouteUnknown);
    let r = |verb, repo, bodies| Ok(Route { verb, repo, bodies, public: false, restricted: false });
    match segs {
        ["repos", o, n, rest @ ..] => {
            let repo = Some(repo(o, n)?);
            match (method, rest) {
                _ if read => {
                    let first = rest.first().copied().unwrap_or("");
                    let public = match rest {
                        ["actions", sub, ..] => PUBLIC_ACTIONS.contains(sub),
                        _ => PUBLIC_ON_PUBLIC.contains(&first),
                    };
                    let bodies = BODY_ROUTES.contains(&first) || ref_is_untrusted(query);
                    Ok(Route { verb: "repo.read", repo, bodies, public: false, restricted: !public })
                }
                ("POST", ["pulls"]) => r("pr.create", repo, false),
                ("PUT", ["pulls", n, "merge"]) if number(n) => r("pr.merge", repo, false),
                ("POST", ["issues", n, "comments"]) if number(n) => r("issue.comment", repo, false),
                ("PUT" | "DELETE", ["contents", _, ..]) => r("contents.write", repo, false),
                _ => Err(Reason::GithubRouteUnknown),
            }
        }
        ["graphql"] => Err(Reason::GithubGraphqlUnsupported),
        ["gists"] if method == "POST" => r("gist.create", None, false),
        [first, ..] if read && PUBLIC_READS.contains(first) => {
            Ok(Route { verb: "github.read", repo: None, bodies: false, public: true, restricted: false })
        }
        // Host-wide reads that return what anyone can write: search results,
        // gists, notifications, and repositories addressed by ID (where
        // GitHub redirects transferred issues).
        [first, ..] if read && matches!(*first, "search" | "gists" | "notifications" | "repositories") => {
            r("github.read", None, true)
        }
        _ if read => r("github.read", None, false),
        _ => Err(Reason::GithubRouteUnknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> CanonicalHost {
        canon_host(s.as_bytes()).unwrap()
    }

    fn ok(method: &str, path: &str) -> (String, Option<String>, bool) {
        let r = route(&h("api.github.com"), method, path, None).unwrap();
        (r.verb.to_string(), r.repo.map(|x| x.to_string()), r.bodies)
    }

    #[test]
    fn routes_map_to_verbs() {
        let web = Some("github.com/acme/web".to_string());
        assert_eq!(ok("GET", "/repos/acme/web"), ("repo.read".into(), web.clone(), false));
        assert_eq!(ok("GET", "/repos/acme/web/issues/7"), ("repo.read".into(), web.clone(), true));
        assert_eq!(ok("GET", "/repos/acme/web/pulls"), ("repo.read".into(), web.clone(), true));
        assert_eq!(ok("GET", "/repos/acme/web/contents/README.md"), ("repo.read".into(), web.clone(), false));
        assert_eq!(ok("POST", "/repos/acme/web/pulls"), ("pr.create".into(), web.clone(), false));
        assert_eq!(ok("PUT", "/repos/acme/web/pulls/12/merge"), ("pr.merge".into(), web.clone(), false));
        assert_eq!(ok("POST", "/repos/acme/web/issues/3/comments"), ("issue.comment".into(), web.clone(), false));
        assert_eq!(ok("PUT", "/repos/acme/web/contents/a/b.txt"), ("contents.write".into(), web.clone(), false));
        assert_eq!(ok("POST", "/gists"), ("gist.create".into(), None, false));
        assert_eq!(ok("GET", "/user"), ("github.read".into(), None, false));
        assert_eq!(ok("GET", "/search/issues"), ("github.read".into(), None, true));
        // Maintainer-only data under a public repository is restricted; the
        // repository's public parts are not.
        let restricted = |p: &str| route(&h("api.github.com"), "GET", p, None).unwrap().restricted;
        for p in [
            "/repos/acme/web/secret-scanning/alerts",
            "/repos/acme/web/security-advisories",
            "/repos/acme/web/actions/variables",
            "/repos/acme/web/actions/secrets",
            "/repos/acme/web/dependabot/alerts",
            "/repos/acme/web/code-scanning/alerts",
            "/repos/acme/web/hooks",
            "/repos/acme/web/invitations",
            "/repos/acme/web/traffic/views",
            "/repos/acme/web/environments",
            "/repos/acme/web/collaborators",
        ] {
            assert!(restricted(p), "{p}");
        }
        for p in [
            "/repos/acme/web",
            "/repos/acme/web/contents/a",
            "/repos/acme/web/issues/1",
            "/repos/acme/web/actions/runs",
        ] {
            assert!(!restricted(p), "{p}");
        }
        // Text anyone can write, including files at a pull request's ref.
        let bodies = |p: &str, q: Option<&str>| route(&h("api.github.com"), "GET", p, q).unwrap().bodies;
        for p in [
            "/repos/acme/web/comments",
            "/repos/acme/web/events",
            "/repositories/1/issues/1",
            "/gists/abc",
            "/notifications",
        ] {
            assert!(bodies(p, None), "{p}");
        }
        assert!(bodies("/repos/acme/web/contents/README.md", Some("ref=refs/pull/1/head")));
        assert!(bodies("/repos/acme/web/contents/README.md", Some("x=1&ref=4f2c1a9e")));
        assert!(!bodies("/repos/acme/web/contents/README.md", Some("ref=main")));
        assert!(!bodies("/repos/acme/web/contents/README.md", None));
        assert!(!bodies("/user", None));
        let g = h("api.github.com");
        assert!(route(&g, "GET", "/rate_limit", None).unwrap().public);
        assert!(route(&g, "GET", "/licenses/mit", None).unwrap().public);
        for p in ["/user", "/user/repos", "/search/code", "/orgs/acme/repos", "/notifications", "/gists"] {
            assert!(!route(&g, "GET", p, None).unwrap().public, "{p} may return private data");
        }
        let ghe = route(&h("ghe.corp.example"), "POST", "/api/v3/repos/acme/web/pulls", None).unwrap();
        assert_eq!(ghe.repo.unwrap().to_string(), "ghe.corp.example/acme/web");
    }

    proptest::proptest! {
        /// Any method and path: no panic; a mapped route is a known verb,
        /// read verbs only for GET/HEAD, repository verbs carry a repository.
        #[test]
        fn routes_are_total_and_consistent(
            method in proptest::prop_oneof![
                proptest::strategy::Just("GET"), proptest::strategy::Just("HEAD"), proptest::strategy::Just("POST"),
                proptest::strategy::Just("PUT"), proptest::strategy::Just("PATCH"), proptest::strategy::Just("DELETE"),
            ],
            segs in proptest::collection::vec("[a-z0-9._-]{0,8}", 0..7),
        ) {
            let path = format!("/{}", segs.join("/"));
            if let Ok(r) = route(&h("api.github.com"), method, &path, None) {
                proptest::prop_assert!(policy::github::is_verb(r.verb));
                if policy::github::is_read_verb(r.verb) {
                    proptest::prop_assert!(matches!(method, "GET" | "HEAD"));
                }
                proptest::prop_assert_eq!(policy::github::is_repo_verb(r.verb), r.repo.is_some());
            }
        }
    }

    #[test]
    fn unmapped_requests_deny() {
        let g = h("api.github.com");
        for (m, p) in [
            ("POST", "/repos/acme/web/issues"),
            ("PATCH", "/repos/acme/web/pulls/1"),
            ("PUT", "/repos/acme/web/pulls/x/merge"),
            ("DELETE", "/repos/acme/web"),
            ("POST", "/repos/acme/web/forks"),
            ("PATCH", "/gists/abc"),
            ("POST", "/user/repos"),
            ("PUT", "/repos/acme/web/contents"),
        ] {
            assert_eq!(route(&g, m, p, None), Err(Reason::GithubRouteUnknown), "{m} {p}");
        }
        assert_eq!(route(&g, "POST", "/graphql", None), Err(Reason::GithubGraphqlUnsupported));
        let github = || Some(Ok(h("github.com")));
        assert_eq!(graphql_endpoint(&g, "POST", "/graphql", None), github());
        assert_eq!(graphql_endpoint(&g, "POST", "/graphql", Some("query=x")), Some(Err(Reason::GithubGraphqlInvalid)));
        assert_eq!(graphql_endpoint(&g, "GET", "/graphql", None), Some(Err(Reason::GithubGraphqlUnsupported)));
        assert_eq!(graphql_endpoint(&g, "POST", "/api/graphql", None), None);
        assert_eq!(graphql_endpoint(&g, "POST", "/graphql/", None), None);
        let ghe = h("ghe.corp.example");
        assert_eq!(graphql_endpoint(&ghe, "POST", "/api/graphql", None), Some(Ok(ghe.clone())));
        assert_eq!(graphql_endpoint(&ghe, "POST", "/graphql", None), None);
        assert_eq!(route(&h("ghe.corp.example"), "GET", "/repos/acme/web", None), Err(Reason::GithubRouteUnknown));
    }
}
