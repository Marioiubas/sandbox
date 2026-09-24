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
//! - other `GET|HEAD` → `github.read` (search results flagged as bodies).
//!
//! `POST /graphql` is denied until GraphQL documents are parsed (a mutation
//! could hide in a query-looking request). Anything else is unknown: deny.

use audit::Reason;
use netguard::{CanonicalHost, canon_host};
use policy::RepoId;

/// A mapped request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub verb: &'static str,
    pub repo: Option<RepoId>,
    /// The response carries issue, PR or comment bodies, or search results.
    pub bodies: bool,
}

fn number(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Map a request on a GitHub API host (`api.github.com`, or a GitHub
/// Enterprise host under `/api/v3`) to its verb. `path` is canonical.
pub fn route(host: &CanonicalHost, method: &str, path: &str) -> Result<Route, Reason> {
    let segs: Vec<&str> = path.split('/').skip(1).filter(|s| !s.is_empty()).collect();
    let (authority, segs) = if host.as_str() == "api.github.com" {
        (canon_host(b"github.com").map_err(|_| Reason::GithubRouteUnknown)?, &segs[..])
    } else if segs.len() >= 2 && segs[0] == "api" && segs[1] == "v3" {
        (host.clone(), &segs[2..])
    } else {
        return Err(Reason::GithubRouteUnknown);
    };
    let read = matches!(method, "GET" | "HEAD");
    let repo = |o: &str, r: &str| RepoId::new(&authority, 443, o, r).ok_or(Reason::GithubRouteUnknown);
    let r = |verb, repo, bodies| Ok(Route { verb, repo, bodies });
    match segs {
        ["repos", o, n, rest @ ..] => {
            let repo = Some(repo(o, n)?);
            match (method, rest) {
                _ if read => r("repo.read", repo, matches!(rest.first(), Some(&"issues") | Some(&"pulls"))),
                ("POST", ["pulls"]) => r("pr.create", repo, false),
                ("PUT", ["pulls", n, "merge"]) if number(n) => r("pr.merge", repo, false),
                ("POST", ["issues", n, "comments"]) if number(n) => r("issue.comment", repo, false),
                ("PUT" | "DELETE", ["contents", _, ..]) => r("contents.write", repo, false),
                _ => Err(Reason::GithubRouteUnknown),
            }
        }
        ["graphql"] => Err(Reason::GithubGraphqlUnsupported),
        ["gists"] if method == "POST" => r("gist.create", None, false),
        _ if read => r("github.read", None, segs.first() == Some(&"search")),
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
        let r = route(&h("api.github.com"), method, path).unwrap();
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
        let ghe = route(&h("ghe.corp.example"), "POST", "/api/v3/repos/acme/web/pulls").unwrap();
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
            if let Ok(r) = route(&h("api.github.com"), method, &path) {
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
            assert_eq!(route(&g, m, p), Err(Reason::GithubRouteUnknown), "{m} {p}");
        }
        assert_eq!(route(&g, "POST", "/graphql"), Err(Reason::GithubGraphqlUnsupported));
        assert_eq!(route(&h("ghe.corp.example"), "GET", "/repos/acme/web"), Err(Reason::GithubRouteUnknown));
    }
}
