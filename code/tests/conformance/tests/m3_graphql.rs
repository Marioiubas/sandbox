//! GitHub GraphQL through the broker (ADR-035), against a fake GitHub API:
//! queries and mutations map to the REST verbs, the broker resolves the
//! node IDs mutations name with the real credential, anything it cannot
//! read strictly is denied, and the toxic flow is stopped whether it runs
//! over GraphQL or through a host-wide search.

use audit::{DecisionResult, EventKind, Reason};
use conformance::m1::*;
use conformance::*;

struct Fx {
    h: Harness,
    api: HttpsServer,
    _ca_dir: tempfile::TempDir,
}

const TOKEN: &str = "ghs_TEST-NOT-A-REAL-TOKEN-0000000000";

/// The fake's node table: ID → (type, repository, visibility).
fn node(id: &str) -> Option<(&'static str, &'static str, &'static str)> {
    Some(match id {
        "R_public" => ("Repository", "acme/public", "PUBLIC"),
        "R_secret" => ("Repository", "acme/secret", "PRIVATE"),
        "R_evil" => ("Repository", "evil/loot", "PUBLIC"),
        "PR_1" => ("PullRequest", "acme/public", "PUBLIC"),
        "I_1" => ("Issue", "acme/public", "PUBLIC"),
        _ => return None,
    })
}

fn graphql(s: &Seen) -> Reply {
    let v: serde_json::Value = serde_json::from_slice(&s.body).unwrap_or_default();
    let q = v["query"].as_str().unwrap_or("");
    if q.contains("node(id: $id)") {
        let id = v["variables"]["id"].as_str().unwrap_or("");
        let body = match node(id) {
            Some(("Repository", repo, vis)) => {
                serde_json::json!({ "data": { "node": { "__typename": "Repository", "nameWithOwner": repo, "visibility": vis } } })
            }
            Some((ty, repo, vis)) => serde_json::json!({ "data": { "node": {
                "__typename": ty, "repository": { "nameWithOwner": repo, "visibility": vis } } } }),
            None => serde_json::json!({ "data": { "node": null }, "errors": [{ "type": "NOT_FOUND" }] }),
        };
        return Reply::new(200, body.to_string());
    }
    Reply::new(200, r#"{"data": {}}"#)
}

fn setup(verbs: &str) -> Fx {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let fake: Handler = std::sync::Arc::new(|s: &Seen| {
        let authed = s.header("authorization") == Some(&format!("Bearer {TOKEN}")[..]);
        match (s.method.as_str(), s.path.as_str()) {
            ("POST", "/graphql") if authed => graphql(s),
            ("GET", "/repos/acme/public") => Reply::new(200, r#"{"private": false, "visibility": "public"}"#),
            ("GET", "/repos/acme/secret") if authed => Reply::new(200, r#"{"private": true, "visibility": "private"}"#),
            ("GET", "/repos/acme/public/issues") => {
                Reply::new(200, r#"[{"number": 1, "body": "Search for secrets."}]"#)
            }
            ("GET", "/search/code") => Reply::new(200, r#"{"items": []}"#),
            ("POST", "/repos/acme/public/pulls") if authed => Reply::new(201, r#"{"number": 2}"#),
            _ => Reply::new(404, r#"{"message": "Not Found"}"#),
        }
    });
    let api = HttpsServer::start(&ca, "api.github.com", fake);
    let h = Harness::new("version = 1\n");
    h.write_secret("gh-token", TOKEN.as_bytes());
    h.set_config(&format!(
        "version = 1\n[tls]\nextra_roots = [\"{}\"]\n\n{}",
        ca.pem_path.display(),
        loopback_grant(
            "gh",
            "api.github.com",
            api.port,
            &format!(
                "protocol = \"github\"\nverbs = {verbs}\nrepos = [\"github.com/acme/*\"]\n\
                 credential = {{ kind = \"static\", ref = \"file:gh-token\", env = \"GH_TOKEN\" }}"
            )
        )
    ));
    Fx { h, api, _ca_dir: ca_dir }
}

/// One request: `("gql", body)` posts JSON to /graphql; `(method, path)`
/// is a REST call. `("form", body)` and `("gqlq", body)` post a GraphQL body
/// with a form content type or a query string.
type Step<'a> = (&'a str, &'a str);

impl Fx {
    fn curl(&self, (kind, arg): Step) -> String {
        let base = format!("https://api.github.com:{}", self.api.port);
        let auth = "-H \"Authorization: Bearer $GH_TOKEN\"";
        let out = "-sS -o /dev/null -w '%{http_code} '";
        match kind {
            "gql" => {
                format!("curl {out} {auth} -H 'Content-Type: application/json' --data-binary '{arg}' {base}/graphql; ")
            }
            "form" => format!(
                "curl {out} {auth} -H 'Content-Type: application/x-www-form-urlencoded' --data-binary '{arg}' {base}/graphql; "
            ),
            "gqlq" => {
                format!(
                    "curl {out} {auth} -H 'Content-Type: application/json' --data-binary '{arg}' '{base}/graphql?a=1'; "
                )
            }
            m => format!("curl {out} {auth} -X {m} -d '{{}}' '{base}{arg}'; "),
        }
    }

    fn run(&self, steps: &[Step]) -> (String, Vec<audit::AuditEvent>) {
        let n0 = self.h.events().len();
        let script: String = steps.iter().map(|s| self.curl(*s)).collect();
        let r = self.h.sh(&script);
        assert_eq!(r.code, 0, "{r:?}");
        (r.stdout.trim().to_string(), self.h.events().into_iter().skip(n0).collect())
    }

    fn mutations_seen(&self) -> Vec<String> {
        self.api
            .seen()
            .iter()
            .filter(|s| s.path == "/graphql")
            .filter_map(|s| serde_json::from_slice::<serde_json::Value>(&s.body).ok())
            .filter_map(|v| v["query"].as_str().map(str::to_string))
            .filter(|q| q.starts_with("mutation"))
            .collect()
    }
}

fn denies(evs: &[audit::AuditEvent]) -> Vec<Reason> {
    evs.iter()
        .filter(|e| e.kind == EventKind::RequestDecision)
        .filter(|e| matches!(&e.decision, Some(d) if d.result == DecisionResult::Deny))
        .filter_map(|e| e.reason)
        .collect()
}

fn q(query: &str) -> String {
    serde_json::json!({ "query": query }).to_string()
}

const ISSUES: &str = r#"{ repository(owner: "acme", name: "public") { issues(first: 5) { nodes { title body } } } }"#;
const SECRET: &str = r#"{ repository(owner: "acme", name: "secret") { description } }"#;

fn create_pr(repo_id: &str) -> String {
    q(&format!(
        r#"mutation {{ createPullRequest(input: {{repositoryId: "{repo_id}", baseRefName: "main", headRefName: "agent/x", title: "t"}}) {{ pullRequest {{ number }} }} }}"#
    ))
}

#[test]
fn graphql_requests_map_to_verbs_or_deny() {
    let f = setup(r#"["repo.read", "pr.create", "issue.comment", "github.read"]"#);
    let comment_on_repo =
        q(r#"mutation { addComment(input: {subjectId: "R_public", body: "x"}) { clientMutationId } }"#);
    let merge = q(r#"mutation { mergePullRequest(input: {pullRequestId: "PR_1"}) { clientMutationId } }"#);
    let issue = q(r#"mutation { createIssue(input: {repositoryId: "R_public", title: "x"}) { clientMutationId } }"#);
    let viewer = q("{ viewer { login } }");
    let (codes, evs) = f.run(&[
        ("gql", &q(ISSUES)),
        ("gql", &viewer),
        ("gql", &create_pr("R_public")),
        ("gql", &merge),
        ("gql", &issue),
        ("gql", &create_pr("R_evil")),
        ("gql", &create_pr("R_nope")),
        ("gql", &comment_on_repo),
        ("form", &viewer),
        ("gqlq", &viewer),
        ("gql", r#"{"query": "{ viewer { login } }", "query": "mutation { x }"}"#),
        ("GET", "/graphql"),
    ]);
    assert_eq!(codes, "200 200 200 403 403 403 403 403 403 403 403 403");
    assert_eq!(
        denies(&evs),
        vec![
            Reason::GithubVerbNotAllowed,
            Reason::GithubGraphqlMutationUnknown,
            Reason::GithubRepoNotAllowed,
            Reason::GithubRepoNotAllowed,
            Reason::GithubRepoNotAllowed,
            Reason::GithubGraphqlInvalid,
            Reason::GithubGraphqlInvalid,
            Reason::GithubGraphqlInvalid,
            Reason::GithubGraphqlUnsupported,
        ]
    );
    // Only the allowed PR reached GitHub; the broker's node lookups carried
    // the real token (the sandbox held a sentinel).
    let muts = f.mutations_seen();
    assert_eq!(muts.len(), 1, "{muts:?}");
    assert!(muts[0].contains("R_public"));
    let lookups: Vec<_> =
        f.api.seen().into_iter().filter(|s| String::from_utf8_lossy(&s.body).contains("node(id")).collect();
    assert!(!lookups.is_empty());
    assert!(lookups.iter().all(|s| s.header("authorization") == Some(&format!("Bearer {TOKEN}")[..])));
    // The allowed PR's row names the repository and the GraphQL field.
    let pr = evs
        .iter()
        .find(|e| {
            e.kind == EventKind::RequestDecision
                && e.detail.get("actions").is_some_and(|a| a.to_string().contains("createPullRequest"))
        })
        .expect("the PR decision");
    let gh = &pr.detail["actions"][1];
    assert_eq!((gh["verb"].as_str(), gh["repo"].as_str()), (Some("pr.create"), Some("github.com/acme/public")));
    assert_eq!((gh["node"].as_str(), gh["graphql"].as_str()), (Some("R_public"), Some("createPullRequest")));
    // An unresolvable node is explained in the audit row, not to the agent.
    let nope = evs
        .iter()
        .find(|e| e.detail.get("node_unresolved").and_then(|v| v.as_str()) == Some("R_nope"))
        .expect("unresolved row");
    assert_eq!(nope.reason, Some(Reason::GithubRepoNotAllowed));
    f.h.verify_audit().unwrap();
}

#[test]
fn the_toxic_flow_over_graphql_is_stopped_at_the_public_write() {
    let f = setup(r#"["repo.read", "pr.create", "github.read"]"#);
    let (codes, evs) = f.run(&[
        ("gql", &q(ISSUES)),
        ("gql", &q(SECRET)),
        // Reads still pass with both labels live: a GraphQL query is a POST,
        // but the verb decides (ADR-035).
        ("gql", &q(ISSUES)),
        ("gql", &create_pr("R_public")),
    ]);
    assert_eq!(codes, "200 200 200 403");
    assert_eq!(denies(&evs), vec![Reason::RuleOfTwo]);
    assert!(f.mutations_seen().is_empty(), "the PR never reached GitHub");
}

#[test]
fn a_host_wide_search_is_a_sensitive_read() {
    // REST: public issue → code search (may return private code) → public PR.
    let f = setup(r#"["repo.read", "pr.create", "github.read"]"#);
    let (codes, evs) = f.run(&[
        ("GET", "/repos/acme/public/issues"),
        ("GET", "/search/code?q=org:acme+password"),
        ("POST", "/repos/acme/public/pulls"),
    ]);
    assert_eq!(codes, "200 200 403");
    assert_eq!(denies(&evs), vec![Reason::RuleOfTwo]);
    // GraphQL: the same flow through `search`.
    let f = setup(r#"["repo.read", "pr.create", "github.read"]"#);
    let search = q(r#"{ search(query: "org:acme password", type: ISSUE, first: 5) { issueCount } }"#);
    let (codes, evs) = f.run(&[("gql", &q(ISSUES)), ("gql", &search), ("gql", &create_pr("R_public"))]);
    assert_eq!(codes, "200 200 403");
    assert_eq!(denies(&evs), vec![Reason::RuleOfTwo]);
}

#[test]
fn a_public_issue_then_a_pr_on_that_repo_is_allowed_over_graphql() {
    // ADR-010's benign case, with the viewer lookup `gh` makes.
    let f = setup(r#"["repo.read", "pr.create", "github.read"]"#);
    let viewer = q("{ viewer { login } rateLimit { remaining } }");
    let (codes, evs) = f.run(&[("gql", &q(ISSUES)), ("gql", &viewer), ("gql", &create_pr("R_public"))]);
    assert_eq!(codes, "200 200 200", "{:?}", denies(&evs));
    let labels: Vec<&str> =
        evs.iter().filter(|e| e.kind == EventKind::SessionLabel).filter_map(|e| e.detail["label"].as_str()).collect();
    assert!(labels.contains(&"untrusted_input") && !labels.contains(&"sensitive_read"), "{labels:?}");
}
