use super::*;
use netguard::canon_host;
use proptest::prelude::*;

fn gh() -> CanonicalHost {
    canon_host(b"github.com").unwrap()
}

fn body(query: &str, vars: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "query": query, "variables": vars })).unwrap()
}

fn run(query: &str, vars: serde_json::Value) -> Result<Vec<Mapped>, Reason> {
    map(&gh(), &body(query, vars))
}

/// (verb, repo, node, bodies, public) per mapped verb.
type Short<'a> = (&'a str, Option<String>, Option<&'a str>, bool, bool);

fn short(m: &[Mapped]) -> Vec<Short<'_>> {
    m.iter().map(|m| (m.verb, m.repo.as_ref().map(|r| r.to_string()), m.node.as_deref(), m.bodies, m.public)).collect()
}

#[test]
fn a_repository_read_is_confined_to_that_repository() {
    // The GitHub MCP server's list_issues shape.
    let q = "query($owner: String!, $repo: String!, $first: Int) {
        repository(owner: $owner, name: $repo) {
          issues(first: $first, states: [OPEN]) {
            nodes { number title body state author { login } labels(first: 10) { nodes { name } } comments { totalCount } }
            pageInfo { hasNextPage endCursor } totalCount
          }
        }
      }";
    let m = run(q, serde_json::json!({ "owner": "Acme", "repo": "Web", "first": 5 })).unwrap();
    assert_eq!(short(&m), vec![("repo.read", Some("github.com/acme/web".into()), None, true, false)]);
    assert_eq!(m[0].field, "repository");
    // Metadata only: no bodies.
    let m = run(
        r#"{ repository(owner: "acme", name: "web") { id nameWithOwner defaultBranchRef { name } } }"#,
        serde_json::json!({}),
    )
    .unwrap();
    assert_eq!(short(&m), vec![("repo.read", Some("github.com/acme/web".into()), None, false, false)]);
}

#[test]
fn leaving_the_repository_is_an_unconfined_read() {
    for q in [
        r#"{ repository(owner: "acme", name: "web") { owner { repositories(first: 50) { nodes { name } } } } }"#,
        r#"{ repository(owner: "acme", name: "web") { issues(first: 1) { nodes { author { ... on User { repositories { totalCount } } } } } } }"#,
        r#"{ repository(owner: "acme", name: "web") { pullRequest(number: 1) { headRepository { name } } } }"#,
        r#"{ repository(owner: "acme", name: "web") { issue(number: 1) { subIssues { nodes { body } } } } }"#,
        r#"{ repository(owner: "acme", name: "web") { ...F } } fragment F on Repository { forks { totalCount } }"#,
        r#"{ repository(owner: "acme", name: "web") { ... on Organization { name } } }"#,
        r#"{ repository(owner: "acme", name: "web") { name { x } } }"#,
    ] {
        let m = run(q, serde_json::json!({})).unwrap();
        assert_eq!(
            short(&m),
            vec![
                ("repo.read", Some("github.com/acme/web".into()), None, true, false),
                ("github.read", None, None, true, false)
            ],
            "{q}"
        );
    }
}

#[test]
fn host_reads_are_public_only_when_confined() {
    let public = |q: &str| -> Vec<(&str, bool, bool)> {
        run(q, serde_json::json!({})).unwrap().iter().map(|m| (m.verb, m.bodies, m.public)).collect()
    };
    let p = vec![("github.read", false, true)];
    assert_eq!(public("{ viewer { login name } }"), p);
    assert_eq!(public("{ rateLimit { remaining } __typename }"), p);
    assert_eq!(public(r#"{ __type(name: "Repository") { fields { name } } }"#), p);
    assert_eq!(public(r#"{ user(login: "octocat") { login } repositoryOwner(login: "x") { id } }"#), p);
    let u = vec![("github.read", true, false)];
    assert_eq!(public("{ viewer { login repositories(first: 100) { nodes { name } } } }"), u);
    assert_eq!(public(r#"{ search(query: "org:acme password", type: ISSUE, first: 5) { issueCount } }"#), u);
    assert_eq!(public(r#"{ node(id: "R_1") { id } }"#), u);
    assert_eq!(public(r#"{ organization(login: "acme") { name } viewer { login } }"#), u, "unconfined wins");
}

#[test]
fn mutations_map_to_verbs_on_node_ids() {
    let m = run(
        "mutation($input: CreatePullRequestInput!) { createPullRequest(input: $input) { pullRequest { number url } } }",
        serde_json::json!({ "input": { "repositoryId": "R_kgDOabc", "baseRefName": "main", "headRefName": "agent/x", "title": "t" } }),
    )
    .unwrap();
    assert_eq!(short(&m), vec![("pr.create", None, Some("R_kgDOabc"), false, false)]);
    assert_eq!(m[0].field, "createPullRequest");
    let q = r#"mutation($pr: ID!) {
        a: mergePullRequest(input: {pullRequestId: $pr}) { clientMutationId }
        enablePullRequestAutoMerge(input: {pullRequestId: "PR_2"}) { pullRequest { number } }
        enqueuePullRequest(input: {pullRequestId: "PR_3"}) { clientMutationId }
        addComment(input: {subjectId: "I_4", body: "hi"}) { commentEdge { node { id } } subject { ... on Issue { number } } }
        __typename
      }"#;
    let m = run(q, serde_json::json!({ "pr": "PR_1" })).unwrap();
    assert_eq!(
        short(&m),
        vec![
            ("pr.merge", None, Some("PR_1"), false, false),
            ("pr.merge", None, Some("PR_2"), false, false),
            ("pr.merge", None, Some("PR_3"), false, false),
            ("issue.comment", None, Some("I_4"), false, false),
        ]
    );
    // A default value supplies the input.
    let m = run(
        r#"mutation($i: AddCommentInput = {subjectId: "I_9", body: "x"}) { addComment(input: $i) { clientMutationId } }"#,
        serde_json::json!(null),
    )
    .unwrap();
    assert_eq!(short(&m), vec![("issue.comment", None, Some("I_9"), false, false)]);
    // A payload that leaves the repository also reads host-wide.
    let m = run(
        r#"mutation { createPullRequest(input: {repositoryId: "R_1"}) { pullRequest { headRepository { owner { repositories { totalCount } } } } } }"#,
        serde_json::json!({}),
    )
    .unwrap();
    assert_eq!(
        short(&m),
        vec![("pr.create", None, Some("R_1"), false, false), ("github.read", None, None, true, false)]
    );
    assert_eq!(
        short(&run("mutation { __typename }", serde_json::json!({})).unwrap()),
        vec![("github.read", None, None, false, true)]
    );
}

#[test]
fn unknown_mutations_and_hidden_ones_deny() {
    let deny = |q: &str| run(q, serde_json::json!({ "i": { "pullRequestId": "PR_1" } })).unwrap_err();
    for q in [
        r#"mutation { createIssue(input: {repositoryId: "R_1", title: "x"}) { clientMutationId } }"#,
        r#"mutation { updatePullRequest(input: {pullRequestId: "PR_1"}) { clientMutationId } }"#,
        r#"mutation { addComment(input: {subjectId: "I_1"}) { clientMutationId } deleteRepository(input: {}) { x } }"#,
    ] {
        assert_eq!(deny(q), Reason::GithubGraphqlMutationUnknown, "{q}");
    }
    for q in [
        // A mutation fragment spread into a query.
        r#"query { ...F } fragment F on Mutation { mergePullRequest(input: {pullRequestId: "PR_1"}) { clientMutationId } }"#,
        r#"query { ... on Mutation { mergePullRequest(input: $i) { clientMutationId } } }"#,
        "subscription { x }",
        // Node IDs the broker cannot determine.
        r#"mutation { mergePullRequest(input: {}) { clientMutationId } }"#,
        r#"mutation { mergePullRequest(input: {pullRequestId: 7}) { clientMutationId } }"#,
        r#"mutation { mergePullRequest(input: {pullRequestId: "PR 1"}) { clientMutationId } }"#,
        r#"mutation { mergePullRequest(input: {pullRequestId: """PR_1"""}) { clientMutationId } }"#,
        r#"mutation { mergePullRequest(input: {pullRequestId: "PR_1", pullRequestId: "PR_2"}) { clientMutationId } }"#,
        r#"mutation { mergePullRequest(input: $undeclared) { clientMutationId } }"#,
        r#"mutation($i: X) { mergePullRequest(input: $i, input: $i) { clientMutationId } }"#,
        r#"mutation($i: X) { mergePullRequest(other: $i) { clientMutationId } }"#,
    ] {
        assert_eq!(deny(q), Reason::GithubGraphqlInvalid, "{q}");
    }
    let too_many: String = (0..=MAX_MUTATIONS)
        .map(|k| format!(r#"m{k}: addComment(input: {{subjectId: "I_{k}"}}) {{ clientMutationId }} "#))
        .collect();
    assert_eq!(deny(&format!("mutation {{ {too_many} }}")), Reason::GithubGraphqlInvalid);
}

#[test]
fn the_operation_is_chosen_unambiguously() {
    let doc = r#"query A { viewer { login } } mutation B { mergePullRequest(input: {pullRequestId: "PR_1"}) { clientMutationId } }"#;
    let with = |name: serde_json::Value| {
        map(&gh(), &serde_json::to_vec(&serde_json::json!({ "query": doc, "operationName": name })).unwrap())
    };
    assert_eq!(with(serde_json::json!(null)), Err(Reason::GithubGraphqlInvalid));
    assert_eq!(with(serde_json::json!("C")), Err(Reason::GithubGraphqlInvalid));
    assert_eq!(with(serde_json::json!(1)), Err(Reason::GithubGraphqlInvalid));
    assert_eq!(short(&with(serde_json::json!("A")).unwrap()), vec![("github.read", None, None, false, true)]);
    assert_eq!(short(&with(serde_json::json!("B")).unwrap()), vec![("pr.merge", None, Some("PR_1"), false, false)]);
    for doc in ["query A { a } query A { b }", "{ a } query B { b }", "{ a } { b }"] {
        assert_eq!(run(doc, serde_json::json!({})), Err(Reason::GithubGraphqlInvalid), "{doc}");
    }
}

#[test]
fn the_body_is_read_strictly() {
    let bad: &[&[u8]] = &[
        br#"{"query": "{ viewer { login } }", "query": "mutation { x }"}"#,
        br#"{"query": "{ a }", "variables": {"o": 1, "o": 2}}"#,
        br#"{"query": "{ a }", "extensions": {}}"#,
        br#"[{"query": "{ a }"}]"#,
        br#"{"query": 1}"#,
        br#"{"variables": {}}"#,
        br#"{"query": "{ a }", "variables": "{}"}"#,
        br#"{"query": "{ a }"} trailing"#,
        br#"{"query": "{ a }""#,
        b"",
    ];
    for b in bad {
        assert_eq!(map(&gh(), b), Err(Reason::GithubGraphqlInvalid), "{}", String::from_utf8_lossy(b));
    }
    assert_eq!(map(&gh(), &vec![b' '; MAX_BODY + 1]), Err(Reason::GithubGraphqlInvalid));
    assert!(map(&gh(), br#"{"query": "{ viewer { login } }", "variables": null, "operationName": null}"#).is_ok());
}

#[test]
fn repository_arguments_must_be_determinable() {
    for (q, vars) in [
        (r#"{ repository(owner: "acme") { id } }"#, serde_json::json!({})),
        (r#"{ repository(owner: "acme", name: "web", extra: 1) { id } }"#, serde_json::json!({})),
        (r#"{ repository(owner: "acme", owner: "evil", name: "web") { id } }"#, serde_json::json!({})),
        ("query($o: String!) { repository(owner: $o, name: \"web\") { id } }", serde_json::json!({})),
        ("query($o: String!) { repository(owner: $o, name: \"web\") { id } }", serde_json::json!({ "o": 5 })),
        (r#"{ repository(owner: $o, name: "web") { id } }"#, serde_json::json!({ "o": "acme" })),
        (r#"{ repository(owner: "a/b", name: "web") { id } }"#, serde_json::json!({})),
        (r#"{ ...F } fragment F on Query { ...F }"#, serde_json::json!({})),
        (r#"{ repository(owner: "a", name: "b") { ...G } }"#, serde_json::json!({})),
        (r#"{ repository(owner: "a", name: "b") { ...F } } fragment F on Repository { ...F }"#, serde_json::json!({})),
    ] {
        assert_eq!(run(q, vars.clone()), Err(Reason::GithubGraphqlInvalid), "{q} {vars}");
    }
    // Directives never hide a field from the adapter.
    let m = run(r#"{ repository(owner: "a", name: "b") @skip(if: true) { id } }"#, serde_json::json!({})).unwrap();
    assert_eq!(short(&m), vec![("repo.read", Some("github.com/a/b".into()), None, false, false)]);
}

#[test]
fn shared_fragments_are_walked_once() {
    // 2^40 paths if expanded naively.
    let mut doc = String::from(r#"{ repository(owner: "a", name: "b") { ...F0 } }"#);
    for k in 0..40 {
        doc += &format!(" fragment F{k} on Repository {{ ...F{} ...F{} }}", k + 1, k + 1);
    }
    doc += " fragment F40 on Repository { id }";
    let m = run(&doc, serde_json::json!({})).unwrap();
    assert_eq!(short(&m), vec![("repo.read", Some("github.com/a/b".into()), None, false, false)]);
}

const ROOTS: &[&str] = &[
    "__typename",
    "viewer { login }",
    r#"repository(owner: "a", name: "b") { id }"#,
    r#"search(query: "x", type: ISSUE) { issueCount }"#,
    r#"createPullRequest(input: {repositoryId: "R_1"}) { clientMutationId }"#,
    r#"mergePullRequest(input: {pullRequestId: "PR_1"}) { clientMutationId }"#,
    r#"addComment(input: {subjectId: "I_1"}) { clientMutationId }"#,
    r#"createIssue(input: {repositoryId: "R_1"}) { clientMutationId }"#,
];

proptest! {
    /// A query never yields a write verb; a mutation that maps yields one
    /// write verb per root field that is not `__typename`.
    #[test]
    fn writes_come_only_from_mapped_mutations(
        mutation in any::<bool>(),
        picks in proptest::collection::vec(0..ROOTS.len(), 1..6),
    ) {
        let fields: Vec<&str> = picks.iter().map(|&k| ROOTS[k]).collect();
        let doc = format!("{} {{ {} }}", if mutation { "mutation" } else { "query" }, fields.join(" "));
        let Ok(m) = run(&doc, serde_json::json!({})) else { return Ok(()) };
        let writes = m.iter().filter(|m| !policy::github::is_read_verb(m.verb)).count();
        if mutation {
            prop_assert_eq!(writes, fields.iter().filter(|f| **f != "__typename").count());
            prop_assert!(!m.is_empty());
            prop_assert!(m.iter().filter(|m| m.node.is_some()).all(|m| !node_types(m.verb).is_empty()));
        } else {
            prop_assert_eq!(writes, 0);
        }
        for x in &m {
            prop_assert!(policy::github::is_verb(x.verb));
            prop_assert!(!x.public || (x.verb == "github.read" && !x.bodies));
        }
    }

    /// Arbitrary bodies never panic the adapter.
    #[test]
    fn arbitrary_bodies_never_panic(b in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = map(&gh(), &b);
    }
}
