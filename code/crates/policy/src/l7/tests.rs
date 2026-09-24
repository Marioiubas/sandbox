use super::*;
use crate::config::parse_policy_str;
use crate::egress::{EgressPolicy, PathChoice};
use netguard::canon_host;
use proptest::prelude::*;

fn env() -> CompileEnv {
    CompileEnv {
        repo_remote: RepoId::parse("github.com/acme/web"),
        github_app_issuers: ["acme".to_string()].into_iter().collect(),
        ..Default::default()
    }
}

fn policy(toml: &str) -> EgressPolicy {
    let p = parse_policy_str(toml).unwrap();
    EgressPolicy::compile_with([("user", p.egress.as_slice())], &env()).unwrap()
}

fn compile_err(toml: &str) -> String {
    let p = parse_policy_str(toml).unwrap();
    EgressPolicy::compile_with([("user", p.egress.as_slice())], &env()).unwrap_err().to_string()
}

const GIT: &str = r#"
version = 1
[[egress]]
host = "github.com"
id = "git"
protocol = "git"
allow = { fetch = ["${repo_remote}"], push = { repo = "${repo_remote}", refs = ["agent/*"], force = false } }
credential = { kind = "github_app", issuer = "acme", permissions = { contents = "write" }, repos = ["${repo_remote}"], ttl = "30m" }
"#;

fn repo(s: &str) -> RepoId {
    RepoId::parse(s).unwrap()
}

fn push(r: &str, refname: &str, force: bool) -> Action {
    Action::GitPush { repo: repo(r), refname: refname.into(), force, update: "test" }
}

#[test]
fn git_push_scoping() {
    let p = policy(GIT);
    let adm = p.admit_host(&canon_host(b"github.com").unwrap(), 443).unwrap();
    assert_eq!(p.path_choice(&adm), PathChoice::L7);
    let ok = p.authorize_l7(&adm, &[push("github.com/acme/web", "refs/heads/agent/x", false)]);
    assert!(ok.result.is_ok());
    let b = ok.binding.expect("credential bound");
    assert_eq!(b.credential().id, "user:git");
    assert_eq!(b.credential().attach, AttachSpec::Basic { username: "x-access-token".into() });
    assert!(
        matches!(&b.credential().kind, CredKind::GitHubApp { repos, .. } if repos == &vec![repo("github.com/acme/web")])
    );

    let cases = [
        (push("github.com/evil/web", "refs/heads/agent/x", false), Reason::GitRepoNotAllowed),
        (push("github.com/acme/web", "refs/heads/main", false), Reason::GitRefNotAllowed),
        (push("github.com/acme/web", "refs/heads/agent/x", true), Reason::GitForcePush),
        (push("github.com/acme/web", "refs/tags/agent/x", false), Reason::GitRefNotAllowed),
        (Action::Http { method: "GET".into(), path: "/".into() }, Reason::L7NoRuleMatched),
        (Action::GitFetch { repo: repo("github.com/acme/other") }, Reason::GitRepoNotAllowed),
    ];
    for (a, want) in cases {
        let d = p.authorize_l7(&adm, std::slice::from_ref(&a));
        assert_eq!(d.result, Err(want), "{}", a.verb());
        assert!(d.binding.is_none(), "no credential on deny");
    }
    // One denied ref denies the whole push.
    let d = p.authorize_l7(
        &adm,
        &[
            push("github.com/acme/web", "refs/heads/agent/x", false),
            push("github.com/acme/web", "refs/heads/main", false),
        ],
    );
    assert_eq!(d.result, Err(Reason::GitRefNotAllowed));
    assert!(d.binding.is_none());
    assert!(p.authorize_l7(&adm, &[Action::GitFetch { repo: repo("github.com/acme/web") }]).result.is_ok());
    assert!(p.authorize_l7(&adm, &[Action::GitPushAdvertise { repo: repo("github.com/acme/web") }]).result.is_ok());
    assert_eq!(p.authorize_l7(&adm, &[]).result, Err(Reason::L7NoRuleMatched), "nothing classified: deny");
}

#[test]
fn methods_paths_and_default_deny() {
    let p = policy(
        r#"
version = 1
[[egress]]
host = "api.anthropic.com"
methods = ["POST"]
paths = ["/v1/messages", "/v1/messages/count_tokens"]
credential = { kind = "static", ref = "keychain:broker-anthropic", header = "x-api-key", env = "ANTHROPIC_API_KEY" }
[[egress]]
host = "registry.npmjs.org"
protocol = "registry"
"#,
    );
    let h = canon_host(b"api.anthropic.com").unwrap();
    let adm = p.admit_host(&h, 443).unwrap();
    let post = |path: &str| Action::Http { method: "POST".into(), path: path.into() };
    let d = p.authorize_l7(&adm, &[post("/v1/messages")]);
    assert!(d.result.is_ok());
    let c = d.binding.unwrap();
    assert_eq!(c.credential().attach, AttachSpec::Header { name: "x-api-key".into() });
    assert_eq!(c.credential().env.as_deref(), Some("ANTHROPIC_API_KEY"));
    assert_eq!(p.authorize_l7(&adm, &[post("/v1/files")]).result, Err(Reason::L7NoRuleMatched));
    let get = Action::Http { method: "GET".into(), path: "/v1/messages".into() };
    assert_eq!(p.authorize_l7(&adm, &[get]).result, Err(Reason::L7NoRuleMatched));

    let npm = p.admit_host(&canon_host(b"registry.npmjs.org").unwrap(), 443).unwrap();
    assert_eq!(p.path_choice(&npm), PathChoice::L7);
    let get = Action::Http { method: "GET".into(), path: "/left-pad".into() };
    assert!(p.authorize_l7(&npm, &[get]).result.is_ok());
    let put = Action::Http { method: "PUT".into(), path: "/left-pad".into() };
    assert_eq!(p.authorize_l7(&npm, &[put]).result, Err(Reason::L7NoRuleMatched), "publish denied");
    assert_eq!(p.credentials().len(), 1);
}

#[test]
fn plain_grant_stays_l4_and_passthrough_wins() {
    let p = policy(
        r#"
version = 1
[[egress]]
host = "example.com"
[[egress]]
host = "pinned.example"
passthrough = true
[[egress]]
host = "pinned.example"
methods = ["GET"]
"#,
    );
    let a = p.admit_host(&canon_host(b"example.com").unwrap(), 443).unwrap();
    assert_eq!(p.path_choice(&a), PathChoice::L4);
    let b = p.admit_host(&canon_host(b"pinned.example").unwrap(), 443).unwrap();
    assert_eq!(p.path_choice(&b), PathChoice::L4, "passthrough: never terminate, never attach");
}

#[test]
fn ambiguous_credentials_deny() {
    let p = policy(
        r#"
version = 1
[[egress]]
host = "api.example.com"
credential = { kind = "static", ref = "env:A" }
[[egress]]
host = "api.example.com"
id = "b"
credential = { kind = "static", ref = "env:B" }
"#,
    );
    let adm = p.admit_host(&canon_host(b"api.example.com").unwrap(), 443).unwrap();
    let d = p.authorize_l7(&adm, &[Action::Http { method: "GET".into(), path: "/".into() }]);
    assert_eq!(d.result, Err(Reason::AmbiguousCredential));
}

#[test]
fn unresolved_repo_remote_grants_nothing() {
    let p = parse_policy_str(GIT).unwrap();
    let env = CompileEnv {
        repo_remote: None,
        github_app_issuers: ["acme".to_string()].into_iter().collect(),
        ..Default::default()
    };
    let pol = EgressPolicy::compile_with([("user", p.egress.as_slice())], &env).unwrap();
    let adm = pol.admit_host(&canon_host(b"github.com").unwrap(), 443).unwrap();
    let d = pol.authorize_l7(&adm, &[push("github.com/acme/web", "refs/heads/agent/x", false)]);
    assert_eq!(d.result, Err(Reason::GitRepoNotAllowed));
    let c = &pol.credentials()[0];
    assert!(matches!(&c.kind, CredKind::GitHubApp { repos, .. } if repos.is_empty()));
}

#[test]
fn compile_errors() {
    let base = "version = 1\n[[egress]]\nhost = \"a.example\"\n";
    for (extra, needle) in [
        ("protocol = \"ftp\"\n", "unknown protocol"),
        ("methods = [\"get\"]\n", "upper-case"),
        ("paths = [\"v1\"]\n", "must start with /"),
        ("allow = { fetch = [\"a.example/o/r\"] }\n", "needs protocol"),
        ("protocol = \"git\"\n", "needs allow"),
        ("protocol = \"git\"\nallow = { push = { repo = \"a.example/o/r\", refs = [] } }\n", "empty lists deny"),
        ("protocol = \"git\"\nallow = { push = { repo = \"a.example/o/r\", refs = [\"a..b\"] } }\n", "bad ref"),
        ("passthrough = true\nmethods = [\"GET\"]\n", "passthrough"),
        ("credential = { kind = \"static\" }\n", "needs ref"),
        ("credential = { kind = \"static\", ref = \"vault:x\" }\n", "keychain:"),
        ("credential = { kind = \"static\", ref = \"file:../x\" }\n", "~/ path"),
        ("credential = { kind = \"static\", ref = \"env:A\", env = \"PATH\" }\n", "not an allowed variable"),
        ("credential = { kind = \"static\", ref = \"env:A\", env = \"BROKER_X\" }\n", "not an allowed variable"),
        ("credential = { kind = \"static\", ref = \"env:A\", scheme = \"digest\" }\n", "unknown scheme"),
        ("credential = { kind = \"static\", ref = \"env:A\", scheme = \"basic\" }\n", "needs username"),
        ("credential = { kind = \"static\", ref = \"env:A\", ttl = \"1h\" }\n", "github_app only"),
        ("credential = { kind = \"aws\", ref = \"env:A\" }\n", "unknown kind"),
        (
            "credential = { kind = \"github_app\", issuer = \"nope\", permissions = { contents = \"read\" }, repos = [\"a.example/o/r\"] }\n",
            "no [issuers",
        ),
        (
            "credential = { kind = \"github_app\", issuer = \"acme\", repos = [\"a.example/o/r\"] }\n",
            "explicit permissions",
        ),
        (
            "credential = { kind = \"github_app\", issuer = \"acme\", permissions = { contents = \"all\" }, repos = [\"a.example/o/r\"] }\n",
            "bad permission",
        ),
        (
            "credential = { kind = \"github_app\", issuer = \"acme\", permissions = { contents = \"read\" } }\n",
            "needs repos",
        ),
        (
            "credential = { kind = \"github_app\", issuer = \"acme\", permissions = { contents = \"read\" }, repos = [\"a.example/o/r\", \"a.example/p/r\"] }\n",
            "span owners",
        ),
        (
            "credential = { kind = \"github_app\", issuer = \"acme\", permissions = { contents = \"read\" }, repos = [\"a.example/o/r\"], ttl = \"2h\" }\n",
            "at most 1h",
        ),
    ] {
        let msg = compile_err(&format!("{base}{extra}"));
        assert!(msg.contains(needle), "{extra:?}: {msg}");
    }
}

#[test]
fn secret_refs() {
    let r = SecretRef::parse("keychain:Claude Code-credentials#claudeAiOauth.accessToken").unwrap();
    assert_eq!(
        r.alternatives[0].source,
        SecretSource::Keychain { service: "Claude Code-credentials".into(), account: None }
    );
    assert_eq!(r.alternatives[0].json_path, vec!["claudeAiOauth", "accessToken"]);
    assert_eq!(r.describe(), "keychain:Claude Code-credentials#claudeAiOauth.accessToken");
    let r = SecretRef::parse("keychain:svc/acct").unwrap();
    assert_eq!(
        r.alternatives[0].source,
        SecretSource::Keychain { service: "svc".into(), account: Some("acct".into()) }
    );
    let alt = "keychain:a#x.y|file:~/.claude/.credentials.json#x.y|env:K";
    let r = SecretRef::parse(alt).unwrap();
    assert_eq!(r.alternatives.len(), 3);
    assert_eq!(r.alternatives[1].source, SecretSource::File("~/.claude/.credentials.json".into()));
    assert_eq!(r.describe(), alt);
    for bad in ["file:~/", "file:~/../x", "file:~/a//b", "file:/etc/passwd", "keychain:a|", "|env:A"] {
        assert!(SecretRef::parse(bad).is_err(), "{bad}");
    }
    assert!(SecretRef::parse("env:1BAD").is_err());
    assert!(SecretRef::parse("keychain:").is_err());
    assert!(SecretRef::parse("keychain:a#").is_err());
    assert!(SecretRef::parse("file:.hidden").is_err());
}

#[test]
fn ttl() {
    assert_eq!(parse_ttl("30m").unwrap(), Duration::from_secs(1800));
    assert_eq!(parse_ttl("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(parse_ttl("900s").unwrap(), Duration::from_secs(900));
    for bad in ["30", "0m", "m", "-1m", "1d"] {
        assert!(parse_ttl(bad).is_err(), "{bad}");
    }
}

proptest! {
    /// The decision over several pushes is the conjunction of the
    /// per-ref decisions, and a credential is bound only on allow.
    #[test]
    fn push_decision_is_conjunction(refs in proptest::collection::vec(("(agent/[a-z]{1,4}|main|feature/[a-z]{1,3})", any::<bool>()), 1..6)) {
        let p = policy(GIT);
        let adm = p.admit_host(&canon_host(b"github.com").unwrap(), 443).unwrap();
        let actions: Vec<Action> = refs.iter().map(|(r, f)| push("github.com/acme/web", &format!("refs/heads/{r}"), *f)).collect();
        let each_ok = actions.iter().all(|a| p.authorize_l7(&adm, std::slice::from_ref(a)).result.is_ok());
        let d = p.authorize_l7(&adm, &actions);
        prop_assert_eq!(d.result.is_ok(), each_ok);
        prop_assert_eq!(d.binding.is_some(), each_ok);
        let expect_ok = refs.iter().all(|(r, f)| r.starts_with("agent/") && !f);
        prop_assert_eq!(each_ok, expect_ok);
    }
}
