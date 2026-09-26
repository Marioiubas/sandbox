//! GitHub verbs through Cedar: compile rules fail closed, Cedar agrees with
//! the explainer, and the Rule of Two fires once both labels are raised.

use super::*;
use crate::config::parse_policy_str;
use crate::egress::EgressPolicy;
use crate::github::{Label, Visibility};
use crate::l7::{Action, CompileEnv};
use crate::repo::RepoId;
use audit::Reason;
use netguard::canon_host;
use proptest::prelude::*;

fn env() -> CompileEnv {
    CompileEnv {
        repo_remote: RepoId::parse("github.com/acme/web"),
        session: SessionInfo { expires_at: entities::now_epoch() + 3600, ..Default::default() },
        ..Default::default()
    }
}

fn policy(toml: &str) -> EgressPolicy {
    let p = parse_policy_str(toml).unwrap();
    EgressPolicy::compile_with([("user", p.egress.as_slice())], &env()).unwrap()
}

fn gh(verb: &str, repo: Option<&str>, vis: Visibility, method: &str) -> Action {
    Action::GitHub {
        verb: verb.into(),
        repo: repo.map(|r| RepoId::parse(r).unwrap()),
        visibility: vis,
        bodies: false,
        method: method.into(),
        path: "/x".into(),
        node: None,
        field: None,
    }
}

fn decide(p: &EgressPolicy, a: Action) -> Result<(), Reason> {
    let mut adm = p.admit_host(&canon_host(b"api.github.com").unwrap(), 443).unwrap();
    p.admit_addrs(&mut adm, &["140.82.112.5".parse().unwrap()]).unwrap();
    let m = match &a {
        Action::GitHub { method, .. } => method.clone(),
        _ => "GET".into(),
    };
    p.authorize_l7(&adm, &[Action::Http { method: m, path: "/x".into() }, a]).result
}

const API: &str = r#"
version = 1
[[egress]]
host = "api.github.com"
id = "gh"
protocol = "github"
verbs = ["repo.read", "pr.create", "issue.comment", "github.read"]
repos = ["${repo_remote}", "github.com/acme-public/*"]
"#;

#[test]
fn verbs_compile_fail_closed() {
    for bad in [
        "version = 1\n[[egress]]\nhost = \"api.github.com\"\nprotocol = \"github\"\n",
        "version = 1\n[[egress]]\nhost = \"api.github.com\"\nprotocol = \"github\"\nverbs = [\"pr.nuke\"]\n",
        "version = 1\n[[egress]]\nhost = \"api.github.com\"\nprotocol = \"github\"\nverbs = [\"repo.read\"]\nmethods = [\"GET\"]\n",
        "version = 1\n[[egress]]\nhost = \"api.github.com\"\nverbs = [\"repo.read\"]\nmethods = [\"GET\"]\n",
    ] {
        let p = parse_policy_str(bad).unwrap();
        assert!(EgressPolicy::compile_with([("user", p.egress.as_slice())], &env()).is_err(), "{bad}");
    }
    // `repos` absent means the task repository only.
    let p =
        policy("version = 1\n[[egress]]\nhost = \"api.github.com\"\nprotocol = \"github\"\nverbs = [\"pr.create\"]\n");
    assert_eq!(decide(&p, gh("pr.create", Some("github.com/acme/web"), Visibility::Unknown, "POST")), Ok(()));
    assert_eq!(
        decide(&p, gh("pr.create", Some("github.com/acme/other"), Visibility::Unknown, "POST")),
        Err(Reason::GithubRepoNotAllowed)
    );
}

#[test]
fn verbs_decide_and_the_rule_of_two_fires() {
    let p = policy(API);
    let web = Some("github.com/acme/web");
    assert_eq!(decide(&p, gh("repo.read", web, Visibility::Private, "GET")), Ok(()));
    assert_eq!(decide(&p, gh("github.read", None, Visibility::Unknown, "GET")), Ok(()));
    assert_eq!(decide(&p, gh("pr.merge", web, Visibility::Private, "PUT")), Err(Reason::GithubVerbNotAllowed));
    assert_eq!(
        decide(&p, gh("pr.create", Some("github.com/evil/loot"), Visibility::Public, "POST")),
        Err(Reason::GithubRepoNotAllowed)
    );
    // A merge grant still needs approval (the default forbid).
    let m = policy(&API.replace("\"github.read\"]", "\"github.read\", \"pr.merge\"]"));
    assert_eq!(decide(&m, gh("pr.merge", web, Visibility::Private, "PUT")), Err(Reason::NeedsApproval));
    // Untrusted input alone: the public PR is allowed (ADR-010's benign case).
    let public = Some("github.com/acme-public/site");
    p.labels().raise(Label::UntrustedInput);
    assert_eq!(decide(&p, gh("pr.create", public, Visibility::Public, "POST")), Ok(()));
    // Both labels live: every write needs approval; reads still pass.
    p.labels().raise(Label::SensitiveRead);
    assert_eq!(decide(&p, gh("pr.create", public, Visibility::Public, "POST")), Err(Reason::RuleOfTwo));
    assert_eq!(decide(&p, gh("issue.comment", web, Visibility::Private, "POST")), Err(Reason::RuleOfTwo));
    assert_eq!(decide(&p, gh("repo.read", web, Visibility::Private, "GET")), Ok(()));
    // GraphQL reads are POSTs: the verb, not the method, decides (ADR-035).
    assert_eq!(decide(&p, gh("github.read", None, Visibility::Unknown, "POST")), Ok(()));
    assert_eq!(decide(&p, gh("repo.read", web, Visibility::Private, "POST")), Ok(()));
    // Every write verb is stopped, whatever method carries it.
    for (verb, repo) in [("pr.create", public), ("issue.comment", web)] {
        for m in ["POST", "PUT", "GET"] {
            assert_eq!(decide(&p, gh(verb, repo, Visibility::Public, m)), Err(Reason::RuleOfTwo), "{verb} {m}");
        }
    }
    // A plain HTTP write without a verb is still covered by the method.
    let adm = {
        let mut a = p.admit_host(&canon_host(b"api.github.com").unwrap(), 443).unwrap();
        p.admit_addrs(&mut a, &["140.82.112.5".parse().unwrap()]).unwrap();
        a
    };
    let post = [Action::Http { method: "POST".into(), path: "/x".into() }];
    assert_eq!(p.authorize_l7(&adm, &post).result, Err(Reason::RuleOfTwo));
}

fn arb_verb() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("repo.read"),
        Just("pr.create"),
        Just("pr.merge"),
        Just("issue.comment"),
        Just("contents.write"),
        Just("github.read"),
        Just("gist.create"),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]
    /// Cedar and the explainer agree on GitHub verbs (the verb, the repo
    /// scope and the approval forbids aside, which only Cedar knows).
    #[test]
    fn cedar_agrees_with_the_reference_on_verbs(
        granted in proptest::collection::vec(arb_verb(), 0..4),
        repos in prop_oneof![Just("[\"${repo_remote}\"]"), Just("[\"github.com/acme/*\"]"), Just("[]")],
        verb in arb_verb(),
        repo in prop_oneof![Just("github.com/acme/web"), Just("github.com/acme/x"), Just("github.com/evil/y")],
    ) {
        let toml = format!(
            "version = 1\n[[egress]]\nhost = \"api.github.com\"\nprotocol = \"github\"\nverbs = {granted:?}\nrepos = {repos}\n"
        );
        let p = policy(&toml);
        let a = gh(verb, crate::github::is_repo_verb(verb).then_some(repo), Visibility::Unknown, "POST");
        let cedar = decide(&p, a.clone());
        let reference = crate::l7::explain(p.grants().iter().map(|g| (g.id.as_str(), g.l7.as_deref())), &[a]).result;
        if verb == "pr.merge" && reference.is_ok() {
            prop_assert_eq!(cedar, Err(Reason::NeedsApproval));
        } else {
            prop_assert_eq!(cedar.is_ok(), reference.is_ok(), "cedar {:?} reference {:?}", cedar, reference);
        }
    }
}

/// MCP calls: a pinned server's tools pass, denied tools and unpinned
/// servers do not, and a write tool joins the Rule of Two.
#[test]
fn mcp_calls_decide() {
    let p = parse_policy_str(
        "version = 1\n[mcp.gh]\ncommand = [\"/bin/true\"]\ntools.write = [\"post\"]\ntools.deny = [\"delete_repo\"]\n",
    )
    .unwrap();
    let e = EgressPolicy::compile_with([("user", p.egress.as_slice())], &env()).unwrap().with_mcp(&p.mcp).unwrap();
    let call =
        |tool: &str, pinned: bool, write: bool| e.authorize_mcp("gh", "sha256:x", pinned, tool, "sha256:a", write);
    assert!(call("read", true, false).is_ok());
    assert!(call("post", true, true).is_ok());
    assert_eq!(call("delete_repo", true, false).unwrap_err().0, Reason::McpToolNotAllowed);
    assert_eq!(call("read", false, false).unwrap_err().0, Reason::McpUnpinned);
    assert_eq!(
        e.authorize_mcp("other", "sha256:x", true, "read", "sha256:a", false).unwrap_err().0,
        Reason::McpToolNotAllowed
    );
    e.labels().raise(Label::UntrustedInput);
    e.labels().raise(Label::SensitiveRead);
    assert_eq!(call("post", true, true).unwrap_err().0, Reason::RuleOfTwo);
    assert!(call("read", true, false).is_ok(), "reads still pass");
    // Invalid definitions fail closed.
    for bad in [
        "version = 1\n[mcp.gh]\ncommand = [\"relative\"]\n",
        "version = 1\n[mcp.GH]\ncommand = [\"/bin/true\"]\n",
        "version = 1\n[mcp.gh]\ncommand = []\n",
    ] {
        assert!(parse_policy_str(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_org_option_denies_public_sinks_after_untrusted_input() {
    let toml = format!(
        "{}\n[[egress]]\nhost = \"github.com\"\nid = \"git\"\nprotocol = \"git\"\n\
         allow = {{ push = {{ repo = \"${{repo_remote}}\", refs = [\"agent/*\"] }} }}\n",
        API.replace("\"github.read\"]", "\"github.read\", \"gist.create\"]")
    );
    let p = parse_policy_str(&toml).unwrap();
    let strict = CompileEnv { deny_public_sinks_after_untrusted_input: true, ..env() };
    // As the daemon builds it: the MCP rebuild keeps the option's forbids.
    let on = EgressPolicy::compile_with([("user", p.egress.as_slice())], &strict).unwrap().with_mcp(&p.mcp).unwrap();
    let off = EgressPolicy::compile_with([("user", p.egress.as_slice())], &env()).unwrap();
    let (public, web) = (Some("github.com/acme-public/site"), Some("github.com/acme/web"));
    let push = |e: &EgressPolicy| {
        let mut adm = e.admit_host(&canon_host(b"github.com").unwrap(), 443).unwrap();
        e.admit_addrs(&mut adm, &["140.82.112.3".parse().unwrap()]).unwrap();
        let a = Action::GitPush {
            repo: RepoId::parse("github.com/acme/web").unwrap(),
            refname: "refs/heads/agent/x".into(),
            force: false,
            update: "t",
        };
        e.authorize_l7(&adm, &[a]).result
    };
    for e in [&on, &off] {
        assert_eq!(decide(e, gh("pr.create", public, Visibility::Public, "POST")), Ok(()), "no untrusted input yet");
        assert_eq!(push(e), Ok(()));
        e.labels().raise(Label::UntrustedInput);
    }
    // Off (the default): [A]+[C] alone is allowed, as ADR-010 describes.
    assert_eq!(decide(&off, gh("pr.create", public, Visibility::Public, "POST")), Ok(()));
    assert_eq!(push(&off), Ok(()));
    // On: public sinks and repositories not known to be private are denied.
    let sink = Err(Reason::PublicSinkAfterUntrustedInput);
    assert_eq!(decide(&on, gh("pr.create", public, Visibility::Public, "POST")), sink);
    assert_eq!(decide(&on, gh("issue.comment", web, Visibility::Unknown, "POST")), sink);
    assert_eq!(decide(&on, gh("gist.create", None, Visibility::Unknown, "POST")), sink);
    assert_eq!(push(&on), sink, "pushes carry no looked-up visibility, so every push counts");
    assert_eq!(
        decide(&on, gh("pr.create", web, Visibility::Private, "POST")),
        Ok(()),
        "a private repository is not a sink"
    );
    assert_eq!(decide(&on, gh("repo.read", public, Visibility::Public, "GET")), Ok(()), "reads pass");
    // A verb that is not granted still reports the more specific reason.
    assert_eq!(decide(&on, gh("pr.merge", public, Visibility::Public, "PUT")), Err(Reason::GithubVerbNotAllowed));
}

#[test]
fn a_human_approval_lifts_exactly_one_action_once() {
    use crate::approvals::Scope;
    let p = policy(API);
    let adm = {
        let mut a = p.admit_host(&canon_host(b"api.github.com").unwrap(), 443).unwrap();
        p.admit_addrs(&mut a, &["140.82.112.5".parse().unwrap()]).unwrap();
        a
    };
    let pr = |repo: &str| {
        vec![
            Action::Http { method: "POST".into(), path: "/x".into() },
            gh("pr.create", Some(repo), Visibility::Public, "POST"),
        ]
    };
    let public = "github.com/acme-public/site";
    p.labels().raise(Label::UntrustedInput);
    p.labels().raise(Label::SensitiveRead);
    let dec = p.authorize_l7(&adm, &pr(public));
    assert_eq!(dec.result, Err(Reason::RuleOfTwo));
    let keys = p.approvable(&adm, &pr(public), &dec).expect("approval would help");
    assert_eq!(keys, vec!["github pr.create github.com/acme-public/site".to_string()]);
    // A repository the grant does not cover is not approvable.
    let evil = pr("github.com/evil/loot");
    let dec = p.authorize_l7(&adm, &evil);
    assert_eq!(p.approvable(&adm, &evil, &dec), None);
    // Approved once: this action passes, another does not, and it is used up.
    p.approvals().grant(keys[0].clone(), Scope::Once);
    assert_eq!(p.authorize_l7(&adm, &pr(public)).result, Ok(()));
    let other = pr("github.com/acme-public/other");
    assert_eq!(p.authorize_l7(&adm, &other).result, Err(Reason::RuleOfTwo));
    let used = p.approvals_used(&adm, &pr(public));
    assert_eq!(used, keys);
    p.approvals().consume(&used);
    assert_eq!(p.authorize_l7(&adm, &pr(public)).result, Err(Reason::RuleOfTwo));
    // For the session: it stays.
    p.approvals().grant(keys[0].clone(), Scope::Session);
    p.approvals().consume(&keys);
    assert_eq!(p.authorize_l7(&adm, &pr(public)).result, Ok(()));
    // The merge approval (needs_approval) works the same way.
    let m = policy(&API.replace("\"github.read\"]", "\"github.read\", \"pr.merge\"]"));
    let merge = vec![
        Action::Http { method: "PUT".into(), path: "/x".into() },
        gh("pr.merge", Some("github.com/acme/web"), Visibility::Private, "PUT"),
    ];
    let dec = m.authorize_l7(&adm, &merge);
    assert_eq!(dec.result, Err(Reason::NeedsApproval));
    assert_eq!(m.approvable(&adm, &merge, &dec), Some(vec!["github pr.merge github.com/acme/web".to_string()]));
}

#[test]
fn the_model_api_is_not_a_write_destination_for_the_rule_of_two() {
    let toml = r#"
version = 1
[[egress]]
id = "model"
host = "api.anthropic.com"
model_api = true
methods = ["POST"]

[[egress]]
id = "other"
host = "paste.example"
methods = ["POST"]
"#;
    let p = policy(toml);
    let post = |host: &str| {
        let mut a = p.admit_host(&canon_host(host.as_bytes()).unwrap(), 443).unwrap();
        p.admit_addrs(&mut a, &["140.82.112.5".parse().unwrap()]).unwrap();
        p.authorize_l7(&a, &[Action::Http { method: "POST".into(), path: "/v1/messages".into() }]).result
    };
    p.labels().raise(Label::UntrustedInput);
    p.labels().raise(Label::SensitiveRead);
    assert_eq!(post("api.anthropic.com"), Ok(()), "the agent keeps its model API with both labels live");
    assert_eq!(post("paste.example"), Err(Reason::RuleOfTwo), "any other write is still held");
    // Only a plain HTTP grant may be a model API, and a repository layer can never mark one.
    let bad = parse_policy_str("version = 1\n[[egress]]\nhost = \"api.github.com\"\nprotocol = \"github\"\nverbs = [\"repo.read\"]\nmodel_api = true\n").unwrap();
    assert!(EgressPolicy::compile_with([("user", bad.egress.as_slice())], &env()).is_err());
    let repo = parse_policy_str("version = 1\n[[egress]]\nhost = \"api.anthropic.com\"\nmodel_api = true\n").unwrap();
    assert!(policy(toml).with_repo_layer(&repo.egress, None, &env()).is_err());
}
