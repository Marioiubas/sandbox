use super::*;
use crate::config::parse_policy_str;
use crate::egress::{EgressPolicy, PathChoice};
use crate::l7::{Action, CompileEnv};
use crate::repo::RepoId;
use audit::Reason;
use netguard::canon_host;
use proptest::prelude::*;

fn env_with(session: SessionInfo) -> CompileEnv {
    CompileEnv {
        repo_remote: RepoId::parse("github.com/acme/web"),
        github_app_issuers: ["acme".to_string()].into_iter().collect(),
        session,
    }
}

fn session(mode: Mode) -> SessionInfo {
    SessionInfo {
        session_id: "s1".into(),
        task_id: "task-1".into(),
        user: "local:dev".into(),
        agent: "claude".into(),
        agent_sha256: "00".into(),
        repo: "acme/web".into(),
        branch_prefix: "agent/".into(),
        expires_at: entities::now_epoch() + 3600,
        mode,
    }
}

fn policy_in(toml: &str, s: SessionInfo) -> EgressPolicy {
    let p = parse_policy_str(toml).unwrap();
    EgressPolicy::compile_with([("user", p.egress.as_slice())], &env_with(s)).unwrap()
}

fn policy(toml: &str) -> EgressPolicy {
    policy_in(toml, session(Mode::Enforce))
}

const GIT: &str = r#"
version = 1
[[egress]]
host = "github.com"
id = "git"
protocol = "git"
allow = { fetch = ["${repo_remote}"], push = { repo = "${repo_remote}", refs = ["agent/*"], force = false } }
credential = { kind = "github_app", issuer = "acme", permissions = { contents = "write" }, repos = ["${repo_remote}"] }
[[egress]]
host = "api.anthropic.com"
id = "llm"
methods = ["POST"]
paths = ["/v1/messages", "/v1/messages/*"]
credential = { kind = "static", ref = "env:K", header = "x-api-key" }
[[egress]]
host = "*.example.com"
id = "wild"
ports = [443, 8443]
[[egress]]
host = "pastebin.com"
id = "paste"
"#;

fn h(s: &str) -> netguard::CanonicalHost {
    canon_host(s.as_bytes()).unwrap()
}

fn push(r: &str, refname: &str, force: bool) -> Action {
    Action::GitPush { repo: RepoId::parse(r).unwrap(), refname: refname.into(), force, update: "t" }
}

#[test]
fn schema_and_default_policies_validate() {
    let e = Engine::new(&[]).unwrap();
    assert!(e.base().policies().count() >= 10);
    validate(e.base()).unwrap();
}

/// The worked decisions of Example Cedar Policies, rows 1-5 and 8.
#[test]
fn golden_worked_decisions() {
    let p = policy(GIT);
    let adm = p.admit_host(&h("github.com"), 443).unwrap();
    let d = p.authorize_l7(&adm, &[push("github.com/acme/web", "refs/heads/agent/fix-1", false)]);
    assert!(d.result.is_ok(), "row 1: {d:?}");
    assert!(d.policy_ids.iter().any(|i| i == "user:git#push0"), "{:?}", d.policy_ids);
    assert_eq!(d.binding.unwrap().credential().id, "user:git");
    for (a, want) in [
        (push("github.com/acme/web", "refs/heads/main", false), Reason::GitRefNotAllowed),
        (push("github.com/acme/web", "refs/heads/agent/x", true), Reason::GitForcePush),
        (push("github.com/attacker/web", "refs/heads/agent/x", false), Reason::GitRepoNotAllowed),
    ] {
        let d = p.authorize_l7(&adm, std::slice::from_ref(&a));
        assert_eq!(d.result, Err(want), "{}", a.verb());
        assert!(d.binding.is_none());
    }
    // Row 8: an expired task denies everything, whatever permits exist.
    let mut s = session(Mode::Enforce);
    s.expires_at = entities::now_epoch() - 1;
    let exp = policy_in(GIT, s);
    assert_eq!(exp.admit_host(&h("github.com"), 443).unwrap_err().0, Reason::TaskExpired);
}

#[test]
fn admission_semantics_match_m0() {
    let p = policy(GIT);
    assert_eq!(p.admit_host(&h("evil.test"), 443).unwrap_err().0, Reason::HostNotAllowed);
    assert_eq!(p.admit_host(&h("8.8.8.8"), 443).unwrap_err().0, Reason::IpLiteral);
    assert_eq!(p.admit_host(&h("github.com"), 22).unwrap_err().0, Reason::PortNotAllowed);
    assert!(p.admit_host(&h("a.example.com"), 8443).is_ok());
    assert!(p.admit_host(&h("a.b.example.com"), 443).is_ok());
    assert_eq!(p.admit_host(&h("example.com"), 443).unwrap_err().0, Reason::HostNotAllowed, "*.x never matches x");
    // Paste sites stay outside the ceiling even when granted.
    assert_eq!(p.admit_host(&h("pastebin.com"), 443).unwrap_err().0, Reason::CeilingPasteSite);
    let mut a = p.admit_host(&h("api.anthropic.com"), 443).unwrap();
    assert_eq!(a.policy_ids, vec!["user:llm"]);
    assert_eq!(p.path_choice(&a), PathChoice::L7);
    assert_eq!(
        p.admit_addrs(&mut a, &["169.254.169.254".parse().unwrap()]).unwrap_err().0,
        Reason::MetadataAddr,
        "one bad address denies the name"
    );
    let mut a = p.admit_host(&h("api.anthropic.com"), 443).unwrap();
    p.admit_addrs(&mut a, &["160.79.104.10".parse().unwrap()]).unwrap();
    assert_eq!(a.addr_classes, vec!["public"]);
    let ok = p.authorize_l7(&a, &[Action::Http { method: "POST".into(), path: "/v1/messages".into() }]);
    assert!(ok.result.is_ok() && ok.binding.is_some());
    let sub = p.authorize_l7(&a, &[Action::Http { method: "POST".into(), path: "/v1/messages/count_tokens".into() }]);
    assert!(sub.result.is_ok(), "/v1/messages/* covers one more segment");
    let deep = p.authorize_l7(&a, &[Action::Http { method: "POST".into(), path: "/v1/messages/a/b".into() }]);
    assert_eq!(deep.result, Err(Reason::L7NoRuleMatched), "* stays within one segment");
    let get = p.authorize_l7(&a, &[Action::Http { method: "GET".into(), path: "/v1/messages".into() }]);
    assert_eq!(get.result, Err(Reason::L7NoRuleMatched));
    assert!(p.authorize_l7(&a, &[]).result.is_err(), "nothing classified: deny");
}

#[test]
fn record_mode_relaxes_task_permits_but_not_the_ceiling() {
    let p = policy_in(GIT, session(Mode::Record));
    // An ungranted public HTTPS name is admitted, and the would-deny recorded.
    let mut a = p.admit_host(&h("registry.npmjs.org"), 443).unwrap();
    assert_eq!(a.would_deny, Some(Reason::HostNotAllowed));
    p.admit_addrs(&mut a, &["104.16.0.1".parse().unwrap()]).unwrap();
    // …but never a private address, an IP literal, another port or the ceiling.
    let mut b = p.admit_host(&h("internal.corp.test"), 443).unwrap();
    assert!(p.admit_addrs(&mut b, &["10.0.0.5".parse().unwrap()]).is_err());
    assert!(p.admit_host(&h("8.8.8.8"), 443).is_err());
    assert!(p.admit_host(&h("registry.npmjs.org"), 22).is_err());
    assert_eq!(p.admit_host(&h("x.ngrok-free.app"), 443).unwrap_err().0, Reason::CeilingTunnel);
    assert_eq!(p.admit_host(&h("pastebin.com"), 443).unwrap_err().0, Reason::CeilingPasteSite);
    // L7 in record mode: unmatched requests pass with a would-deny, but no
    // credential is attached outside a grant.
    let mut g = p.admit_host(&h("github.com"), 443).unwrap();
    p.admit_addrs(&mut g, &["140.82.112.3".parse().unwrap()]).unwrap();
    let d = p.authorize_l7(&g, &[push("github.com/acme/web", "refs/heads/main", false)]);
    assert!(d.result.is_ok());
    assert_eq!(d.would_deny, Some(Reason::GitRefNotAllowed));
    assert!(d.binding.is_none(), "record mode never binds a credential no grant allowed");
    let ok = p.authorize_l7(&g, &[push("github.com/acme/web", "refs/heads/agent/x", false)]);
    assert!(ok.binding.is_some() && ok.would_deny.is_none());
}

#[test]
fn repo_layer_only_narrows() {
    let base = policy(GIT);
    let repo_toml = parse_policy_str(
        "version = 1\n[[egress]]\nhost = \"api.anthropic.com\"\nmethods = [\"POST\"]\npaths = [\"/v1/messages\"]\n\
         [[egress]]\nhost = \"evil.test\"\n",
    )
    .unwrap();
    let p = base.with_repo_layer(&repo_toml.egress, None, &env_with(session(Mode::Enforce))).unwrap();
    // A repo permit for a host the user never granted does not widen.
    assert_eq!(p.admit_host(&h("evil.test"), 443).unwrap_err().0, Reason::HostNotAllowed);
    // A host the repo layer does not list is narrowed away.
    assert_eq!(p.admit_host(&h("github.com"), 443).unwrap_err().0, Reason::RepoPolicyDenied);
    let mut a = p.admit_host(&h("api.anthropic.com"), 443).unwrap();
    p.admit_addrs(&mut a, &["160.79.104.10".parse().unwrap()]).unwrap();
    let d = p.authorize_l7(&a, &[Action::Http { method: "POST".into(), path: "/v1/messages/count_tokens".into() }]);
    assert_eq!(d.result, Err(Reason::RepoPolicyDenied), "the repo narrows paths");
    let ok = p.authorize_l7(&a, &[Action::Http { method: "POST".into(), path: "/v1/messages".into() }]);
    assert!(ok.result.is_ok() && ok.binding.is_some(), "credentials still come from the base layer");
    // Keys that confer authority are rejected in repo scope.
    for bad in ["credential = { kind = \"static\", ref = \"env:K\" }", "passthrough = true", "addrs = [\"10.0.0.1\"]"] {
        let t = parse_policy_str(&format!("version = 1\n[[egress]]\nhost = \"a.test\"\n{bad}\n")).unwrap();
        let e =
            policy(GIT).with_repo_layer(&t.egress, None, &env_with(session(Mode::Enforce))).unwrap_err().to_string();
        assert!(e.contains("not allowed in repository policy"), "{bad}: {e}");
    }
}

#[test]
fn raw_repo_cedar_only_narrows() {
    let base = policy(GIT);
    let widen = "permit (principal, action, resource);";
    let narrow = "forbid (principal, action == Broker::Action::\"git.push\", resource);";
    let p = base.clone().with_repo_layer(&[], Some(widen), &env_with(session(Mode::Enforce))).unwrap();
    // A repo-wide permit cannot widen what the base denies…
    assert_eq!(p.admit_host(&h("evil.test"), 443).unwrap_err().0, Reason::HostNotAllowed);
    let mut g = p.admit_host(&h("github.com"), 443).unwrap();
    p.admit_addrs(&mut g, &["140.82.112.3".parse().unwrap()]).unwrap();
    assert_eq!(
        p.authorize_l7(&g, &[push("github.com/acme/web", "refs/heads/main", false)]).result,
        Err(Reason::GitRefNotAllowed)
    );
    // …while a repo forbid narrows what the base allows.
    let q = base.with_repo_layer(&[], Some(&format!("{widen}\n{narrow}")), &env_with(session(Mode::Enforce))).unwrap();
    let mut g = q.admit_host(&h("github.com"), 443).unwrap();
    q.admit_addrs(&mut g, &["140.82.112.3".parse().unwrap()]).unwrap();
    assert_eq!(
        q.authorize_l7(&g, &[push("github.com/acme/web", "refs/heads/agent/x", false)]).result,
        Err(Reason::RepoPolicyDenied)
    );
    assert!(
        policy(GIT)
            .with_repo_layer(
                &[],
                Some("permit (principal, action, resource) when { nope };"),
                &env_with(session(Mode::Enforce))
            )
            .is_err()
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    /// For generated repo layers, allow_effective ⇒ allow_base (I4).
    #[test]
    fn repo_layers_never_widen(hosts in proptest::collection::vec(prop_oneof![Just("github.com"), Just("evil.test"), Just("api.anthropic.com"), Just("a.example.com")], 0..4),
                               methods in proptest::collection::vec(prop_oneof![Just("GET"), Just("POST"), Just("DELETE")], 0..3),
                               target in prop_oneof![Just("github.com"), Just("evil.test"), Just("api.anthropic.com"), Just("a.example.com"), Just("pastebin.com")],
                               method in prop_oneof![Just("GET"), Just("POST"), Just("DELETE")]) {
        let mut t = String::from("version = 1\n");
        for hst in &hosts {
            t.push_str(&format!("[[egress]]\nhost = \"{hst}\"\nmethods = {methods:?}\n"));
        }
        let repo = parse_policy_str(&t).unwrap();
        let base = policy(GIT);
        let eff = base.clone().with_repo_layer(&repo.egress, Some("permit (principal, action, resource);"), &env_with(session(Mode::Enforce))).unwrap();
        let host = h(target);
        let (b, e) = (base.admit_host(&host, 443), eff.admit_host(&host, 443));
        if e.is_ok() { prop_assert!(b.is_ok()); }
        if let (Ok(mut ba), Ok(mut ea)) = (b, e) {
            let addr: std::net::IpAddr = "93.184.216.34".parse().unwrap();
            let bok = base.admit_addrs(&mut ba, &[addr]).is_ok();
            let eok = eff.admit_addrs(&mut ea, &[addr]).is_ok();
            if eok { prop_assert!(bok); }
            if bok && eok {
                let a = [Action::Http { method: method.into(), path: "/v1/messages".into() }];
                if eff.authorize_l7(&ea, &a).result.is_ok() { prop_assert!(base.authorize_l7(&ba, &a).result.is_ok()); }
            }
        }
    }
}

#[test]
fn credential_ceiling_confines_credentials() {
    // A credential whose grant pattern does not cover the host is refused by
    // the ceiling even if the rest of the policy would bind it.
    let p = policy(GIT);
    let c = &p.credentials()[0];
    let mut adm = p.admit_host(&h("github.com"), 443).unwrap();
    p.admit_addrs(&mut adm, &["140.82.112.3".parse().unwrap()]).unwrap();
    let mut elsewhere = adm.clone();
    elsewhere.host = h("paste.example.org");
    let mut ents = entities::principal_entities(&session(Mode::Enforce));
    ents.push(entities::credential_entity(&c.id, "github_app", &["github.com".into()], &[]));
    let ctx = |dest: &str| {
        serde_json::json!({
            "session": entities::session_record(&session(Mode::Enforce), Mode::Enforce, entities::now_epoch()),
            "dest_host": dest, "dest_domains": [], "port": 443, "method": "", "path_str": "", "verb": "x",
        })
    };
    let e = p.engine();
    assert!(e.authorize("credential.use", &entities::credential_uid(&c.id), ents.clone(), ctx("github.com")).allowed);
    let v = e.authorize("credential.use", &entities::credential_uid(&c.id), ents, ctx("paste.example.org"));
    assert!(!v.allowed);
    assert_eq!(v.determining, vec!["credential-host-ceiling"]);
}

#[test]
fn malformed_requests_deny() {
    let e = Engine::new(&[]).unwrap();
    let ents = entities::principal_entities(&session(Mode::Enforce));
    let v =
        e.authorize("net.resolve", &entities::host_uid(&h("a.test")), ents.clone(), serde_json::json!({ "port": "x" }));
    assert!(!v.allowed && !v.errors.is_empty());
    let v = e.authorize("no.such.action", &entities::host_uid(&h("a.test")), ents, serde_json::json!({}));
    assert!(!v.allowed);
}

// ---------------------------------------------------------------- differential

fn arb_grants() -> impl Strategy<Value = String> {
    let method = prop_oneof![Just("GET"), Just("POST"), Just("PUT")];
    let path = prop_oneof![Just("/a"), Just("/a/*"), Just("/a/**"), Just("/b/c"), Just("/*/c")];
    (
        proptest::collection::vec(method, 0..3),
        proptest::collection::vec(path, 0..3),
        any::<bool>(),
        any::<bool>(),
        proptest::collection::vec(prop_oneof![Just("agent/*"), Just("main"), Just("refs/tags/v*")], 1..3),
        any::<bool>(),
    )
        .prop_map(|(ms, ps, with_methods, with_paths, refs, force)| {
            let mut t = String::from("version = 1\n[[egress]]\nhost = \"api.test\"\n");
            if with_methods {
                t.push_str(&format!("methods = {:?}\n", ms));
            }
            if with_paths {
                t.push_str(&format!("paths = {:?}\n", ps));
            }
            if !with_methods && !with_paths {
                t.push_str("protocol = \"http\"\n");
            }
            t.push_str(&format!(
                "[[egress]]\nhost = \"git.test\"\nprotocol = \"git\"\nallow = {{ fetch = [\"git.test/acme/web\"], push = {{ repo = \"git.test/acme/*\", refs = {:?}, force = {force} }} }}\n",
                refs
            ));
            t
        })
}

fn arb_action() -> impl Strategy<Value = (bool, Action)> {
    let http = (
        prop_oneof![Just("GET"), Just("POST"), Just("PUT"), Just("DELETE")],
        prop_oneof![Just("/a"), Just("/a/x"), Just("/a/x/y"), Just("/b/c"), Just("/z/c"), Just("/"), Just("/b")],
    )
        .prop_map(|(m, p)| (true, Action::Http { method: m.into(), path: p.into() }));
    let git = (
        prop_oneof![Just("git.test/acme/web"), Just("git.test/acme/other"), Just("git.test/evil/web")],
        prop_oneof![
            Just("refs/heads/agent/x"),
            Just("refs/heads/agent/a/b"),
            Just("refs/heads/main"),
            Just("refs/tags/v1")
        ],
        any::<bool>(),
        0..3u8,
    )
        .prop_map(|(r, refname, force, kind)| {
            let repo = RepoId::parse(r).unwrap();
            (
                false,
                match kind {
                    0 => Action::GitFetch { repo },
                    1 => Action::GitPushAdvertise { repo },
                    _ => Action::GitPush { repo, refname: refname.into(), force, update: "t" },
                },
            )
        });
    prop_oneof![http, git]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    /// Cedar and the reference evaluation (M1 semantics) agree on every
    /// generated grant set and request, in enforce mode.
    #[test]
    fn cedar_agrees_with_the_reference(toml in arb_grants(), acts in proptest::collection::vec(arb_action(), 1..3)) {
        let p = policy(&toml);
        for (is_http, a) in acts {
            let host = if is_http { "api.test" } else { "git.test" };
            let adm = p.admit_host(&h(host), 443).unwrap();
            let cedar = p.authorize_l7(&adm, std::slice::from_ref(&a));
            let reference = crate::l7::explain(
                p.grants().iter().filter(|g| g.pattern.matches(&h(host))).map(|g| (g.id.as_str(), g.l7.as_deref())),
                std::slice::from_ref(&a),
            );
            prop_assert_eq!(cedar.result.is_ok(), reference.result.is_ok(), "{} under\n{}", a.verb(), toml);
            prop_assert_eq!(cedar.result, reference.result);
        }
    }
}
