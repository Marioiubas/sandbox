//! The gates prove the shipped policy and catch deliberately broken ones.
//! Needs cvc5 (CVC5 env var or PATH); CI sets BROKER_REQUIRE_SOLVER=1 so a
//! missing solver fails instead of skipping.

use super::*;
use crate::cedar::{Mode, SessionInfo, entities};
use crate::config::parse_policy_str;
use crate::l7::{Action, CompileEnv};
use crate::repo::RepoId;
use proptest::prelude::*;

fn solver() -> bool {
    match solver_version() {
        Ok(_) => true,
        Err(e) if std::env::var_os("BROKER_REQUIRE_SOLVER").is_some() => panic!("{e}"),
        Err(e) => {
            eprintln!("skipping: {e}");
            false
        }
    }
}

fn env() -> CompileEnv {
    CompileEnv {
        repo_remote: RepoId::parse("github.com/acme/web"),
        github_app_issuers: ["acme".to_string()].into_iter().collect(),
        aws_sts_issuers: ["dev".to_string()].into_iter().collect(),
        session: SessionInfo {
            session_id: "s1".into(),
            task_id: "task-1".into(),
            user: "local:dev".into(),
            idp: "local".into(),
            agent: "claude".into(),
            agent_sha256: "00".into(),
            repo: "acme/web".into(),
            branch_prefix: "agent/".into(),
            expires_at: entities::now_epoch() + 3600,
            mode: Mode::Enforce,
        },
    }
}

fn egress(toml: &str) -> EgressPolicy {
    let p = parse_policy_str(toml).unwrap();
    EgressPolicy::compile_with([("user", p.egress.as_slice())], &env()).unwrap()
}

fn bundle(toml: &str) -> Bundle {
    Bundle::from_egress(&egress(toml))
}

const BASE: &str = r#"
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
[[egress]]
host = "acme-data.s3.us-east-1.amazonaws.com"
id = "data"
protocol = "s3"
s3 = { bucket = "acme-data", read = ["tasks/123/"], write = ["tasks/123/out/"] }
credential = { kind = "aws_sts", issuer = "dev" }
"#;

const WIDER: &str = r#"
[[egress]]
host = "api.github.com"
id = "learned"
methods = ["GET"]
paths = ["/repos/acme/web/pulls/*"]
"#;

fn without(b: &Bundle, id: &str) -> Bundle {
    let mut set = PolicySet::new();
    for p in b.set.policies().filter(|p| p.id().to_string() != id) {
        set.add(p.clone()).unwrap();
    }
    Bundle { set, credentials: b.credentials.clone(), force_opt_ins: b.force_opt_ins.clone() }
}

fn with(b: &Bundle, id: &str, src: &str) -> Bundle {
    let mut b = b.clone();
    b.set.add(Policy::parse(Some(PolicyId::new(id)), src).unwrap()).unwrap();
    b
}

#[test]
fn the_shipped_policy_passes_every_hard_gate() {
    if !solver() {
        return;
    }
    let new = bundle(BASE);
    let r = check(&Inputs { new: &new, old: None, repo: None }).unwrap();
    eprintln!("{}\n{} envs, {} queries, {} ms", r.render(), r.envs, r.queries, r.millis);
    assert!(r.hard_failures().is_empty(), "{}", r.render());
    assert!(r.findings.iter().any(|f| f.gate == Gate::CredentialConfinement && f.outcome == Outcome::Proved));
    assert!(r.findings.iter().any(|f| f.gate == Gate::DenyLive && f.subject == "pkg.publish needs approval"));
}

#[test]
fn a_learned_widening_shows_counterexamples_and_a_narrowing_is_proved() {
    if !solver() {
        return;
    }
    let (old, new) = (bundle(BASE), bundle(&format!("{BASE}{WIDER}")));
    let r = check(&Inputs { new: &new, old: Some(&old), repo: None }).unwrap();
    assert!(r.hard_failures().is_empty(), "{}", r.render());
    let w = r.widenings();
    assert!(!w.is_empty(), "{}", r.render());
    assert!(w.iter().any(|f| f.env.contains("http.GET")), "{}", r.render());
    // The expansion delta names the new host and a path under the new rule.
    let get = w.iter().find(|f| f.env.contains("http.GET")).unwrap();
    let Outcome::Failed { counterexample } = &get.outcome else { unreachable!() };
    assert!(
        counterexample.contains("api.github.com") && counterexample.contains("path /repos/acme/web/pulls/"),
        "{counterexample}"
    );
    assert!(r.summary().contains("human approval required"));
    // The reverse direction removes authority: proved.
    let r = check(&Inputs { new: &old, old: Some(&new), repo: None }).unwrap();
    assert!(r.widenings().is_empty() && r.hard_failures().is_empty(), "{}", r.render());
}

#[test]
fn each_hard_gate_catches_its_regression() {
    if !solver() {
        return;
    }
    let good = bundle(BASE);
    let failed = |b: &Bundle, g: Gate| {
        let r = check(&Inputs { new: b, old: None, repo: None }).unwrap();
        r.hard_failures().iter().any(|f| f.gate == g)
    };
    // A bundle that drops the org ceiling.
    let no_ceiling = without(&without(&without(&good, "ceiling-paste"), "ceiling-tunnel"), "ceiling-doh");
    assert!(failed(&no_ceiling, Gate::Ceiling));
    // Without the textual confinement the entity-based forbid is not enough:
    // the analyzer treats entity data as arbitrary.
    assert!(failed(&without(&good, "credential:user:llm#confine"), Gate::CredentialConfinement));
    // A policy that can overflow (an error skips a forbid in Cedar).
    let erring = with(
        &good,
        "overflow",
        "forbid (principal, action == Broker::Action::\"http.GET\", resource) when { context.port * 9223372036854775807 > 0 };",
    );
    assert!(failed(&erring, Gate::NeverErrors));
    // Publishing without approval.
    let publish = with(
        &without(&good, "publish-needs-approval"),
        "pub",
        "permit (principal, action == Broker::Action::\"pkg.publish\", resource);",
    );
    assert!(failed(&publish, Gate::DenyLive));
    // A deny rule that can never fire.
    let dead = with(&good, "dead", "@reason(\"policy_denied\")\nforbid (principal, action, resource) when { false };");
    assert!(failed(&dead, Gate::DenyLive));
    // A forced push allowed without a `force = true` grant (here: the
    // pre-gate record-mode permit).
    let force = with(
        &good,
        "force",
        "permit (principal, action == Broker::Action::\"git.push\", resource) when { context.session.mode == \"record\" };",
    );
    assert!(failed(&force, Gate::DenyLive));
    // A grant that opts in is not a failure.
    let opt_in = bundle(&BASE.replace("force = false", "force = true"));
    assert_eq!(opt_in.force_opt_ins, vec!["user:git#push0".to_string()]);
    assert!(!failed(&opt_in, Gate::DenyLive));
}

#[test]
fn the_repository_layer_only_narrows() {
    if !solver() {
        return;
    }
    let repo_toml =
        parse_policy_str("version = 1\n[[egress]]\nhost = \"api.anthropic.com\"\nmethods = [\"POST\"]\n").unwrap();
    let p =
        egress(BASE).with_repo_layer(&repo_toml.egress, Some("permit (principal, action, resource);"), &env()).unwrap();
    let new = Bundle::from_egress(&p);
    let r = check(&Inputs { new: &new, old: None, repo: p.engine().repo() }).unwrap();
    assert!(r.hard_failures().is_empty(), "{}", r.render());
    assert!(r.findings.iter().any(|f| f.gate == Gate::RepoNarrows && f.outcome == Outcome::Proved));
    // The union composition (repo permits added to the base) widens, and the
    // same query shows it.
    let mut union = new.clone();
    for q in p.engine().repo().unwrap().policies() {
        union.set.add(q.clone()).unwrap();
    }
    let r = check(&Inputs { new: &union, old: Some(&new), repo: None }).unwrap();
    assert!(!r.widenings().is_empty(), "{}", r.render());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]
    /// The single-set encoding the I4 gate proves allows exactly what the
    /// runtime's two-set conjunction allows (no solver needed).
    #[test]
    fn conjoin_agrees_with_the_runtime(
        hosts in proptest::collection::vec(prop_oneof![Just("github.com"), Just("evil.test"), Just("api.anthropic.com"), Just("a.example.com")], 0..3),
        methods in proptest::collection::vec(prop_oneof![Just("GET"), Just("POST")], 0..2),
        raw in prop_oneof![Just(None), Just(Some("permit (principal, action, resource);")),
                           Just(Some("forbid (principal, action == Broker::Action::\"http.POST\", resource);"))],
        target in prop_oneof![Just("github.com"), Just("evil.test"), Just("api.anthropic.com"), Just("a.example.com")],
        method in prop_oneof![Just("GET"), Just("POST")],
    ) {
        let mut t = String::from("version = 1\n");
        for hst in &hosts {
            t.push_str(&format!("[[egress]]\nhost = \"{hst}\"\nmethods = {methods:?}\n"));
        }
        let repo = parse_policy_str(&t).unwrap();
        let rt = egress(BASE).with_repo_layer(&repo.egress, raw, &env()).unwrap();
        let composed = conjoin(rt.engine().base(), rt.engine().repo().unwrap()).unwrap();
        let one = egress(BASE).with_engine(rt.engine().clone().with_base_only(composed));
        let host = netguard::canon_host(target.as_bytes()).unwrap();
        let (a, b) = (rt.admit_host(&host, 443), one.admit_host(&host, 443));
        prop_assert_eq!(a.is_ok(), b.is_ok());
        if let (Ok(mut ga), Ok(mut gb)) = (a, b) {
            let addr: std::net::IpAddr = "93.184.216.34".parse().unwrap();
            prop_assert_eq!(rt.admit_addrs(&mut ga, &[addr]).is_ok(), one.admit_addrs(&mut gb, &[addr]).is_ok());
            let acts = [Action::Http { method: method.into(), path: "/v1/messages".into() }];
            prop_assert_eq!(rt.authorize_l7(&ga, &acts).result.is_ok(), one.authorize_l7(&gb, &acts).result.is_ok());
        }
    }
}
