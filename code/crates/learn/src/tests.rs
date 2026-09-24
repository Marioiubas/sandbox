use super::*;
use audit::{AuditEvent, Dest, EventKind, RequestId, SessionId};
use policy::RepoId;
use policy::config::parse_policy_str;

fn start(s: &SessionId) -> AuditEvent {
    let mut e =
        AuditEvent::new(EventKind::SessionStart).session(s).detail("mode", "record").detail("profile", "default");
    e.agent = Some("claude".into());
    e
}

fn dest(host: &str, port: u16) -> Dest {
    Dest {
        ingress: Some("connect".into()),
        host: Some(host.into()),
        registrable: None,
        port: Some(port),
        addrs: vec!["93.184.216.34".into()],
    }
}

fn l4(s: &SessionId, host: &str, would: Option<Reason>) -> AuditEvent {
    let mut e = AuditEvent::new(EventKind::RequestDecision)
        .session(s)
        .request(&RequestId::new())
        .allow(vec![])
        .dest(dest(host, 443));
    if let Some(w) = would {
        e = e.audit_mode().detail("would_deny", w.as_str());
    }
    e
}

fn l7(s: &SessionId, host: &str, acts: &[policy::Action], would: Option<Reason>) -> AuditEvent {
    let mut e = AuditEvent::new(EventKind::RequestDecision)
        .session(s)
        .request(&RequestId::new())
        .allow(vec![])
        .dest(dest(host, 443))
        .detail("layer", "l7")
        .detail("actions", acts.iter().map(|a| a.to_json()).collect::<Vec<_>>());
    if let Some(w) = would {
        e = e.audit_mode().detail("would_deny", w.as_str());
    }
    e
}

fn denied(s: &SessionId, host: &str, r: Reason) -> AuditEvent {
    AuditEvent::new(EventKind::RequestDecision)
        .session(s)
        .request(&RequestId::new())
        .deny(r, vec![])
        .dest(dest(host, 443))
}

fn get(p: &str) -> policy::Action {
    policy::Action::Http { method: "GET".into(), path: p.into() }
}

fn push(refname: &str, force: bool) -> policy::Action {
    policy::Action::GitPush {
        repo: RepoId::parse("github.com/acme/web").unwrap(),
        refname: refname.into(),
        force,
        update: "t",
    }
}

/// Current policy: api.test and github.com are terminated (so L7 is seen);
/// nothing else is granted.
const CURRENT: &str = r#"
version = 1
[[egress]]
host = "api.test"
methods = ["POST"]
paths = ["/v1/messages"]
[[egress]]
host = "github.com"
protocol = "git"
allow = { fetch = ["github.com/acme/web"] }
"#;

fn corpus_events() -> Vec<AuditEvent> {
    let (s1, s2, s3) = (SessionId::new(), SessionId::new(), SessionId::new());
    let mut ev = vec![start(&s1), start(&s2), start(&s3)];
    for s in [&s1, &s2] {
        for h in ["registry.npmjs.org", "a.cdn.example", "b.cdn.example", "c.cdn.example"] {
            ev.push(l4(s, h, Some(Reason::HostNotAllowed)));
        }
        for n in ["101", "102", "103"] {
            ev.push(l7(s, "api.test", &[get(&format!("/repos/acme/web/pulls/{n}"))], Some(Reason::L7NoRuleMatched)));
        }
        for x in ["alpha", "beta", "gamma"] {
            ev.push(l7(s, "api.test", &[get(&format!("/repos/acme/web/labels/{x}"))], Some(Reason::L7NoRuleMatched)));
        }
        ev.push(l7(
            s,
            "api.test",
            &[policy::Action::Http { method: "POST".into(), path: "/v1/messages".into() }],
            None,
        ));
        ev.push(l7(s, "github.com", &[push("refs/heads/agent/fix", false)], Some(Reason::GitRepoNotAllowed)));
        ev.push(l7(s, "github.com", &[push("refs/heads/main", false)], Some(Reason::GitRepoNotAllowed)));
        ev.push(denied(s, "pastebin.com", Reason::CeilingPasteSite));
    }
    ev.push(l4(&s1, "once-only.example", Some(Reason::HostNotAllowed)));
    // A poisoned session: a planted key was rejected; nothing of it is learned.
    ev.push(denied(&s3, "api.test", Reason::ForeignCredential));
    ev.push(l4(&s3, "attacker-drop.example", Some(Reason::HostNotAllowed)));
    ev.push(l4(&s3, "attacker-drop.example", Some(Reason::HostNotAllowed)));
    ev
}

#[test]
fn mining_applies_the_safeguards() {
    let s = suggest(&corpus_events(), Options::default());
    let toml = s.render_toml();
    let report = s.render_report();
    // The diff parses and compiles with the same compiler as user policy.
    let parsed = parse_policy_str(&format!("version = 1\n{}", toml)).unwrap_or_else(|e| panic!("{e}\n{toml}"));
    EgressPolicy::compile([("learned", parsed.egress.as_slice())]).unwrap();
    let hosts: Vec<&str> = parsed.egress.iter().map(|e| e.host.as_str()).collect();
    assert!(hosts.contains(&"registry.npmjs.org"), "{toml}");
    assert!(hosts.contains(&"*.cdn.example"), "G4: 3 subdomains collapse: {toml}");
    assert!(!hosts.iter().any(|h| h.contains("attacker")), "P2: poisoned session excluded");
    assert!(!hosts.contains(&"once-only.example"), "P1: one session is not enough");
    assert!(!hosts.contains(&"pastebin.com"), "ceiling hits are never proposed");
    let api = parsed.egress.iter().find(|e| e.host == "api.test").unwrap();
    assert_eq!(api.methods.as_deref(), Some(&["GET".to_string()][..]), "G5: GET only");
    let paths = api.paths.clone().unwrap();
    assert!(paths.contains(&"/repos/acme/web/pulls/*".to_string()), "G2: IDs templated: {paths:?}");
    assert!(paths.contains(&"/repos/acme/web/labels/*".to_string()), "G3: 3 children in 2 runs collapse: {paths:?}");
    let git = parsed.egress.iter().find(|e| e.host == "github.com").unwrap();
    assert_eq!(git.allow.as_ref().unwrap().push[0].refs, vec!["agent/fix"]);
    assert!(toml.contains("# NEEDS REVIEW (risk high: push outside refs/heads/agent/)"), "{toml}");
    assert!(!parsed.egress.iter().any(|e| {
        e.allow.as_ref().is_some_and(|a| a.push.iter().any(|p| p.refs.contains(&"refs/heads/main".to_string())))
    }));
    assert!(report.contains("excluded") && report.contains("foreign_credential"), "{report}");
    assert!(report.contains("observed but blocked (ceiling_paste_site)"), "{report}");
    assert!(report.contains("contents=write"), "G8: {report}");
    assert!(report.contains("not proposed, seen in 1 session(s)"), "{report}");
}

#[test]
fn replay_shows_the_candidate_closes_the_gap() {
    let s = suggest(&corpus_events(), Options::default());
    let current = parse_policy_str(CURRENT).unwrap();
    let env = CompileEnv::default();
    let before = replay(&s.corpus, [("user", current.egress.as_slice())], &env).unwrap();
    let learned = s.active_entries();
    let after =
        replay(&s.corpus, [("user", current.egress.as_slice()), ("learned", learned.as_slice())], &env).unwrap();
    assert!(before.denied > 0);
    // Only the high-risk push to main and the once-only host stay denied.
    assert_eq!(after.denied, 3, "{after:?}");
    assert_eq!(after.blocked_still_denied, after.blocked_total, "the ceiling still blocks what it blocked");
}
