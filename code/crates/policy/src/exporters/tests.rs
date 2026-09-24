//! Exported files only narrow: on a generated host/port corpus, anything a
//! vendor file admits, the broker admits too.

use super::*;
use crate::config::parse_policy_str;
use proptest::prelude::*;

const POLICY: &str = r#"
version = 1
[[egress]]
host = "api.anthropic.com"
id = "llm"
methods = ["POST"]
paths = ["/v1/messages"]
credential = { kind = "static", ref = "env:K", header = "x-api-key" }
[[egress]]
host = "*.github.com"
id = "gh"
ports = [443, 8443]
[[egress]]
host = "pastebin.com"
id = "paste"
[[egress]]
host = "*.serveo.net"
id = "tunnel"
[[egress]]
host = "dns.google"
id = "doh"
[[egress]]
host = "[2001:db8::1]"
id = "v6"
"#;

fn policy() -> EgressPolicy {
    let p = parse_policy_str(POLICY).unwrap();
    EgressPolicy::compile([("user", p.egress.as_slice())]).unwrap()
}

fn normalized() -> Normalized {
    Normalized::from_policy(&policy(), &["~/.ssh".into(), "~/.aws".into()], &["~/.bashrc".into()])
}

#[test]
fn claude_settings_carry_the_fail_closed_flags_and_drop_ceiling_grants() {
    let e = claude::export(&normalized());
    let v: serde_json::Value = serde_json::from_str(&e.file).unwrap();
    let sb = &v["sandbox"];
    assert_eq!(sb["enabled"], true);
    assert_eq!(sb["failIfUnavailable"], true);
    assert_eq!(sb["allowUnsandboxedCommands"], false);
    assert_eq!(sb["network"]["allowManagedDomainsOnly"], true);
    let allowed: Vec<&str> =
        sb["network"]["allowedDomains"].as_array().unwrap().iter().filter_map(|x| x.as_str()).collect();
    assert_eq!(allowed, vec!["*.github.com:443", "*.github.com:8443", "[2001:db8::1]:443", "api.anthropic.com:443"]);
    assert!(sb["network"]["deniedDomains"].as_array().unwrap().iter().any(|x| x == "*.pastebin.com"));
    assert_eq!(sb["filesystem"]["denyRead"], serde_json::json!(["~/.aws", "~/.ssh"]));
    for g in ["user:paste", "user:tunnel", "user:doh"] {
        assert!(e.report.iter().any(|r| r.starts_with(g) && r.contains("dropped")), "{g}: {:?}", e.report);
    }
    assert!(e.report.iter().any(|r| r.contains("credential user:llm stays in the broker")));
    assert!(!e.file.contains("env:K"), "no secret reference is exported");
    // gist.github.com is a paste site: the wildcard allow does not reach it.
    assert!(!claude::allows(&e.file, "gist.github.com", 443));
    assert!(claude::allows(&e.file, "api.github.com", 443));
}

#[test]
fn codex_requirements_parse_and_match_the_documented_semantics() {
    let e = codex::export(&normalized(), "test");
    let v: toml::Value = toml::from_str(&e.file).unwrap();
    assert_eq!(v["allowed_sandbox_modes"].as_array().unwrap().len(), 2);
    assert_eq!(v["experimental_network"]["enabled"].as_bool(), Some(true));
    assert_eq!(v["experimental_network"]["managed_allowed_domains_only"].as_bool(), Some(true));
    assert_eq!(v["experimental_network"]["domains"]["*.github.com"].as_str(), Some("allow"));
    assert_eq!(v["experimental_network"]["domains"]["**.pastebin.com"].as_str(), Some("deny"));
    assert!(v["experimental_network"]["domains"].get("pastebin.com").is_none());
    assert!(codex::allows(&e.file, "api.anthropic.com"));
    assert!(!codex::allows(&e.file, "github.com"), "*.name is subdomains only");
    assert!(!codex::allows(&e.file, "gist.github.com"));
}

fn arb_host() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("api.anthropic.com".to_string()),
        Just("github.com".to_string()),
        Just("api.github.com".to_string()),
        Just("gist.github.com".to_string()),
        Just("a.b.github.com".to_string()),
        Just("pastebin.com".to_string()),
        Just("x.pastebin.com".to_string()),
        Just("a.serveo.net".to_string()),
        Just("dns.google".to_string()),
        Just("evil.test".to_string()),
        Just("[2001:db8::1]".to_string()),
        "[a-z]{1,6}\\.(github\\.com|example\\.org|anthropic\\.com)",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn exported_files_never_admit_what_the_broker_denies(host in arb_host(), port in prop_oneof![Just(443u16), Just(8443u16), Just(80u16)]) {
        let p = policy();
        let n = Normalized::from_policy(&p, &[], &[]);
        let h = netguard::canon_host(host.as_bytes()).unwrap();
        let spelled = h.as_str().to_string();
        let broker = p.admit_host(&h, port).is_ok();
        if claude::allows(&claude::export(&n).file, &spelled, port) {
            prop_assert!(broker, "claude export admits {spelled}:{port}; the broker does not");
        }
        // Codex cannot express ports: the host must be admitted on some port.
        if codex::allows(&codex::export(&n, "t").file, &spelled) {
            prop_assert!([443u16, 8443].iter().any(|pt| p.admit_host(&h, *pt).is_ok()), "codex export admits {spelled}");
        }
    }
}
