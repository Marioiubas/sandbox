//! `broker policy check` (SymCC CI Gates, eval layer L5): exit 0 when every
//! gate is proved, 2 when the policy widens its baseline (counterexamples
//! shown), 1 when a hard gate fails, 125 without a solver.

use conformance::*;
use std::process::Command;

const OLD: &str = "version = 1\n[[egress]]\nhost = \"api.anthropic.com\"\nid = \"llm\"\nmethods = [\"POST\"]\npaths = [\"/v1/messages\"]\n";
const WIDER: &str = "[[egress]]\nhost = \"api.github.com\"\nid = \"learned\"\nmethods = [\"GET\"]\npaths = [\"/repos/acme/web/pulls/*\"]\n";

fn check(h: &Harness, args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
    let mut c = Command::new(&h.bins.broker);
    c.args(["policy", "check"]).args(args).current_dir(h.repo.path()).env("BROKER_HOME", h.home.path());
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
}

#[test]
fn policy_check_proves_flags_widenings_and_blocks_hard_failures() {
    let h = Harness::new(OLD);
    let old = h.home.path().join("old.toml");
    let new = h.home.path().join("new.toml");
    std::fs::write(&old, OLD).unwrap();
    std::fs::write(&new, format!("{OLD}{WIDER}")).unwrap();
    let (old, new) = (old.to_str().unwrap(), new.to_str().unwrap());

    // No solver: a broker error, never a silent pass.
    let (code, text) = check(&h, &[], &[("CVC5", "/nonexistent/cvc5")]);
    assert_eq!(code, 125, "{text}");
    if !solver() {
        return;
    }

    // The configured user policy with a built-in profile: every gate proved.
    let (code, text) = check(&h, &["--profile", "claude-code"], &[]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("credential-confinement  proved"), "{text}");

    // A widening: exit 2 with the expansion delta.
    let (code, text) = check(&h, &["--policy", new, "--baseline", old], &[]);
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("newly permits: http.GET on Broker::Host::\"api.github.com\""), "{text}");
    assert!(text.contains("path /repos/acme/web/pulls/"), "{text}");

    // The reverse is a narrowing: proved.
    let (code, text) = check(&h, &["--policy", old, "--baseline", new, "--json"], &[]);
    assert_eq!(code, 0, "{text}");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(v["findings"].as_array().unwrap().iter().all(|f| f["outcome"] != "failed"));

    // Repository policy: a wide permit only narrows (I4)…
    let dot = h.repo.path().join(".broker");
    std::fs::create_dir_all(&dot).unwrap();
    std::fs::write(dot.join("policy.cedar"), "permit (principal, action, resource);\n").unwrap();
    let (code, text) = check(&h, &["--repo"], &[]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("repo-narrows            proved"), "{text}");
    // …and a repo policy that can error fails the never-errors gate.
    std::fs::write(
        dot.join("policy.cedar"),
        "forbid (principal, action == Broker::Action::\"http.GET\", resource) when { context.port * 9223372036854775807 > 0 };\n",
    )
    .unwrap();
    let (code, text) = check(&h, &["--repo"], &[]);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("never-errors            FAILED"), "{text}");
}
