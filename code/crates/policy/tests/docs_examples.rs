//! Every TOML example in `docs/policy-reference.md` parses and compiles, so
//! the reference cannot drift from what the broker accepts.

use policy::{CompileEnv, EgressPolicy, RepoId};

#[test]
fn policy_reference_examples_compile() {
    let text = include_str!("../../../docs/policy-reference.md");
    let mut blocks = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        match (&mut cur, line.trim()) {
            (None, "```toml") => cur = Some(String::new()),
            (Some(b), "```") => {
                blocks.push(std::mem::take(b));
                cur = None;
            }
            (Some(b), _) => {
                b.push_str(line);
                b.push('\n');
            }
            _ => {}
        }
    }
    assert!(blocks.len() >= 2, "examples found: {}", blocks.len());
    for b in blocks {
        let doc = if b.contains("version =") { b } else { format!("version = 1\n{b}") };
        let p = policy::config::parse_policy_str(&doc).unwrap_or_else(|e| panic!("{e}\n{doc}"));
        let env = CompileEnv {
            repo_remote: RepoId::parse("github.com/acme/web"),
            github_app_issuers: p.issuers.github_app.keys().cloned().collect(),
            ..Default::default()
        };
        EgressPolicy::compile_with([("user", p.egress.as_slice())], &env).unwrap_or_else(|e| panic!("{e}\n{doc}"));
    }
}
