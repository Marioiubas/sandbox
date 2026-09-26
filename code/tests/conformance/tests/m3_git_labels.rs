//! Git fetches and the session labels (ADR-036): fetching a repository that
//! is not known to be public raises `sensitive_read`, so the toxic flow
//! cannot route its private read through `git clone`. The broker learns
//! visibility from an anonymous `info/refs` probe on the same host.

use audit::EventKind;
use conformance::m1::*;
use conformance::*;

struct Git {
    h: Harness,
    gh: FakeGitHub,
    _ca_dir: tempfile::TempDir,
}

fn setup() -> Git {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let gh = FakeGitHub::start(&ca, "github.test");
    let web = gh.create_repo("acme", "web");
    gh.create_repo("acme", "secret");
    gh.create_repo("acme", "pub");
    gh.public.lock().unwrap().push("acme/pub".into());
    let port = gh.server.port;
    let repos =
        format!(r#"["github.test:{port}/acme/web", "github.test:{port}/acme/secret", "github.test:{port}/acme/pub"]"#);
    let grant = loopback_grant(
        "git",
        "github.test",
        port,
        &format!(
            "protocol = \"git\"\nallow = {{ fetch = {repos} }}\n\
             credential = {{ kind = \"github_app\", issuer = \"test\", permissions = {{ contents = \"read\" }}, repos = {repos}, ttl = \"30m\" }}"
        ),
    );
    let config = format!(
        "version = 1\n[tls]\nextra_roots = [\"{ca}\"]\n\n[issuers.github_app.test]\napp_id = \"{APP_ID}\"\n\
         installation_id = \"{INSTALLATION}\"\nprivate_key = \"file:gh-app.pem\"\napi_base = \"https://github.test:{port}\"\n\
         api_addrs = [\"127.0.0.1\"]\n\n{grant}",
        ca = ca.pem_path.display()
    );
    let url = gh.url("acme", "web");
    let h = Harness::custom(&config, &[], |p| {
        host_git(p, &["clone", "-q", &web.display().to_string(), "."]);
        host_git(p, &["remote", "set-url", "origin", &url]);
    });
    h.write_secret("gh-app.pem", &gh.key_pem);
    Git { h, gh, _ca_dir: ca_dir }
}

impl Git {
    /// `git ls-remote` of each `acme/<name>` in one session; labels raised.
    fn fetch(&self, names: &[&str]) -> Vec<(String, String)> {
        let n0 = self.h.events().len();
        let script: String =
            names.iter().map(|n| format!("git ls-remote {} >/dev/null && echo OK; ", self.gh.url("acme", n))).collect();
        let r = self.h.sh(&script);
        assert_eq!(r.stdout.matches("OK").count(), names.len(), "{names:?}: {r:?}");
        self.h
            .events()
            .into_iter()
            .skip(n0)
            .filter(|e| e.kind == EventKind::SessionLabel)
            .map(|e| {
                let s = |k: &str| e.detail.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                (s("label"), s("cause"))
            })
            .collect()
    }
}

#[test]
fn fetching_a_public_repository_is_not_a_sensitive_read() {
    let g = setup();
    assert_eq!(g.fetch(&["pub"]), vec![], "anyone can fetch acme/pub");
    // The probe was anonymous; the fetch itself used the minted token.
    let seen = g.gh.server.seen();
    let probes: Vec<_> = seen.iter().filter(|s| s.path == "/acme/pub.git/info/refs").collect();
    assert!(probes.iter().any(|s| s.header("authorization").is_none()), "an anonymous probe");
    assert!(probes.iter().any(|s| s.header("authorization").is_some()), "the brokered fetch");
}

#[test]
fn fetching_a_private_repository_is_a_sensitive_read() {
    let g = setup();
    // Twice in one session: one label, one probe (cached for the session).
    let cause = format!("git.fetch github.test:{}/acme/secret", g.gh.server.port);
    assert_eq!(g.fetch(&["secret", "secret"]), vec![("sensitive_read".to_string(), cause)]);
    let probes =
        g.gh.server
            .seen()
            .iter()
            .filter(|s| s.path == "/acme/secret.git/info/refs" && s.header("authorization").is_none())
            .count();
    assert_eq!(probes, 1, "one anonymous probe per repository per session");
    g.h.verify_audit().unwrap();
}
