//! Adversarial review of the credential path (2026-10-06, branch
//! `review-creds`). Each test states what the invariants require of
//! `creds`: GitHub App tokens no wider than the grant (Credential Injector
//! and Issuers: "unexpected scope in the response: deny"), and I7 (a
//! client credential the broker did not issue never reaches an upstream).
//! A failing test is an open defect; none of them changes product code.

use audit::Reason;
use creds::Secret;
use creds::foreign::{inspect, strip};
use creds::issuers::github_app::{self, GitHubApp};
use creds::issuers::{ApiEndpoint, Transport};
use creds::sentinel::Sentinels;
use http::{HeaderMap, HeaderValue};
use netguard::{CanonicalHost, HostPattern, canon_host};
use policy::config::GitHubAppIssuerSpec;
use policy::{AttachSpec, CredKind, CredentialDef, RepoId, SecretRef};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

fn contents_write() -> BTreeMap<String, String> {
    [("contents".to_string(), "write".to_string())].into()
}

/// A throwaway RSA key for this run (as `github_app::tests` makes one).
fn rsa_pem() -> Secret {
    let out = std::process::Command::new("openssl").args(["genrsa", "2048"]).output().expect("openssl on PATH");
    assert!(out.status.success(), "openssl genrsa failed");
    Secret::new(out.stdout)
}

// ---------------------------------------------------------------------
// GitHub App installation tokens: the owner is part of the scope.
//
// `request_body` sends repository *names* only, and GitHub resolves them
// inside the installation's account. `verify_response` compares the
// returned `repositories[].name` with the requested names and never looks
// at `full_name` / `owner.login`, and `same_instance` checks only the host.
// So a credential whose repos resolve to `github.com/evil/infra` (for
// example `${repo_remote}` in a checkout of an attacker's repository, or of
// a fork) is minted as a contents:write token for the installation's own
// `acme/infra`, and the broker accepts and caches it. A grant with the
// host-wide `github.read` verb (GraphQL `search`/`node`, REST search)
// then reads `acme/infra` with that token although no policy names it.
// ---------------------------------------------------------------------

#[test]
fn github_app_token_for_another_owners_same_named_repo_is_refused() {
    let resp = br#"{"token":"ghs_CANARYTOKEN","expires_at":"2099-01-01T00:00:00Z",
        "permissions":{"contents":"write","metadata":"read"},"repository_selection":"selected",
        "repositories":[{"name":"infra","full_name":"acme/infra","owner":{"login":"acme"}}]}"#;
    // Control: the same response is right for a credential naming acme/infra.
    let own = vec![RepoId::parse("github.com/acme/infra").unwrap()];
    assert!(github_app::verify_response(201, resp, &contents_write(), &own).is_ok());
    let requested = vec![RepoId::parse("github.com/evil/infra").unwrap()];
    let got = github_app::verify_response(201, resp, &contents_write(), &requested);
    assert!(
        got.is_err(),
        "a token GitHub scoped to acme/infra was accepted for a credential that names only github.com/evil/infra"
    );
}

/// GitHub as it answers `POST /app/installations/{id}/access_tokens`:
/// names are looked up in the installation's account; the response lists
/// the full repositories the token covers.
struct InstallationOf {
    account: &'static str,
    repos: &'static [&'static str],
    calls: Mutex<u32>,
}

#[async_trait::async_trait]
impl Transport for InstallationOf {
    async fn post_json(&self, _: &ApiEndpoint, _: &str, _: &Secret, body: Vec<u8>) -> anyhow::Result<(u16, Vec<u8>)> {
        *self.calls.lock().unwrap() += 1;
        let v: serde_json::Value = serde_json::from_slice(&body)?;
        let mut covered = Vec::new();
        for n in v["repositories"].as_array().cloned().unwrap_or_default() {
            let n = n.as_str().unwrap_or_default().to_string();
            if !self.repos.contains(&n.as_str()) {
                return Ok((422, br#"{"message":"repository not accessible to the installation"}"#.to_vec()));
            }
            covered.push(
                json!({ "name": n, "full_name": format!("{}/{n}", self.account), "owner": { "login": self.account } }),
            );
        }
        let resp = json!({
            "token": "ghs_MINTEDFORACMEINFRA", "expires_at": "2099-01-01T00:00:00Z",
            "permissions": v["permissions"], "repository_selection": "selected", "repositories": covered,
        });
        Ok((201, serde_json::to_vec(&resp)?))
    }
}

#[tokio::test]
async fn github_app_mint_for_a_repo_of_another_owner_yields_no_token() {
    let spec = GitHubAppIssuerSpec {
        app_id: "1".into(),
        installation_id: "42".into(),
        private_key: "env:UNUSED".into(),
        api_base: None,
        api_addrs: vec![],
    };
    let app = GitHubApp::from_spec("acme", &spec).unwrap();
    let key = github_app::load_rsa_key(&rsa_pem()).unwrap();
    let gh = InstallationOf { account: "acme", repos: &["web", "infra"], calls: Mutex::new(0) };
    // Control: the installation's own repository mints.
    let own = vec![RepoId::parse("github.com/acme/infra").unwrap()];
    assert!(github_app::mint(&app, &key, &gh, &contents_write(), &own).await.is_ok());
    let requested = vec![RepoId::parse("github.com/evil/infra").unwrap()];
    let got = github_app::mint(&app, &key, &gh, &contents_write(), &requested).await;
    assert_eq!(*gh.calls.lock().unwrap(), 2, "the mint request reached GitHub");
    assert!(
        got.is_err(),
        "the broker now holds a contents:write token for acme/infra; the policy named only github.com/evil/infra"
    );
}

/// Fail closed on a response that does not state the token's repository
/// scope (the code already does this for `permissions`, and refuses
/// `repository_selection: "all"`, but accepts a response that says nothing
/// about repositories). Defence in depth: GitHub's documented 201 response
/// always carries both fields when `repositories` was requested. Note that
/// `github_app::tests::responses_beyond_the_request_are_refused` currently
/// asserts the opposite for its `lower` sample.
#[test]
fn github_app_response_without_repository_scope_is_refused() {
    let requested = vec![RepoId::parse("github.com/acme/web").unwrap()];
    // Control: a response that states its scope is accepted.
    let stated = br#"{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z","permissions":{"contents":"write"},"repository_selection":"selected","repositories":[{"name":"web","full_name":"acme/web","owner":{"login":"acme"}}]}"#;
    assert!(github_app::verify_response(201, stated, &contents_write(), &requested).is_ok());
    let silent: [&[u8]; 2] = [
        br#"{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z","permissions":{"contents":"write"}}"#,
        br#"{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z","permissions":{"contents":"write"},"repository_selection":"selected"}"#,
    ];
    for resp in silent {
        assert!(
            github_app::verify_response(201, resp, &contents_write(), &requested).is_err(),
            "accepted a token whose repository scope is not stated: {}",
            String::from_utf8_lossy(resp)
        );
    }
}

// ---------------------------------------------------------------------
// I7: a credential the broker did not issue never reaches the upstream.
//
// `inspect`/`strip` match a fixed list of exact header and parameter
// names. Backends fold other spellings onto those names: CGI/WSGI/Rack
// style servers expose `x_api_key` and `x-api-key` as the same
// `HTTP_X_API_KEY` (nginx drops underscore headers by default for this
// reason; hyper does not), and PHP turns `.` and spaces in parameter names
// into `_` (`api.key` arrives as `$_GET['api_key']`). The header a
// credential is declared with (`header = "x-example-key"`) is not inspected
// or stripped either; `attach` overwrites it when that credential is bound,
// but a request allowed by another grant on the same host forwards it.
// ---------------------------------------------------------------------

fn session_with(header: &str, host: &str) -> (Sentinels, CanonicalHost) {
    let def = CredentialDef {
        id: "api".into(),
        kind: CredKind::Static { secret: SecretRef::parse("env:X").unwrap() },
        attach: AttachSpec::Header { name: header.into() },
        env: Some("API_KEY".into()),
        swap_body: false,
        hosts: vec![HostPattern::parse(host).unwrap()],
        ttl: None,
        high_risk: false,
    };
    (Sentinels::issue(&[Arc::new(def)]), canon_host(host.as_bytes()).unwrap())
}

/// The planted value is refused, or at least does not survive `strip`.
fn planted_header_blocked(s: &Sentinels, host: &CanonicalHost, name: &'static str) -> bool {
    let mut h = HeaderMap::new();
    h.insert(name, HeaderValue::from_static("sk-ant-api03-attacker-planted"));
    match inspect(&h, None, s, host, None) {
        Err(r) => r.reason == Reason::ForeignCredential,
        Ok(_) => {
            strip(&mut h, None);
            h.get(name).is_none()
        }
    }
}

#[test]
fn i7_underscore_spelling_of_a_credential_header_does_not_reach_the_upstream() {
    let (s, host) = session_with("x-api-key", "api.anthropic.com");
    // Control: the listed spelling is refused today.
    assert!(planted_header_blocked(&s, &host, "x-api-key"));
    for name in ["x_api_key", "x_goog_api_key", "private_token", "x_github_token"] {
        assert!(planted_header_blocked(&s, &host, name), "{name}: a planted key is forwarded untouched");
    }
}

#[test]
fn i7_php_folded_credential_parameter_does_not_reach_the_upstream() {
    let (s, host) = session_with("x-api-key", "api.example.com");
    // Control: the listed spelling is refused today.
    assert!(inspect(&HeaderMap::new(), Some("api_key=attacker"), &s, &host, None).is_err());
    for q in ["api.key=attacker", "access.token=attacker", "api+key=attacker", "client.secret=attacker"] {
        let refused = inspect(&HeaderMap::new(), Some(q), &s, &host, None).is_err();
        let forwarded = strip(&mut HeaderMap::new(), Some(q));
        assert!(refused || forwarded.is_none(), "{q}: forwarded as {forwarded:?}");
    }
}

#[test]
fn i7_the_declared_credential_header_is_inspected() {
    let (s, host) = session_with("x-example-key", "api.example.com");
    // Control: a listed header is refused on the same session.
    assert!(planted_header_blocked(&s, &host, "x-api-key"));
    assert!(
        planted_header_blocked(&s, &host, "x-example-key"),
        "a planted value in the credential's own header passes"
    );
}
