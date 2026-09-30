//! GitHub App installation-token responses (creds::issuers::github_app::
//! verify_response): never panics; an accepted response never grants more
//! than was requested (the function refuses wider scope) and its token is
//! visible ASCII.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

fuzz_target!(|data: &[u8]| {
    let mut perms = BTreeMap::new();
    perms.insert("contents".to_string(), "read".to_string());
    let repos = vec![policy::RepoId::parse("github.com/acme/web").unwrap()];
    if let Ok((secret, _exp)) = creds::issuers::github_app::verify_response(201, data, &perms, &repos) {
        assert!(secret.expose().iter().all(|b| b.is_ascii_graphic()));
        // Parse again the way GitHub's JSON would be read: the scope checks
        // passed, so any listed permission is within the request.
        let v: serde_json::Value = serde_json::from_slice(data).unwrap();
        if let Some(p) = v.get("permissions").and_then(|p| p.as_object()) {
            for (k, level) in p {
                assert!(k == "metadata" || k == "contents", "unrequested permission {k} accepted");
                assert!(level.as_str() == Some("read"), "wider level {level} accepted");
            }
        }
    }
});
