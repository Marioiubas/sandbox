//! Repository identity from remote URLs and policy text: never panics, and
//! what parses re-parses to the same identity.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Some(r) = policy::RepoId::from_remote_url(s) {
        assert_eq!(policy::RepoId::parse(&r.to_string()), Some(r));
    }
    let _ = policy::repo::RepoPattern::parse(s, None);
    let _ = policy::repo::RefPattern::parse(s);
    let _ = policy::glob::PathPattern::parse(s);
});
