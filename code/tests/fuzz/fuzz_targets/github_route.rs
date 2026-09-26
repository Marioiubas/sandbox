//! The GitHub API route table: never panics; a mapped route is a known verb,
//! and only GET/HEAD map to read verbs.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (method, path) = s.split_once(' ').unwrap_or(("GET", s));
    for host in [&b"api.github.com"[..], b"ghe.corp.example"] {
        let h = netguard::canon_host(host).unwrap();
        let (path, query) = path.split_once('?').map_or((path, None), |(p, q)| (p, Some(q)));
        if let Ok(r) = l7::github::route(&h, method, path, query) {
            assert!(!(r.public && r.restricted));
            assert!(policy::github::is_verb(r.verb));
            if policy::github::is_read_verb(r.verb) {
                assert!(matches!(method, "GET" | "HEAD"));
            }
            assert_eq!(policy::github::is_repo_verb(r.verb), r.repo.is_some());
        }
    }
});
