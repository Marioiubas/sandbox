//! Git smart-HTTP routing and classification (l7::git::route, actions,
//! upload_pack_reads_pull_refs): never panics; RPC routes only for POST;
//! a route's repository round-trips through RepoId::parse.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (head, body) = text.split_once('\n').unwrap_or((text, ""));
    let mut it = head.splitn(3, ' ');
    let (Some(method), Some(path)) = (it.next(), it.next()) else { return };
    let query = it.next();
    let host = netguard::canon_host(b"github.com").unwrap();
    let _ = l7::git::upload_pack_reads_pull_refs(body.as_bytes());
    let Some(r) = l7::git::route(&host, 443, method, path, query) else { return };
    let repo = match &r {
        l7::git::Route::InfoRefs { repo, .. } => {
            assert_eq!(method, "GET");
            repo
        }
        l7::git::Route::Rpc { repo, .. } => {
            assert_eq!(method, "POST");
            repo
        }
    };
    assert_eq!(policy::RepoId::parse(&repo.to_string()).as_ref(), Some(repo));
    let _ = l7::git::actions(&r, Some(body.as_bytes()));
});
