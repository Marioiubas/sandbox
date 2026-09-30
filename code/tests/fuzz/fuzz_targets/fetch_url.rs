//! The daemon's own fetch URLs (OIDC discovery and device flow;
//! brokerd::fetch::Target::parse): never panics; an accepted URL has a
//! canonical host (a fixed point) and a path of visible ASCII; same-origin
//! is reflexive and symmetric.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (a, b) = text.split_once('\n').unwrap_or((text, "https://example.com/"));
    let Ok(t) = brokerd::fetch::Target::parse(a) else { return };
    assert_eq!(netguard::canon_host(t.host.as_str().as_bytes()).as_ref(), Ok(&t.host));
    assert!(t.path.bytes().all(|c| c.is_ascii_graphic()));
    assert!(t.port != 0);
    assert!(t.same_origin(&t));
    if let Ok(u) = brokerd::fetch::Target::parse(b) {
        assert_eq!(t.same_origin(&u), u.same_origin(&t));
    }
});
