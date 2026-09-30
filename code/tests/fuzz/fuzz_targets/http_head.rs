//! The L7 request-head check (l7::head::check): never panics; an accepted
//! head yields a canonical path that is a fixed point, and a head carrying a
//! method-override header is never accepted.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let mut lines = text.split('\n');
    let Some(first) = lines.next() else { return };
    let (method, uri) = first.split_once(' ').unwrap_or(("GET", first));
    let mut b = http::Request::builder().method(method).uri(uri);
    let mut override_header = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim();
            override_header |= ["x-http-method-override", "x-http-method", "x-method-override"]
                .iter()
                .any(|o| k.eq_ignore_ascii_case(o));
            b = b.header(k, v.trim());
        }
    }
    let Ok(req) = b.body(()) else { return };
    let (parts, ()) = req.into_parts();
    let host = netguard::canon_host(b"api.example.com").unwrap();
    if let Ok(p) = l7::head::check(&parts, &host, 443) {
        assert!(!override_header, "a method-override header was accepted");
        let again = netguard::canon::canon_path(p.path().as_bytes()).expect("an accepted path re-canonicalises");
        assert_eq!(again.path(), p.path());
    }
});
