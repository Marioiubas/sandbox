//! The S3 adapter: never panics on any request line or header; a mapped
//! request is a known operation on a valid bucket, reads only on GET/HEAD,
//! and its canonical target is what SigV4 signs (plain visible ASCII).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (method, target) = s.split_once(' ').unwrap_or(("GET", s));
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    for host in [&b"acme-data.s3.us-east-1.amazonaws.com"[..], b"s3.eu-west-1.amazonaws.com"] {
        let h = netguard::canon_host(host).unwrap();
        if let Ok(r) = l7::s3::route(&h, method, path, query) {
            assert!(policy::s3::is_op(r.op));
            assert!(policy::s3::bucket_ok(&r.bucket));
            if matches!(r.op, "s3.get" | "s3.list") {
                assert!(matches!(method, "GET" | "HEAD"));
            }
            let signed = format!("{}?{}", r.canonical_uri, r.canonical_query);
            assert!(signed.bytes().all(|b| b.is_ascii_graphic()));
        }
    }
    let mut headers = http::HeaderMap::new();
    if let (Ok(n), Ok(v)) = (http::HeaderName::from_bytes(method.as_bytes()), http::HeaderValue::from_bytes(target.as_bytes())) {
        headers.insert(n, v);
        let _ = l7::s3::check_headers(&headers);
    }
});
