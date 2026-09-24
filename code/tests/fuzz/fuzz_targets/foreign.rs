//! Client-credential inspection: never panics; after `strip` no credential
//! header survives, whatever was sent.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut h = http::HeaderMap::new();
    let mut parts = data.split(|b| *b == b'\n');
    let query = parts.next().and_then(|q| std::str::from_utf8(q).ok());
    for line in parts {
        let mut kv = line.splitn(2, |b| *b == b':');
        let (Some(k), Some(v)) = (kv.next(), kv.next()) else { continue };
        if let (Ok(k), Ok(v)) = (http::HeaderName::from_bytes(k), http::HeaderValue::from_bytes(v)) {
            h.append(k, v);
        }
    }
    let sentinels = creds::Sentinels::issue(&[]);
    let dest = netguard::canon_host(b"api.example.com").unwrap();
    // No sentinel exists, so any credential present must be rejected.
    if creds::inspect(&h, query, &sentinels, &dest, None).is_ok() {
        for n in creds::foreign::CREDENTIAL_HEADERS {
            for v in h.get_all(*n) {
                assert!(v.as_bytes().iter().all(|b| b.is_ascii_whitespace()), "{n} accepted");
            }
        }
    }
    let q = creds::strip(&mut h, query);
    for n in creds::foreign::CREDENTIAL_HEADERS {
        assert!(h.get(*n).is_none());
    }
    if let Some(q) = q {
        assert!(creds::inspect(&http::HeaderMap::new(), Some(&q), &sentinels, &dest, None).is_ok());
    }
});
