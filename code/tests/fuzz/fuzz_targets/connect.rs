//! HTTP CONNECT head parser: never panics; the authority it returns splits
//! back into the same host and port.
#![no_main]
use libfuzzer_sys::fuzz_target;
use netguard::ingress::connect::{ParseOutcome, parse, split_authority};

fuzz_target!(|data: &[u8]| {
    if let ParseOutcome::Done(r) = parse(data) {
        assert!(r.port > 0);
        let mut auth = r.host.clone();
        auth.extend_from_slice(format!(":{}", r.port).as_bytes());
        let (h, p) = split_authority(&auth).expect("re-split");
        assert_eq!((h, p), (r.host.as_slice(), r.port));
    }
});
