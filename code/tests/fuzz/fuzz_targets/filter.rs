//! Response filter differential: however the body is chunked, in both
//! hold-back modes nothing at or after a needle's first occurrence is
//! released, and a clean body is released unchanged.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let nlen = 4 + (data[0] as usize % 12);
    let Some(needle) = data.get(1..1 + nlen) else { return };
    let body = &data[1 + nlen..];
    let step = 1 + (data[1] as usize % 7);
    let first = body.windows(needle.len()).position(|w| w == needle);
    for minimal in [false, true] {
        let n = Arc::new(vec![needle.to_vec()]);
        let mut s = if minimal { l7::filter::Scanner::minimal(n) } else { l7::filter::Scanner::new(n) };
        let mut out = Vec::new();
        let mut found = false;
        for chunk in body.chunks(step) {
            match s.feed(chunk) {
                Ok(b) => out.extend(b),
                Err(_) => {
                    found = true;
                    break;
                }
            }
        }
        assert_eq!(found, first.is_some());
        if let Some(i) = first {
            assert!(out.len() <= i, "released past the needle");
        } else {
            out.extend(s.finish());
            assert_eq!(out, body);
        }
    }
});
