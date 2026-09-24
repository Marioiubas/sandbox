//! Response filter differential: however the body is chunked, a needle is
//! never released, and a clean body is released unchanged.
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
    let mut s = l7::filter::Scanner::new(Arc::new(vec![needle.to_vec()]));
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
    let contains = body.windows(needle.len()).any(|w| w == needle);
    assert_eq!(found, contains);
    assert!(!out.windows(needle.len()).any(|w| w == needle));
    if !found {
        out.extend(s.finish());
        assert_eq!(out, body);
    }
});
