//! Git delta application: never panics, never exceeds the declared size.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.first().copied().unwrap_or(0) as usize;
    let rest = data.get(1..).unwrap_or(&[]);
    let (base, delta) = rest.split_at(split.min(rest.len()));
    let limits = l7::git::pack::Limits { max_objects: 1, max_object: 1 << 20, max_kept: 1 << 20 };
    if let Ok(out) = l7::git::pack::apply_delta(base, delta, &limits) {
        assert!(out.len() <= limits.max_object);
    }
});
