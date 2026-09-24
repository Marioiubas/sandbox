//! Packfile commit-graph extraction: never panics; bounded by its limits.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = l7::git::pack::Limits { max_objects: 64, max_object: 1 << 20, max_kept: 1 << 20 };
    if let Ok(g) = l7::git::pack::commit_graph(data, &limits) {
        let _ = l7::git::pack::classify(&"1".repeat(40), &"2".repeat(40), Some(&g));
    }
});
