//! canon_host / canon_path: never panic; accepted output is a fixed point
//! and never contains a forbidden byte.
#![no_main]
use libfuzzer_sys::fuzz_target;
use netguard::canon::{HostKind, canon_host, canon_path};

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = canon_host(data) {
        assert_eq!(canon_host(h.as_str().as_bytes()).as_ref(), Ok(&h), "not idempotent");
        if let HostKind::Name { .. } = h.kind() {
            assert!(h.as_str().bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'));
        }
    }
    if let Ok(p) = canon_path(data) {
        assert!(!p.path().split('/').any(|s| s == "." || s == ".."));
        assert_eq!(canon_path(p.path().as_bytes()).map(|x| x.path().to_string()), Ok(p.path().to_string()));
    }
});
