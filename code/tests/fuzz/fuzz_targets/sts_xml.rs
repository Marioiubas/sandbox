//! AWS STS AssumeRole responses (creds::issuers::aws_sts::parse_response):
//! never panics, whatever the status; an accepted session has a key ID of
//! visible ASCII.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (status, body) = match data.split_first() {
        Some((0, b)) => (200, b),
        Some((_, b)) => (403, b),
        None => return,
    };
    if let Ok(s) = creds::issuers::aws_sts::parse_response(status, body) {
        assert!(!s.access_key_id.is_empty());
        assert!(s.access_key_id.bytes().all(|b| b.is_ascii_graphic()));
    }
});
