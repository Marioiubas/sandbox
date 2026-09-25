//! Device-flow messages (RFC 8628): the device authorization and token
//! responses never panic; errors carry only a reduced error code; a
//! parsed authorization has an https verification URI and a sane interval.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (status, body) = match data.split_first() {
        Some((s, rest)) => (if *s % 2 == 0 { 200 } else { 400 }, rest),
        None => return,
    };
    if let Ok(a) = grant::device::parse_authorization(status, body) {
        assert!(a.verification_uri.starts_with("https://"));
        assert!((1..=300).contains(&a.interval));
    }
    match grant::device::parse_token_response(status, body) {
        Err(grant::device::DeviceError::Refused(c)) => assert!(c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')),
        Ok(grant::device::Poll::Tokens(t)) => assert!(!t.id_token.is_empty()),
        _ => {}
    }
});
