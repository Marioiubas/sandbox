//! SOCKS5 greeting, RFC 1929 sub-negotiation and request parsers: never
//! panic; consumed lengths never exceed the input.
#![no_main]
use libfuzzer_sys::fuzz_target;
use netguard::ingress::socks5::{Parsed, parse_greeting, parse_request, parse_userpass};

fuzz_target!(|data: &[u8]| {
    if let Parsed::Done(_, n) = parse_greeting(data) {
        assert!(n <= data.len());
    }
    if let Parsed::Done(_, n) = parse_userpass(data) {
        assert!(n <= data.len());
    }
    if let Parsed::Done(r, n) = parse_request(data) {
        assert!(n <= data.len());
        assert!(r.port > 0);
    }
});
