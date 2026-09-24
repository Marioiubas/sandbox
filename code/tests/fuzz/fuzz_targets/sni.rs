//! ClientHello SNI peek: never panics, and a longer buffer never changes a
//! completed answer (prefix stability).
#![no_main]
use libfuzzer_sys::fuzz_target;
use tls::sni_peek::{Peek, peek};

fuzz_target!(|data: &[u8]| {
    let full = peek(data);
    if let Peek::Hello { .. } = &full {
        let mut longer = data.to_vec();
        longer.extend_from_slice(b"trailing application data");
        assert_eq!(peek(&longer), full);
    }
});
