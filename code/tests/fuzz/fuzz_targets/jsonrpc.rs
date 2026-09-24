//! ctl.sock request parsing: never panics on arbitrary bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = serde_json::from_slice::<brokerd::proto::Request>(data) {
        let _ = serde_json::from_value::<brokerd::proto::StartParams>(req.params);
    }
});
