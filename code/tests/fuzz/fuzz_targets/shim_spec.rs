//! The shim's command line (`--spec <b64> -- <argv...>`): never panics, and
//! a spec that decodes re-encodes to an equal spec.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::ffi::OsString;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(spec) = launcher::shim::ShimSpec::decode(s)
    {
        assert_eq!(spec.v, 1);
        assert_eq!(launcher::shim::ShimSpec::decode(&spec.encode()).unwrap(), spec);
    }
    let args: Vec<OsString> = data
        .split(|b| *b == 0)
        .map(|a| {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::OsStr::from_bytes(a).to_os_string()
        })
        .collect();
    if let Ok((_, argv)) = launcher::shim::parse_args(&args) {
        assert!(!argv.is_empty());
    }
});
