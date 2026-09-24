//! MCP stdio framing and manifests: arbitrary bytes in arbitrary chunks
//! never panic, frames never exceed the bound, chunking never changes the
//! frames, and any JSON array's manifest is order-independent.
#![no_main]
use libfuzzer_sys::fuzz_target;
use mcpguard::frame::{Frame, Lines, MAX_FRAME, classify};

fuzz_target!(|data: &[u8]| {
    let (cut, bytes) = match data.split_first() {
        Some((c, rest)) => (*c as usize, rest),
        None => return,
    };
    let whole = {
        let mut l = Lines::default();
        let mut f = l.push(bytes);
        f.extend(l.finish());
        f
    };
    let chunked = {
        let mut l = Lines::default();
        let at = cut.min(bytes.len());
        let mut f = l.push(&bytes[..at]);
        f.extend(l.push(&bytes[at..]));
        f.extend(l.finish());
        f
    };
    assert_eq!(whole, chunked);
    for f in &whole {
        if let Frame::Line(b) = f {
            assert!(b.len() <= MAX_FRAME);
            let _ = classify(b);
            if let Ok(serde_json::Value::Array(tools)) = serde_json::from_slice(b)
                && let Ok(m) = mcpguard::manifest::manifest(tools.clone())
            {
                let mut rev = tools;
                rev.reverse();
                assert_eq!(mcpguard::manifest::manifest(rev).map(|r| r.sha256), Ok(m.sha256));
            }
        }
    }
});
