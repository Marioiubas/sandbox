//! Category 8 differential (generated inputs): a path the canonicaliser
//! accepts under `/allowed/` stays under it after the normalisations
//! lenient servers apply: zero to two rounds of percent-decoding, `\` as
//! `/`, `;params` dropped, overlong and full-width dots as `.`, empty and
//! dot segments resolved. (The fixed-list version is conformance
//! `m4_differential`.)
#![no_main]
use libfuzzer_sys::fuzz_target;

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

fn decode(p: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < p.len() {
        match (p[i], p.get(i + 1).copied().and_then(hex), p.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h << 4) | l);
                i += 3;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn server_view(path: &str, decodes: usize) -> String {
    let mut b = path.as_bytes().to_vec();
    for _ in 0..decodes {
        b = decode(&b);
    }
    let s = String::from_utf8_lossy(&b)
        .replace("\u{FFFD}\u{FFFD}", ".")
        .replace(['\u{FF0E}', '\u{FE52}', '\u{2024}'], ".")
        .replace(['\\', '\u{FF0F}', '\u{FF3C}', '\u{2215}', '\u{2216}', '\u{2044}', '\u{FE68}', '\u{29F5}'], "/");
    let mut out: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg.split(';').next().unwrap_or("") {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            x => out.push(x),
        }
    }
    format!("/{}", out.join("/"))
}

fuzz_target!(|data: &[u8]| {
    let mut raw = b"/allowed/".to_vec();
    raw.extend_from_slice(data);
    if let Ok(p) = netguard::canon_path(&raw) {
        if !p.path().starts_with("/allowed/") {
            return;
        }
        for decodes in 0..=2 {
            let v = server_view(p.path(), decodes);
            assert!(v == "/allowed" || v.starts_with("/allowed/"), "{:?} -> {v:?} after {decodes}", p.path());
        }
    }
});
