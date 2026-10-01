//! Sentinel check and body swap: only the exact sentinel is honoured, and
//! after a swap no sentinel survives and every occurrence was counted.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::{Arc, LazyLock};

static SENTINELS: LazyLock<creds::Sentinels> = LazyLock::new(|| {
    let def = policy::CredentialDef {
        id: "a".into(),
        kind: policy::CredKind::Static { secret: policy::SecretRef::parse("env:X").unwrap() },
        attach: policy::AttachSpec::Bearer,
        env: Some("A".into()),
        swap_body: true,
        hosts: vec![netguard::HostPattern::parse("api.example.com").unwrap()],
        ttl: None,
        high_risk: false,
    };
    creds::Sentinels::issue(&[Arc::new(def)])
});

fuzz_target!(|data: &[u8]| {
    let s = &*SENTINELS;
    let sentinel = s.value_for("a").unwrap().as_bytes();
    let dest = netguard::canon_host(b"api.example.com").unwrap();
    // Only the exact sentinel is honoured (libFuzzer's comparison tracing
    // can learn it: it is fixed for the life of this process).
    let want =
        if data == sentinel { creds::SentinelCheck::Valid("a".into()) } else { creds::SentinelCheck::NotSentinel };
    assert_eq!(s.check(data, &dest), want);
    // Splice the sentinel between the fragments the input names (0xFF).
    let frags: Vec<&[u8]> = data.split(|b| *b == 0xFF).collect();
    let body = frags.join(sentinel);
    let (out, n) = s.swap_in_body(&body, "a", b"SECRET");
    // A sentinel (`brk_s_` + hex) cannot overlap itself, so its occurrences
    // are unambiguous; the fragments may contain some too.
    let occurrences = body.windows(sentinel.len()).filter(|w| *w == sentinel).count();
    assert!(n >= frags.len() - 1);
    assert_eq!(n, occurrences, "every occurrence counted");
    assert!(s.find_any(&out).is_none(), "no sentinel survives the swap");
    if n == 0 {
        assert_eq!(out, body);
    }
    assert_eq!(s.check(sentinel, &dest), creds::SentinelCheck::Valid("a".into()));
    let mut near = sentinel.to_vec();
    near.extend_from_slice(data);
    if !data.is_empty() {
        assert_eq!(s.check(&near, &dest), creds::SentinelCheck::NotSentinel, "a prefix match is not a match");
    }
});
