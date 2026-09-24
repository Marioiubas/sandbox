use super::*;
use proptest::prelude::*;

fn label() -> impl Strategy<Value = String> {
    "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// canon(canon(x)) == canon(x) for arbitrary bytes.
    #[test]
    fn idempotent_on_arbitrary_bytes(raw in proptest::collection::vec(any::<u8>(), 0..80)) {
        if let Ok(h) = canon_host(&raw) {
            prop_assert_eq!(canon_host(h.as_str().as_bytes()), Ok(h));
        }
    }

    /// Accepted names contain only LDH bytes and dots; never a forbidden byte.
    #[test]
    fn accepted_output_is_ldh(raw in proptest::collection::vec(any::<u8>(), 0..80)) {
        if let Ok(h) = canon_host(&raw) {
            let s = h.as_str();
            if let HostKind::Name { .. } = h.kind() {
                prop_assert!(s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'));
            }
            prop_assert!(!s.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n' || b == b'%' || b == b'@'));
        }
    }

    /// Hostile structure: a valid name with a forbidden byte spliced in is
    /// always rejected.
    #[test]
    fn spliced_forbidden_byte_rejected(a in label(), b in label(), pos in 0usize..20,
                                       bad in prop::sample::select(vec![0u8, b'\r', b'\n', b'%', b'@', b'/', b'\\', b' ', b'#', b'?', b':'])) {
        let mut v = format!("{a}.{b}.com").into_bytes();
        let at = pos % (v.len() + 1);
        v.insert(at, bad);
        prop_assert!(canon_host(&v).is_err());
    }

    /// Wildcard patterns match only at label boundaries.
    #[test]
    fn wildcard_label_boundary(sub in label(), base in label(), glue in label()) {
        // Generated labels can accidentally form `xn--` A-labels, which
        // must be valid punycode; those are covered by the IDNA tests.
        prop_assume!(![&sub, &base, &format!("{glue}{base}")].iter().any(|l| l.starts_with("xn--")));
        let base_name = format!("{base}.example");
        let p = HostPattern::parse(&format!("*.{base_name}")).unwrap();
        let child = canon_host(format!("{sub}.{base_name}").as_bytes()).unwrap();
        prop_assert!(p.matches(&child));
        let glued = canon_host(format!("{glue}{base_name}").as_bytes()).unwrap();
        prop_assert!(!p.matches(&glued));
        let same = canon_host(base_name.as_bytes()).unwrap();
        prop_assert!(!p.matches(&same));
    }

    /// Compile-time (pattern) and runtime canonicalisation agree under case changes.
    #[test]
    fn pattern_and_runtime_agree(a in label(), b in label(), upper in any::<bool>()) {
        prop_assume!(!a.starts_with("xn--") && !b.starts_with("xn--"));
        let name = format!("{a}.{b}.example");
        let written = if upper { name.to_uppercase() } else { name.clone() };
        let p = HostPattern::parse(&written).unwrap();
        prop_assert!(p.matches(&canon_host(name.to_uppercase().as_bytes()).unwrap()));
    }

    /// Paths: accepted output never contains dot segments or encoded separators.
    #[test]
    fn path_output_is_safe(raw in proptest::collection::vec(any::<u8>(), 0..60)) {
        let mut v = vec![b'/'];
        v.extend(raw);
        if let Ok(p) = canon_path(&v) {
            prop_assert!(!p.path().split('/').any(|s| s == "." || s == ".."));
            let lower = p.path().to_ascii_lowercase();
            prop_assert!(!lower.contains("%2f") && !lower.contains("%5c") && !lower.contains("%00") && !lower.contains("%2e"));
            prop_assert_eq!(canon_path(p.path().as_bytes()).map(|x| x.path().to_string()), Ok(p.path().to_string()));
        }
    }
}
