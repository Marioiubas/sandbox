//! I6 lint: only `netguard::resolver` may call a system resolver, and no code
//! may parse hosts with its own URL parser. A second parser is how the
//! sandbox-runtime NUL-byte bypass happened.

use std::path::{Path, PathBuf};

const FORBIDDEN: &[&str] = &["to_socket_addrs", "lookup_host", "getaddrinfo", "host_str(", "url::Url"];

/// Files allowed to contain a forbidden call, with the reason.
const ALLOWED: &[(&str, &str)] = &[
    ("crates/netguard/src/resolver.rs", "the broker resolver: the one sanctioned caller, on canonical names only"),
    (
        "tests/conformance/src/bin/conformance-probe.rs",
        "a probe that tries libc resolution *inside* the sandbox and expects it to fail",
    ),
    ("crates/netguard/tests/lint_single_canonicaliser.rs", "this lint"),
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if name != "target" && !name.starts_with('.') {
                rust_files(&p, out);
            }
        } else if name.ends_with(".rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_second_resolver_or_host_parser() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    rust_files(&root.join("tests"), &mut files);
    assert!(files.len() > 20, "lint found too few files under {}", root.display());
    let mut violations = Vec::new();
    for f in files {
        let rel = f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        if ALLOWED.iter().any(|(p, _)| *p == rel) {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for pat in FORBIDDEN {
                if code.contains(pat) {
                    violations.push(format!("{rel}:{}: `{pat}`", n + 1));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "I6: resolution or host parsing outside netguard::canon/resolver:\n{}",
        violations.join("\n")
    );
}
