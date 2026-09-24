//! Native config exporters: golden files per shipped profile and target
//! (a vendor schema change or a policy change shows up as a diff; run with
//! `BLESS=1` to regenerate after reviewing it), and each file parses.

use conformance::*;
use std::path::PathBuf;
use std::process::Command;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../golden/exporters")
}

fn profiles() -> Vec<String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../profiles");
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".toml").map(str::to_string))
        .collect();
    v.sort();
    v
}

#[test]
fn exports_match_the_golden_files() {
    let h = Harness::new("version = 1\n");
    let bless = std::env::var_os("BLESS").is_some();
    std::fs::create_dir_all(golden_dir()).unwrap();
    for p in profiles() {
        for (target, ext) in [("claude-code", "managed-settings.json"), ("codex", "requirements.toml")] {
            let out = Command::new(&h.bins.broker)
                .args(["policy", "export", "--target", target, "--profile", &p])
                .env("BROKER_HOME", h.home.path())
                .output()
                .unwrap();
            assert!(out.status.success(), "{p}/{target}: {}", String::from_utf8_lossy(&out.stderr));
            let text = String::from_utf8(out.stdout).unwrap();
            match target {
                "claude-code" => {
                    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
                    assert_eq!(v["sandbox"]["failIfUnavailable"], true);
                    assert_eq!(v["sandbox"]["allowUnsandboxedCommands"], false);
                }
                _ => {
                    let v: toml::Value = toml::from_str(&text).unwrap();
                    assert_eq!(v["experimental_network"]["managed_allowed_domains_only"].as_bool(), Some(true));
                }
            }
            let report = String::from_utf8_lossy(&out.stderr);
            assert!(report.contains("export: "), "{report}");
            let golden = golden_dir().join(format!("{p}.{ext}"));
            if bless {
                std::fs::write(&golden, &text).unwrap();
                continue;
            }
            let want = std::fs::read_to_string(&golden)
                .unwrap_or_else(|_| panic!("missing {}; run with BLESS=1", golden.display()));
            assert_eq!(text, want, "{p}/{target} differs from {}; review, then BLESS=1", golden.display());
        }
    }
}

#[test]
fn unknown_targets_and_profiles_are_refused() {
    let h = Harness::new("version = 1\n");
    for args in [["--target", "cursor", "--profile", "claude-code"], ["--target", "codex", "--profile", "nope"]] {
        let out = Command::new(&h.bins.broker)
            .args(["policy", "export"])
            .args(args)
            .env("BROKER_HOME", h.home.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(125), "{args:?}");
    }
}
