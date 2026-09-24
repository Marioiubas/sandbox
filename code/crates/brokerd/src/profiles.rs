//! Built-in agent profiles, compiled into the binary so no writable file can
//! change them (I5). Source: `code/profiles/*.toml`.

use policy::ProfileFile;

pub const BUILTIN: &[(&str, &str)] = &[
    ("default", include_str!("../../../profiles/default.toml")),
    ("claude-code", include_str!("../../../profiles/claude-code.toml")),
    ("claude-code-apikey", include_str!("../../../profiles/claude-code-apikey.toml")),
    ("codex", include_str!("../../../profiles/codex.toml")),
    ("gemini-cli", include_str!("../../../profiles/gemini-cli.toml")),
    ("cursor-agent", include_str!("../../../profiles/cursor-agent.toml")),
];

pub fn by_name(name: &str) -> anyhow::Result<ProfileFile> {
    let (_, text) = BUILTIN
        .iter()
        .find(|(n, _)| *n == name)
        .ok_or_else(|| anyhow::anyhow!("unknown profile {name:?} (built-in: {})", names().join(", ")))?;
    policy::load_profile_str(text)
}

pub fn names() -> Vec<&'static str> {
    BUILTIN.iter().map(|(n, _)| *n).collect()
}

/// Pick the profile whose `binaries` contains the command's basename.
pub fn detect(argv0: &str) -> anyhow::Result<ProfileFile> {
    let base = std::path::Path::new(argv0).file_name().and_then(|b| b.to_str()).unwrap_or(argv0);
    for (name, _) in BUILTIN {
        let p = by_name(name)?;
        if p.binaries.iter().any(|b| b == base) {
            return Ok(p);
        }
    }
    by_name("default")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtins_parse_and_compile() {
        for (n, _) in BUILTIN {
            let p = by_name(n).unwrap();
            assert_eq!(&p.name, n);
            policy::EgressPolicy::compile([("profile", p.egress.as_slice())]).unwrap();
            for c in p.agent.config_readonly.iter().chain(&p.agent.state_write) {
                assert!(c.starts_with("~/") || c.starts_with('/'), "{n}: {c} must be home-relative or absolute");
                assert!(!c.contains(".."), "{n}: {c}");
            }
        }
    }

    #[test]
    fn detection() {
        assert_eq!(detect("/usr/local/bin/claude").unwrap().name, "claude-code");
        assert_eq!(detect("codex").unwrap().name, "codex");
        assert_eq!(detect("bash").unwrap().name, "default");
        assert!(by_name("default").unwrap().egress.is_empty(), "default profile grants nothing");
    }
}
