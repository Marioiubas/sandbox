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
            for c in p.agent.config_readonly.iter().chain(&p.agent.state_write).chain(&p.agent.state_private) {
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

    /// The claude-code profile's filesystem as `launch` compiles it, for a
    /// session in `<home>/src/web`.
    fn claude_code_fs(home: &std::path::Path, tmp: &std::path::Path) -> launcher::fs_compile::CompiledFsPolicy {
        let repo = home.join("src/web");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(tmp).unwrap();
        let p = by_name("claude-code").unwrap();
        let dir = |s: &String| {
            let d = crate::session_util::expand_profile_path(s, home, &repo);
            std::fs::create_dir_all(&d).unwrap();
            d
        };
        let private: Vec<_> = p.agent.state_private.iter().map(dir).collect();
        let mut extra_write: Vec<_> = p.agent.state_write.iter().filter(|s| s.starts_with("~/")).map(dir).collect();
        extra_write.extend(private.iter().cloned());
        launcher::fs_compile::compile(&launcher::fs_compile::FsInputs {
            home: home.to_path_buf(),
            repo,
            session_tmp: tmp.to_path_buf(),
            extra_write,
            create_only: private,
            agent_config_readonly: p
                .agent
                .config_readonly
                .iter()
                .map(|c| crate::session_util::expand_home(c, home))
                .collect(),
            ..Default::default()
        })
        .unwrap()
    }

    /// Review (I5: "shell rc files" are authority-bearing): Claude Code runs
    /// every Bash tool command as `zsh -c 'source
    /// ~/.claude/shell-snapshots/snapshot-zsh-<ts>-<id>.sh ... && eval
    /// <cmd>'` (seen in the process table of Claude Code 2.1.288 on this
    /// host). The claude-code profile makes all of `~/.claude/shell-snapshots`
    /// writable, so a sandboxed agent can append to the snapshot of any other
    /// Claude Code session on the machine, including an unsandboxed one, whose
    /// next Bash command then runs that code outside every sandbox.
    #[test]
    fn review_claude_code_cannot_write_other_sessions_shell_snapshots() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let home = root.join("home");
        let fs = claude_code_fs(&home, &root.join("tmp/s1"));
        let other = home.join(".claude/shell-snapshots/snapshot-zsh-1791308291639-u1jij1.sh");
        std::fs::write(&other, "# another session's snapshot\n").unwrap();
        assert!(
            !fs.is_writable(&other),
            "{} is writable from the sandbox; Claude Code sources it before every Bash command of the session \
             that owns it",
            other.display()
        );
    }

    /// Review (I5: agent configuration; the profile already protects
    /// `~/.claude/CLAUDE.md`): Claude Code loads
    /// `~/.claude/projects/<project-slug>/memory/MEMORY.md` as instructions
    /// at session start (auto memory; the directories exist on this host).
    /// The profile grants all of `~/.claude/projects`, so a session in one
    /// project can plant standing instructions in every other project's
    /// memory, including projects the user runs without the broker. The
    /// profile scopes `/tmp/claude-${uid}/${cwd_slug}` to this project for
    /// the same reason; `~/.claude/projects` is not.
    #[test]
    fn review_claude_code_cannot_write_other_projects_memory() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let home = root.join("home");
        let fs = claude_code_fs(&home, &root.join("tmp/s1"));
        let other = home.join(".claude/projects/-Users-dev-src-payments/memory/MEMORY.md");
        assert!(
            !fs.is_writable(&other),
            "{} (another project's standing instructions) is writable from a session in src/web",
            other.display()
        );
    }
}
