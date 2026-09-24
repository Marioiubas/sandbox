//! Generate the Seatbelt (SBPL) profile for one session.
//!
//! Shape: `(deny default)`; read-mostly filesystem with secret paths denied;
//! writes only in the writable roots, with the mandatory deny-write list
//! applied after (the last matching rule wins); a minimal set of Mach
//! services; network only to the session's loopback port. DNS (dnssd),
//! trustd, Launch Services and Apple Events are never reachable, because
//! each is an exfiltration or code-execution path outside the sandbox.
//!
//! Operation names were verified empirically on macOS 26.5 (see the
//! Seatbelt note's build log).

use crate::CompiledFsPolicy;
use std::fmt::Write;
use std::path::{Path, PathBuf};

pub struct SbplInputs<'a> {
    pub fs: &'a CompiledFsPolicy,
    pub broker_port: u16,
    pub tty: Option<&'a Path>,
    pub keychain: bool,
}

/// Mach services every session may reach.
pub const MACH_ALLOW: &[&str] = &[
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.bsd.dirhelper",
    "com.apple.system.logger",
    "com.apple.system.notification_center",
    "com.apple.cfprefsd.agent",
    "com.apple.cfprefsd.daemon",
];

/// Mach services added only for profiles that keep agent credentials in the
/// login keychain until M1 (ADR-016).
pub const MACH_KEYCHAIN: &[&str] = &["com.apple.SecurityServer", "com.apple.securityd.xpc"];

/// Never allowed, listed explicitly for reviewers (deny default covers them).
pub const MACH_NEVER: &[&str] = &[
    "com.apple.dnssd.service",
    "com.apple.trustd",
    "com.apple.trustd.agent",
    "com.apple.coreservices.launchservicesd",
    "com.apple.lsd.mapdb",
];

/// Quote a path for an SBPL string literal. Returns `None` for paths that
/// cannot be represented unambiguously.
pub fn quote(p: &Path) -> Option<String> {
    let s = p.to_str()?;
    if s.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
}

fn path_rules(kind: &str, paths: &[PathBuf]) -> Result<String, String> {
    let mut out = String::new();
    for p in paths {
        let q = quote(p).ok_or_else(|| format!("unrepresentable path {}", p.display()))?;
        // subpath covers the path itself and everything beneath it.
        let _ = write!(out, " ({kind} {q})");
    }
    Ok(out)
}

pub fn generate(i: &SbplInputs) -> Result<String, String> {
    let mut s = String::new();
    s.push_str("(version 1)\n(deny default)\n");
    s.push_str("; processes stay in this sandbox; signals and inspection only within it\n");
    s.push_str("(allow process-exec process-fork)\n");
    s.push_str("(allow signal (target same-sandbox))\n");
    s.push_str("(allow process-info* (target same-sandbox))\n");
    s.push_str("(allow user-preference-read)\n(allow sysctl-read)\n(allow ipc-posix-sem)\n");
    s.push_str("; terminals: ptys created inside, plus the session's own tty\n");
    s.push_str("(allow pseudo-tty)\n");
    s.push_str("(allow file-read* file-write* file-ioctl (literal \"/dev/ptmx\"))\n");
    s.push_str(
        "(allow file-read* file-write* file-ioctl (require-all (regex #\"^/dev/ttys[0-9]+$\") (extension \"com.apple.sandbox.pty\")))\n",
    );
    if let Some(t) = i.tty {
        let q = quote(t).ok_or("unrepresentable tty path")?;
        let _ = writeln!(s, "(allow file-read* file-write* file-ioctl (literal {q}))");
    }
    s.push_str("(allow file-write-data file-ioctl (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/dtracehelper\"))\n");
    s.push_str("; mach services (allowlist)\n(allow mach-lookup");
    for m in MACH_ALLOW.iter().chain(if i.keychain { MACH_KEYCHAIN } else { &[] }) {
        let _ = write!(s, " (global-name \"{m}\")");
    }
    s.push_str(")\n");
    s.push_str("; filesystem: read-mostly, secrets denied (I1)\n(allow file-read*)\n");
    if !i.fs.deny_read.is_empty() {
        let _ = writeln!(s, "(deny file-read*{})", path_rules("subpath", &i.fs.deny_read)?);
    }
    if !i.fs.writable.is_empty() {
        let _ = writeln!(s, "; writable roots\n(allow file-write*{})", path_rules("subpath", &i.fs.writable)?);
    }
    if !i.fs.deny_write.is_empty() {
        let _ = writeln!(
            s,
            "; mandatory deny-write (I5); last match wins\n(deny file-write*{})",
            path_rules("subpath", &i.fs.deny_write)?
        );
    }
    if !i.fs.deny_entry.is_empty() {
        let _ = writeln!(
            s,
            "; entries that may not be renamed or replaced\n(deny file-write*{})",
            path_rules("literal", &i.fs.deny_entry)?
        );
    }
    s.push_str("; network: only the broker's per-session loopback port (TB3)\n");
    let _ = writeln!(s, "(allow network-outbound (remote ip \"localhost:{}\"))", i.broker_port);
    s.push_str("; never reachable (explicit for review)\n(deny mach-lookup");
    for m in MACH_NEVER {
        let _ = write!(s, " (global-name \"{m}\")");
    }
    s.push_str(")\n(deny appleevent-send)\n(deny network-bind network-inbound)\n");
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs() -> CompiledFsPolicy {
        CompiledFsPolicy {
            read_only_root: true,
            writable: vec!["/Users/dev/src/web".into(), "/private/tmp/b-1".into()],
            deny_read: vec!["/Users/dev/.ssh".into()],
            deny_write: vec!["/Users/dev/src/web/.git/hooks".into()],
            deny_entry: vec!["/Users/dev/src/web/.git".into()],
            missing_protected: vec![],
        }
    }

    #[test]
    fn golden_shape() {
        let f = fs();
        let p =
            generate(&SbplInputs { fs: &f, broker_port: 54017, tty: Some(Path::new("/dev/ttys003")), keychain: false })
                .unwrap();
        assert!(p.starts_with("(version 1)\n(deny default)\n"));
        assert!(p.contains("(deny file-read* (subpath \"/Users/dev/.ssh\"))"));
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:54017\"))"));
        assert!(p.contains("(literal \"/dev/ttys003\")"));
        assert!(!p.contains("SecurityServer"));
        assert!(!p.contains("(allow mach-lookup (global-name \"com.apple.dnssd.service\")"));
        // Deny-write must come after the writable allow so it wins.
        let allow = p.find("(allow file-write* (subpath").unwrap();
        let deny = p.find("(deny file-write*").unwrap();
        assert!(deny > allow);
        assert!(p.contains("(deny file-write* (literal \"/Users/dev/src/web/.git\"))"));
        let with_kc = generate(&SbplInputs { fs: &f, broker_port: 1, tty: None, keychain: true }).unwrap();
        assert!(with_kc.contains("com.apple.SecurityServer"));
    }

    #[test]
    fn quoting() {
        assert_eq!(quote(Path::new("/a \"b\"\\c")).unwrap(), "\"/a \\\"b\\\"\\\\c\"");
        assert!(quote(Path::new("/a\nb")).is_none());
        let mut f = fs();
        f.writable.push("/x\n(allow default)".into());
        assert!(generate(&SbplInputs { fs: &f, broker_port: 1, tty: None, keychain: false }).is_err());
    }

    #[test]
    fn only_one_network_allow() {
        let f = fs();
        let p = generate(&SbplInputs { fs: &f, broker_port: 4242, tty: None, keychain: false }).unwrap();
        assert_eq!(p.matches("(allow network").count(), 1);
    }
}
