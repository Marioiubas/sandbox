//! Claude Code managed settings (`managed-settings.json`), per the Claude
//! Code settings reference as of 2026-09-24: `sandbox.enabled`,
//! `failIfUnavailable`, `allowUnsandboxedCommands`, `network.allowedDomains`
//! (`host[:port]`, `*.name` = subdomains), `network.deniedDomains` (wins over
//! allows), `network.allowManagedDomainsOnly`, `network.strictAllowlist`
//! (v2.1.219+), `filesystem.denyRead`/`denyWrite` (`~/` = home) and
//! `filesystem.allowManagedReadPathsOnly`. Install it yourself at
//! `/Library/Application Support/ClaudeCode/managed-settings.json` (macOS)
//! or `/etc/claude-code/managed-settings.json` (Linux); the broker never
//! writes system paths.

use super::{Export, Normalized};
use netguard::HostPattern;
use serde_json::json;

pub const MIN_VERSION: &str = "2.1.219";

pub fn export(n: &Normalized) -> Export {
    let mut allowed: Vec<String> = Vec::new();
    for h in &n.hosts {
        let name = match &h.pattern {
            HostPattern::Exact(x) => x.as_str().to_string(), // IPv6 already bracketed
            HostPattern::Subdomains(b) => format!("*.{}", b.as_str()),
        };
        for p in &h.ports {
            allowed.push(format!("{name}:{p}"));
        }
    }
    allowed.sort();
    allowed.dedup();
    let mut denied: Vec<String> = n.ceiling.iter().flat_map(|c| [c.clone(), format!("*.{c}")]).collect();
    denied.sort();
    denied.dedup();
    let v = json!({
        "$schema": "https://json.schemastore.org/claude-code-settings.json",
        "sandbox": {
            "enabled": true,
            "failIfUnavailable": true,
            "allowUnsandboxedCommands": false,
            "network": {
                "allowManagedDomainsOnly": true,
                "strictAllowlist": true,
                "allowedDomains": allowed,
                "deniedDomains": denied,
            },
            "filesystem": {
                "allowManagedReadPathsOnly": true,
                "denyRead": n.deny_read,
                "denyWrite": n.deny_write,
            },
        },
    });
    let mut report = n.report.clone();
    report.push(format!("requires Claude Code {MIN_VERSION} or later (strictAllowlist)"));
    report
        .push("covers Claude Code's sandboxed commands only; run the agent under `broker run` for the boundary".into());
    report.push("proxy chaining not exported: the broker's ingress is per session".into());
    Export { file: format!("{}\n", serde_json::to_string_pretty(&v).expect("json")), report }
}

/// `name[:port]`, with IPv6 names bracketed.
fn split_port(entry: &str) -> (&str, Option<u16>) {
    if let Some(i) = entry.find(']') {
        return (&entry[..=i], entry[i + 1..].strip_prefix(':').and_then(|p| p.parse().ok()));
    }
    match entry.rsplit_once(':') {
        Some((n, p)) => match p.parse::<u16>() {
            Ok(port) => (n, Some(port)),
            Err(_) => (entry, None),
        },
        None => (entry, None),
    }
}

/// Does the exported file admit `host:port` (vendor spelling) for a
/// sandboxed command? The documented matcher: an allow entry (exact, or
/// `*.name` for subdomains, with an optional port) and no deny entry.
pub fn allows(file: &str, host: &str, port: u16) -> bool {
    let v: serde_json::Value = serde_json::from_str(file).expect("exported JSON");
    let list = |k: &str| -> Vec<String> {
        v["sandbox"]["network"][k]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let matches = |entry: &str| {
        let (name, p) = split_port(entry);
        let name_ok = match name.strip_prefix("*.") {
            Some(base) => host.ends_with(&format!(".{base}")),
            None => name == host,
        };
        name_ok && p.is_none_or(|p| p == port)
    };
    list("allowedDomains").iter().any(|e| matches(e)) && !list("deniedDomains").iter().any(|e| matches(e))
}
