//! Native config exporters (Native Config Exporters): the policy of one
//! profile compiled into vendor-native files as defence in depth. The broker
//! stays the enforcement point: an exported file only narrows, is never read
//! back, and holds no secret. Whatever a target cannot express is listed in
//! the export report (dropped permits, approximations), never widened.

pub mod claude;
pub mod codex;
#[cfg(test)]
mod tests;

use crate::cedar::categories::{PASTE_NAMES, TUNNEL_NAMES};
use crate::doh::DOH_NAMES;
use crate::egress::EgressPolicy;
use netguard::{CanonicalHost, HostPattern};
use std::collections::BTreeSet;

/// One host the broker admits, with the ports it admits it on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRule {
    pub grant: String,
    pub pattern: HostPattern,
    pub ports: Vec<u16>,
}

/// The normalised intermediate form every exporter consumes.
#[derive(Clone, Debug, Default)]
pub struct Normalized {
    pub hosts: Vec<HostRule>,
    /// Names the org ceiling denies, with all their subdomains.
    pub ceiling: Vec<String>,
    /// `~/`-relative or absolute paths.
    pub deny_read: Vec<String>,
    pub deny_write: Vec<String>,
    /// What the broker enforces that no target expresses.
    pub report: Vec<String>,
}

/// A generated file and its export report.
#[derive(Clone, Debug)]
pub struct Export {
    pub file: String,
    pub report: Vec<String>,
}

/// Is every subdomain of `base` (and `base` itself) in a ceiling category?
fn under_ceiling(base: &CanonicalHost) -> bool {
    let h = base.as_str();
    PASTE_NAMES.iter().chain(TUNNEL_NAMES).chain(DOH_NAMES).any(|n| h == *n || h.ends_with(&format!(".{n}")))
}

impl Normalized {
    /// From the compiled policy (enforce mode) and the filesystem lists the
    /// launcher applies. A host is kept only on the ports the Cedar policy
    /// admits it; wildcard grants under a ceiling name are dropped.
    pub fn from_policy(p: &EgressPolicy, deny_read: &[String], deny_write: &[String]) -> Normalized {
        let mut n = Normalized {
            deny_read: dedup(deny_read),
            deny_write: dedup(deny_write),
            ceiling: dedup(
                &PASTE_NAMES.iter().chain(TUNNEL_NAMES).chain(DOH_NAMES).map(|s| s.to_string()).collect::<Vec<_>>(),
            ),
            ..Default::default()
        };
        for g in p.grants() {
            let ports: Vec<u16> = match &g.pattern {
                HostPattern::Exact(h) => {
                    g.ports.iter().copied().filter(|port| p.admit_host(h, *port).is_ok()).collect()
                }
                HostPattern::Subdomains(b) if under_ceiling(b) => vec![],
                HostPattern::Subdomains(_) => g.ports.clone(),
            };
            if ports.is_empty() {
                n.report.push(format!("{}: dropped (the org ceiling or the DoH block denies it)", g.id));
                continue;
            }
            if g.l7.is_some() {
                n.report.push(format!(
                    "{}: exported at domain level; its method, path and git rules are enforced by the broker only",
                    g.id
                ));
            }
            if let Some(c) = g.l7.as_ref().and_then(|r| r.credential.as_ref()) {
                n.report.push(format!("{}: credential {} stays in the broker (never exported)", g.id, c.id));
            }
            if !g.allow_classes.is_empty() || !g.pinned.is_empty() {
                n.report
                    .push(format!("{}: address classes and pinned addresses are enforced by the broker only", g.id));
            }
            n.hosts.push(HostRule { grant: g.id.clone(), pattern: g.pattern.clone(), ports });
        }
        n
    }
}

fn dedup(v: &[String]) -> Vec<String> {
    v.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect()
}
