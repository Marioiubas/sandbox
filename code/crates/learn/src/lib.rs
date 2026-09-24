//! learn: the deterministic half of the Policy Learning Loop.
//!
//! record (`broker learn`, audit rows) → [`observe`] (P2 exclusions) →
//! [`generalise`] (G1-G10, P1 support) → a `broker.toml` diff whose
//! high-risk rules are commented out for review (G7) → [`replay`] of every
//! recorded request under the current and the candidate policy. Nothing is
//! applied automatically, and no model sits on this path (I3).

pub mod generalise;
pub mod observe;
pub mod templatize;

use audit::{AuditEvent, Reason};
use generalise::{Mined, Options, Proposal};
use observe::{Corpus, What};
use policy::config::EgressEntry;
use policy::{CompileEnv, EgressPolicy};
use std::fmt::Write;

pub struct Suggestion {
    pub corpus: Corpus,
    pub mined: Mined,
    pub options: Options,
}

pub fn suggest(events: &[AuditEvent], options: Options) -> Suggestion {
    let corpus = observe::corpus(events);
    let mined = generalise::mine(&corpus, &options);
    Suggestion { corpus, mined, options }
}

fn toml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn toml_list(v: &[String]) -> String {
    format!("[{}]", v.iter().map(|s| toml_str(s)).collect::<Vec<_>>().join(", "))
}

fn entry_toml(id: &str, e: &EgressEntry) -> String {
    let mut t = format!("[[egress]]\nid = {}\nhost = {}\n", toml_str(id), toml_str(&e.host));
    if let Some(p) = &e.ports {
        let _ = writeln!(t, "ports = [{}]", p.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "));
    }
    if let Some(p) = &e.protocol {
        let _ = writeln!(t, "protocol = {}", toml_str(p));
    }
    if let Some(m) = &e.methods {
        let _ = writeln!(t, "methods = {}", toml_list(m));
    }
    if let Some(p) = &e.paths {
        let _ = writeln!(t, "paths = {}", toml_list(p));
    }
    if let Some(a) = &e.allow {
        let pushes: Vec<String> = a
            .push
            .iter()
            .map(|r| format!("{{ repo = {}, refs = {}, force = {} }}", toml_str(&r.repo), toml_list(&r.refs), r.force))
            .collect();
        let _ = writeln!(t, "allow = {{ fetch = {}, push = [{}] }}", toml_list(&a.fetch), pushes.join(", "));
    }
    t
}

impl Suggestion {
    pub fn active(&self) -> Vec<&Proposal> {
        self.mined.proposals.iter().filter(|p| !p.needs_review()).collect()
    }

    /// Active proposals as entries (for replay and for the diff).
    pub fn active_entries(&self) -> Vec<EgressEntry> {
        self.active()
            .iter()
            .enumerate()
            .map(|(i, p)| EgressEntry { id: Some(format!("learned-{}", i + 1)), ..p.entry.clone() })
            .collect()
    }

    /// The proposed `broker.toml` additions. High-risk rules are present but
    /// commented out: a human must decide (G7).
    pub fn render_toml(&self) -> String {
        let used =
            self.corpus.sessions.values().filter(|s| s.record && !self.corpus.excluded.contains_key(&s.id)).count();
        let mut t = format!(
            "# broker suggest: proposed additions to broker.toml (review before merging).\n\
             # {} record-mode sessions used, {} excluded; minimum support {} sessions (P1).\n\
             # Nothing here is applied automatically. High-risk rules are commented out.\n\n",
            used,
            self.corpus.excluded.len(),
            self.options.min_runs
        );
        let mut n = 0;
        for p in self.mined.proposals.iter().filter(|p| !p.needs_review()) {
            n += 1;
            let _ = writeln!(
                t,
                "# evidence: {} requests in {} sessions; risk {} ({}); e.g. {}",
                p.requests,
                p.sessions.len(),
                p.risk.as_str(),
                p.note,
                p.example
            );
            t.push_str(&entry_toml(&format!("learned-{n}"), &p.entry));
            t.push('\n');
        }
        for p in self.mined.proposals.iter().filter(|p| p.needs_review()) {
            let _ = writeln!(
                t,
                "# NEEDS REVIEW (risk high: {}): {} requests in {} sessions; e.g. {}",
                p.note,
                p.requests,
                p.sessions.len(),
                p.example
            );
            for line in entry_toml("learned-review", &p.entry).lines() {
                let _ = writeln!(t, "# {line}");
            }
            t.push('\n');
        }
        t
    }

    /// The human report: safeguards applied, blocked observations, support.
    pub fn render_report(&self) -> String {
        let mut r = String::new();
        let _ = writeln!(r, "sessions: {} record-mode", self.corpus.sessions.values().filter(|s| s.record).count());
        for (s, why) in &self.corpus.excluded {
            let _ = writeln!(r, "  excluded {s}: {why} (P2: the whole session is dropped; review it)");
        }
        let _ = writeln!(
            r,
            "proposals: {} active, {} need review",
            self.active().len(),
            self.mined.proposals.len() - self.active().len()
        );
        for ((what, reason), n) in &self.mined.blocked {
            let _ = writeln!(r, "  observed but blocked ({}): {what} x{n}", reason.as_str());
        }
        for (what, sessions) in &self.mined.insufficient {
            let _ = writeln!(r, "  not proposed, seen in {sessions} session(s) < {}: {what}", self.options.min_runs);
        }
        for (repo, perms) in &self.mined.github_permissions {
            let p: Vec<String> = perms.iter().map(|(k, v)| format!("{k}={v}")).collect();
            let _ = writeln!(r, "  GitHub token scope for {repo} from observed operations (G8): {}", p.join(", "));
        }
        r
    }
}

/// Replay counts for one policy over the corpus.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Replay {
    pub total: usize,
    pub denied: usize,
    /// Recorded requests that the ceiling or a hard deny blocked, still denied.
    pub blocked_still_denied: usize,
    pub blocked_total: usize,
}

fn allows(p: &EgressPolicy, o: &observe::Observation) -> bool {
    let Ok(host) = netguard::canon_host(o.host.as_bytes()) else { return false };
    let Ok(mut adm) = p.admit_host(&host, o.port) else { return false };
    let addrs: Vec<std::net::IpAddr> = o.addrs.iter().filter_map(|a| a.parse().ok()).collect();
    if !addrs.is_empty() && p.admit_addrs(&mut adm, &addrs).is_err() {
        return false;
    }
    match &o.what {
        What::Connect => true,
        What::L7(acts) => p.authorize_l7(&adm, acts).result.is_ok(),
    }
}

/// Replay every recorded request of the corpus under `layers` (+ extra).
pub fn replay<'a>(
    corpus: &Corpus,
    layers: impl IntoIterator<Item = (&'a str, &'a [EgressEntry])>,
    env: &CompileEnv,
) -> Result<Replay, String> {
    let p = EgressPolicy::compile_with(layers, env).map_err(|e| e.to_string())?;
    let mut r = Replay::default();
    for o in &corpus.observations {
        let ok = allows(&p, o);
        if o.allowed {
            r.total += 1;
            if !ok {
                r.denied += 1;
            }
        } else if o.reason != Some(Reason::UpstreamConnectFailed) {
            r.blocked_total += 1;
            if !ok {
                r.blocked_still_denied += 1;
            }
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests;
