//! Which reads are sensitive beyond what adapters know (ADR-040): the
//! session's `sensitive_read` label for connections to intranet addresses
//! and for credentialed reads on hosts without an adapter, with a grant's
//! `sensitive` key deciding either way.

use super::*;

/// Address classes whose hosts serve intranet data by default.
const INTRANET: &[&str] = &["private", "link_local"];

impl EgressPolicy {
    fn admitting(&self, adm: &Admission) -> impl Iterator<Item = &Grant> {
        adm.grants.iter().filter_map(|&i| self.grants.get(i))
    }

    /// Why a connection through this admission is a sensitive read, if it
    /// is: an admitting grant says `sensitive = true`, or the host was
    /// reached on an intranet address and no admitting grant says
    /// `sensitive = false`.
    pub fn admission_sensitive(&self, adm: &Admission) -> Option<String> {
        if let Some(g) = self.admitting(adm).find(|g| g.sensitive == Some(true)) {
            return Some(format!("grant {} (sensitive)", g.id));
        }
        if self.admitting(adm).any(|g| g.sensitive == Some(false)) {
            return None;
        }
        let class = adm.addr_classes.iter().find(|c| INTRANET.contains(&c.as_str()))?;
        Some(format!("{} on a {class} address", adm.host))
    }

    /// Whether a request that carried a brokered credential through this
    /// admission reads sensitive data when no adapter judged it: yes unless
    /// every admitting grant is the model API (ADR-039) or says
    /// `sensitive = false`.
    pub fn credentialed_reads_sensitive(&self, adm: &Admission) -> bool {
        let mut grants = self.admitting(adm).peekable();
        grants.peek().is_none() || !grants.all(|g| g.model_api || g.sensitive == Some(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_policy_str;
    use netguard::canon_host;

    fn admit(p: &EgressPolicy, host: &str, addr: &str) -> Admission {
        let mut a = p.admit_host(&canon_host(host.as_bytes()).unwrap(), 443).unwrap();
        p.admit_addrs(&mut a, &[addr.parse().unwrap()]).unwrap();
        a
    }

    #[test]
    fn intranet_addresses_and_declared_grants_are_sensitive() {
        let p = parse_policy_str(
            r#"version = 1
[[egress]]
host = "wiki.corp.test"
allow_addr_classes = ["private"]
[[egress]]
host = "mirror.corp.test"
allow_addr_classes = ["private"]
sensitive = false
[[egress]]
host = "docs.example"
[[egress]]
host = "crm.example"
sensitive = true
[[egress]]
host = "api.anthropic.com"
model_api = true
[[egress]]
host = "raw.githubusercontent.com"
"#,
        )
        .unwrap();
        let p = EgressPolicy::compile([("user", p.egress.as_slice())]).unwrap();
        assert_eq!(
            p.admission_sensitive(&admit(&p, "wiki.corp.test", "10.1.2.3")).as_deref(),
            Some("wiki.corp.test on a private address")
        );
        assert_eq!(p.admission_sensitive(&admit(&p, "mirror.corp.test", "10.1.2.4")), None);
        assert_eq!(p.admission_sensitive(&admit(&p, "docs.example", "93.184.216.34")), None);
        assert!(p.admission_sensitive(&admit(&p, "crm.example", "93.184.216.35")).is_some());
        assert!(!p.credentialed_reads_sensitive(&admit(&p, "api.anthropic.com", "160.79.104.10")));
        assert!(p.credentialed_reads_sensitive(&admit(&p, "raw.githubusercontent.com", "185.199.108.133")));
        assert!(!p.credentialed_reads_sensitive(&admit(&p, "mirror.corp.test", "10.1.2.4")));
        // A repository layer may not declare sensitivity either way.
        let repo = parse_policy_str("version = 1\n[[egress]]\nhost = \"docs.example\"\nsensitive = true\n").unwrap();
        assert!(p.clone().with_repo_layer(&repo.egress, None, &CompileEnv::default()).is_err());
    }
}
