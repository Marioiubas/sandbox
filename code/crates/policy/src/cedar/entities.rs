//! The entity builder: canonical values in, Cedar entities and context out.
//! Only `CanonicalHost`, `RepoId` and canonical path strings enter here
//! (I6); nothing is parsed from raw request bytes.

use crate::repo::RepoId;
use netguard::{CanonicalHost, HostKind};
use serde_json::{Value, json};

/// Segments recorded individually in the `Path` record.
pub const PATH_SEGMENTS: usize = 16;

/// Who the session is: the principal `Task` and its owner and agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub session_id: String,
    pub task_id: String,
    /// `local:<user>` until IdP identity lands (M3).
    pub user: String,
    pub agent: String,
    pub agent_sha256: String,
    /// `owner/name` of the session repository, or empty.
    pub repo: String,
    pub branch_prefix: String,
    /// Epoch seconds; every grant expires with the task.
    pub expires_at: i64,
    /// `enforce` or `record`.
    pub mode: Mode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Enforce,
    /// Learning: task permits relaxed to the org ceiling, credentials still
    /// only by grant (Policy Learning Loop).
    Record,
    /// Enforce, with a candidate policy evaluated and logged alongside.
    Shadow,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Enforce => "enforce",
            Mode::Record => "record",
            Mode::Shadow => "shadow",
        }
    }
}

impl Default for SessionInfo {
    fn default() -> Self {
        SessionInfo {
            session_id: "unset".into(),
            task_id: "task-unset".into(),
            user: "local:unknown".into(),
            agent: "unknown".into(),
            agent_sha256: String::new(),
            repo: String::new(),
            branch_prefix: "agent/".into(),
            expires_at: i64::MAX,
            mode: Mode::Enforce,
        }
    }
}

pub fn now_epoch() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn uid(ty: &str, id: &str) -> Value {
    json!({ "type": format!("Broker::{ty}"), "id": id })
}

pub fn task_uid(s: &SessionInfo) -> Value {
    uid("Task", &s.task_id)
}

/// Task, User and Agent entities for the session.
pub fn principal_entities(s: &SessionInfo) -> Vec<Value> {
    vec![
        json!({ "uid": uid("User", &s.user), "attrs": { "idp": "local", "subject": s.user }, "parents": [] }),
        json!({ "uid": uid("Agent", &s.agent), "attrs": { "vendor": s.agent, "binary_sha256": s.agent_sha256 }, "parents": [] }),
        json!({
            "uid": task_uid(s),
            "attrs": {
                "owner": { "__entity": { "type": "Broker::User", "id": s.user } },
                "agent": { "__entity": { "type": "Broker::Agent", "id": s.agent } },
                "repo": s.repo,
                "branch_prefix": s.branch_prefix,
                "expires_at": s.expires_at,
            },
            "parents": []
        }),
    ]
}

/// Proper label-boundary suffixes of a name: `a.b.c` → `b.c`, `c`.
pub fn domain_suffixes(host: &CanonicalHost) -> Vec<String> {
    if host.is_ip_literal() {
        return vec![];
    }
    let s = host.as_str();
    s.char_indices().filter(|(_, c)| *c == '.').map(|(i, _)| s[i + 1..].to_string()).collect()
}

/// The `Host` entity with its `Domain` and category parents.
pub fn host_entity(host: &CanonicalHost, categories: &[&str]) -> Value {
    let mut parents: Vec<Value> = domain_suffixes(host).iter().map(|d| uid("Domain", d)).collect();
    parents.extend(categories.iter().map(|c| uid("HostCategory", c)));
    let registrable = match host.kind() {
        HostKind::Name { .. } => host.registrable().unwrap_or(host.as_str()).to_string(),
        _ => host.as_str().to_string(),
    };
    json!({
        "uid": uid("Host", host.as_str()),
        "attrs": { "registrable": registrable, "ip_literal": host.is_ip_literal() },
        "parents": parents,
    })
}

pub fn host_uid(host: &CanonicalHost) -> Value {
    uid("Host", host.as_str())
}

/// The `Repo` entity (child of its host). Visibility is unknown until the
/// GitHub API adapter reports it (M3).
pub fn repo_entity(repo: &RepoId, host: &CanonicalHost) -> Value {
    json!({
        "uid": uid("Repo", &repo.to_string()),
        "attrs": {
            "authority": repo.authority(),
            "owner": repo.owner(),
            "full_name": format!("{}/{}", repo.owner(), repo.name()),
            "visibility": "unknown",
        },
        "parents": [host_uid(host)],
    })
}

pub fn repo_uid(repo: &RepoId) -> Value {
    uid("Repo", &repo.to_string())
}

pub fn credential_uid(id: &str) -> Value {
    uid("Credential", id)
}

pub fn credential_entity(id: &str, issuer: &str, hosts: &[String], domains: &[String]) -> Value {
    json!({
        "uid": credential_uid(id),
        "attrs": { "issuer": issuer, "allowed_hosts": hosts, "allowed_domains": domains, "risk": "high" },
        "parents": [],
    })
}

/// The `Path` record for a canonical path.
pub fn path_record(path: &str) -> Value {
    let rest = path.strip_prefix('/').unwrap_or(path);
    let segs: Vec<&str> = rest.split('/').collect();
    let mut m = serde_json::Map::new();
    m.insert("n".into(), json!(segs.len()));
    for (i, s) in segs.iter().take(PATH_SEGMENTS).enumerate() {
        m.insert(format!("s{i}"), json!(s));
    }
    Value::Object(m)
}

pub fn session_record(s: &SessionInfo, mode: Mode, now: i64) -> Value {
    json!({
        "id": s.session_id,
        "now": now,
        "approved": false,
        "trifecta": { "untrusted_input": false, "sensitive_read": false, "external_effect": false },
        "mode": mode.as_str(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use netguard::canon_host;

    #[test]
    fn suffixes_and_paths() {
        let h = canon_host(b"a.b.example.com").unwrap();
        assert_eq!(domain_suffixes(&h), vec!["b.example.com", "example.com", "com"]);
        assert!(domain_suffixes(&canon_host(b"10.0.0.1").unwrap()).is_empty());
        assert_eq!(domain_suffixes(&canon_host(b"localhost").unwrap()), Vec::<String>::new());
        let p = path_record("/v1/messages");
        assert_eq!(p, json!({ "n": 2, "s0": "v1", "s1": "messages" }));
        assert_eq!(path_record("/"), json!({ "n": 1, "s0": "" }));
        let deep = "/a".repeat(20);
        let p = path_record(&deep);
        assert_eq!(p["n"], 20);
        assert!(p.get("s16").is_none());
    }
}
