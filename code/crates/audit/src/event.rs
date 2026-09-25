//! The audit event schema (format version 1).
//!
//! Identity fields are copied from the session, never from request content or
//! agent output (I9). No field may hold a secret, a sentinel value, a request
//! body or a prompt (I1).

use crate::{Reason, RequestId, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    #[serde(rename = "session.start")]
    SessionStart,
    /// The shim verified every layer from inside; the agent is about to exec.
    #[serde(rename = "session.ready")]
    SessionReady,
    #[serde(rename = "session.stop")]
    SessionStop,
    #[serde(rename = "session_aborted")]
    SessionAborted,
    #[serde(rename = "launch_refused")]
    LaunchRefused,
    #[serde(rename = "request.decision")]
    RequestDecision,
    #[serde(rename = "request.outcome")]
    RequestOutcome,
    #[serde(rename = "fs.denied")]
    FsDenied,
    #[serde(rename = "policy.reload")]
    PolicyReload,
    /// A session trifecta label was raised, and by which request.
    #[serde(rename = "session.label")]
    SessionLabel,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::SessionStart => "session.start",
            EventKind::SessionReady => "session.ready",
            EventKind::SessionLabel => "session.label",
            EventKind::SessionStop => "session.stop",
            EventKind::SessionAborted => "session_aborted",
            EventKind::LaunchRefused => "launch_refused",
            EventKind::RequestDecision => "request.decision",
            EventKind::RequestOutcome => "request.outcome",
            EventKind::FsDenied => "fs.denied",
            EventKind::PolicyReload => "policy.reload",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionResult {
    Allow,
    Deny,
}

/// Enforce denies; audit logs would-be denies (L7 only, M2). Isolation and
/// DNS control never change with the mode (I8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Enforce,
    Audit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub result: DecisionResult,
    /// Determining policy IDs (grant IDs in M0, Cedar `@id`s from M2).
    pub policy_ids: Vec<String>,
    pub mode: Mode,
}

/// Where a request was going, as the broker understood it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dest {
    /// `connect` | `socks5`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<String>,
    /// The canonical host, or, if canonicalisation failed, a redacted
    /// description of the raw bytes (length and first bytes escaped); raw
    /// attacker bytes are never logged verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Addresses the broker resolved (or the literal), as strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event format version.
    pub v: u32,
    pub ts: String,
    pub kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    /// IdP subject (`broker login`, a CI identity token), else `local:<user>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enduser: Option<String>,
    /// The end user's IdP groups, when the login carries them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enduser_groups: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    /// Sandbox backend name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dest: Option<Dest>,
    /// Structured extras (layer report, exit status, byte counts). Must not
    /// contain secrets; floats are rejected by the canonical form.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub detail: Map<String, Value>,
}

impl AuditEvent {
    pub fn new(kind: EventKind) -> Self {
        AuditEvent {
            v: 1,
            ts: crate::time::now(),
            kind,
            session: None,
            request_id: None,
            enduser: None,
            enduser_groups: Vec::new(),
            agent: None,
            agent_sha256: None,
            task: None,
            sandbox: None,
            decision: None,
            reason: None,
            dest: None,
            detail: Map::new(),
        }
    }

    pub fn session(mut self, s: &SessionId) -> Self {
        self.session = Some(s.clone());
        self
    }

    pub fn request(mut self, r: &RequestId) -> Self {
        self.request_id = Some(r.clone());
        self
    }

    pub fn allow(mut self, policy_ids: Vec<String>) -> Self {
        self.decision = Some(Decision { result: DecisionResult::Allow, policy_ids, mode: Mode::Enforce });
        self
    }

    pub fn deny(mut self, reason: Reason, policy_ids: Vec<String>) -> Self {
        self.decision = Some(Decision { result: DecisionResult::Deny, policy_ids, mode: Mode::Enforce });
        self.reason = Some(reason);
        self
    }

    /// Mark the decision as recorded in audit (record) mode.
    pub fn audit_mode(mut self) -> Self {
        if let Some(d) = self.decision.as_mut() {
            d.mode = Mode::Audit;
        }
        self
    }

    pub fn dest(mut self, d: Dest) -> Self {
        self.dest = Some(d);
        self
    }

    pub fn detail(mut self, key: &str, v: impl Into<Value>) -> Self {
        self.detail.insert(key.to_string(), v.into());
        self
    }

    pub fn is_deny(&self) -> bool {
        matches!(self.decision, Some(Decision { result: DecisionResult::Deny, .. }))
    }
}

/// Describe untrusted host bytes for the audit log without writing them
/// verbatim: length plus an escaped, truncated prefix. Exfiltration payloads
/// in query names therefore land in the log only as a bounded prefix.
pub fn describe_raw_host(raw: &[u8]) -> String {
    const MAX: usize = 32;
    let mut s = String::new();
    for &b in raw.iter().take(MAX) {
        if b.is_ascii_graphic() && b != b'\\' {
            s.push(b as char);
        } else {
            s.push_str(&format!("\\x{b:02x}"));
        }
    }
    if raw.len() > MAX {
        s.push('…');
    }
    format!("raw[{}]:{}", raw.len(), s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_host_description_escapes_and_truncates() {
        let d = describe_raw_host(b"attacker.example\x00.google.com");
        assert_eq!(d, "raw[28]:attacker.example\\x00.google.com");
        let long = vec![b'a'; 100];
        assert!(describe_raw_host(&long).ends_with('…'));
    }
}
