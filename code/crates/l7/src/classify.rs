//! Request classification: which adapter speaks for a request, and what
//! policy actions it amounts to. Adapters never call issuers (Credential
//! Injector and Issuers): they only describe the request.

use crate::git;
use audit::Reason;
use netguard::CanonicalHost;
use policy::Action;
use policy::l7::Protocol;
use std::collections::BTreeSet;

/// How the request will be classified, decided from the head alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    /// A generic HTTP request: method and canonical path.
    Http(Action),
    /// A git smart-HTTP request (receive-pack needs the body).
    Git(git::Route),
}

impl Plan {
    pub fn needs_body(&self) -> bool {
        matches!(self, Plan::Git(r) if r.needs_body())
    }
}

/// Choose the adapter: a host with a git grant gets git routes recognised;
/// everything else is a method/path request.
pub fn plan(
    protocols: &BTreeSet<Protocol>,
    host: &CanonicalHost,
    port: u16,
    method: &str,
    path: &str,
    query: Option<&str>,
) -> Plan {
    if protocols.contains(&Protocol::Git)
        && let Some(r) = git::route(host, port, method, path, query)
    {
        return Plan::Git(r);
    }
    Plan::Http(Action::Http { method: method.to_string(), path: path.to_string() })
}

/// The actions of a planned request (body: decoded bytes when needed).
pub fn actions(plan: &Plan, body: Option<&[u8]>) -> Result<(Vec<Action>, Option<git::PushInfo>), Reason> {
    match plan {
        Plan::Http(a) => Ok((vec![a.clone()], None)),
        Plan::Git(r) => git::actions(r, body),
    }
}
