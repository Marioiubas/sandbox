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
    /// A GitHub API request: its Http action and its verb (or why none).
    GitHub(Action, Result<crate::github::Route, Reason>),
    /// An S3 request: its Http action and its operation (or why none).
    S3(Action, Result<crate::s3::Route, Reason>),
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
    let http = Action::Http { method: method.to_string(), path: path.to_string() };
    if protocols.contains(&Protocol::GitHub) {
        return Plan::GitHub(http, crate::github::route(host, method, path));
    }
    if protocols.contains(&Protocol::S3) {
        return Plan::S3(http, crate::s3::route(host, method, path, query));
    }
    Plan::Http(http)
}

/// The actions of a planned request (body: decoded bytes when needed).
pub fn actions(plan: &Plan, body: Option<&[u8]>) -> Result<(Vec<Action>, Option<git::PushInfo>), Reason> {
    match plan {
        Plan::Http(a) => Ok((vec![a.clone()], None)),
        Plan::Git(r) => git::actions(r, body),
        Plan::GitHub(_, Err(reason)) => Err(*reason),
        Plan::GitHub(http, Ok(r)) => {
            let (method, path) = match http {
                Action::Http { method, path } => (method.clone(), path.clone()),
                _ => return Err(Reason::L7NoRuleMatched),
            };
            let verb = Action::GitHub {
                verb: r.verb.to_string(),
                repo: r.repo.clone(),
                visibility: policy::github::Visibility::Unknown,
                bodies: r.bodies,
                method,
                path,
            };
            Ok((vec![http.clone(), verb], None))
        }
        Plan::S3(_, Err(reason)) => Err(*reason),
        Plan::S3(http, Ok(r)) => {
            let op = Action::S3 { op: r.op.to_string(), bucket: r.bucket.clone(), key: r.key.clone() };
            Ok((vec![http.clone(), op], None))
        }
    }
}
