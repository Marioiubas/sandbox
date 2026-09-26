//! Request classification: which adapter speaks for a request, and what
//! policy actions it amounts to. Adapters never call issuers (Credential
//! Injector and Issuers): they only describe the request.

use crate::git;
use audit::Reason;
use netguard::CanonicalHost;
use policy::Action;
use policy::github::Visibility;
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
    /// A GitHub GraphQL request: its Http action and the repository host
    /// (or why it is refused before the body is read).
    GitHubGraphql(Action, Result<netguard::CanonicalHost, Reason>),
    /// An S3 request: its Http action and its operation (or why none).
    S3(Action, Result<crate::s3::Route, Reason>),
}

impl Plan {
    pub fn needs_body(&self) -> bool {
        matches!(self, Plan::Git(r) if r.needs_body()) || matches!(self, Plan::GitHubGraphql(_, Ok(_)))
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
        if let Some(g) = crate::github::graphql_endpoint(host, method, path, query) {
            return Plan::GitHubGraphql(http, g);
        }
        return Plan::GitHub(http, crate::github::route(host, method, path, query));
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
                // Restricted data is private whatever the repository is.
                visibility: if r.restricted {
                    Visibility::Private
                } else if r.public {
                    Visibility::Public
                } else {
                    Visibility::Unknown
                },
                bodies: r.bodies,
                method,
                path,
                node: None,
                field: None,
            };
            Ok((vec![http.clone(), verb], None))
        }
        Plan::GitHubGraphql(_, Err(reason)) => Err(*reason),
        Plan::GitHubGraphql(http, Ok(authority)) => {
            let path = match http {
                Action::Http { path, .. } => path.clone(),
                _ => return Err(Reason::L7NoRuleMatched),
            };
            let mapped = crate::github::graphql::map(authority, body.ok_or(Reason::GithubGraphqlInvalid)?)?;
            let mut out = vec![http.clone()];
            out.extend(mapped.into_iter().map(|m| Action::GitHub {
                verb: m.verb.to_string(),
                repo: m.repo,
                visibility: if m.public { Visibility::Public } else { Visibility::Unknown },
                bodies: m.bodies,
                method: "POST".into(),
                path: path.clone(),
                node: m.node,
                field: Some(m.field),
            }));
            Ok((out, None))
        }
        Plan::S3(_, Err(reason)) => Err(*reason),
        Plan::S3(http, Ok(r)) => {
            let op = Action::S3 { op: r.op.to_string(), bucket: r.bucket.clone(), key: r.key.clone() };
            Ok((vec![http.clone(), op], None))
        }
    }
}
