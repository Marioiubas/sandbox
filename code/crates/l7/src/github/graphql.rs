//! GitHub GraphQL requests (`POST /graphql`, or `/api/graphql` on GitHub
//! Enterprise) mapped to the same verbs as REST, or denied.
//!
//! - The body must be one JSON object (duplicate keys rejected) with a
//!   string `query` and optional `variables` object and `operationName`;
//!   the document must parse ([`crate::graphql`]); the operation run is the
//!   named one, or the only one; subscriptions are denied.
//! - **Mutations:** every root field must be a known mutation; each maps to
//!   a verb on the repository its input names by node ID (`createPullRequest`
//!   → `pr.create`, `mergePullRequest`/`enablePullRequestAutoMerge`/
//!   `enqueuePullRequest` → `pr.merge`, `addComment` → `issue.comment`).
//!   The broker resolves the node ID itself before deciding; any other
//!   mutation is denied.
//! - **Queries:** `repository(owner:, name:)` is `repo.read` on that
//!   repository; `viewer`, `user`, `repositoryOwner`, `rateLimit` and
//!   introspection are `github.read` of public data; everything else, and
//!   any selection that leaves the fields in [`super::schema`], is an
//!   unconfined `github.read`, which raises both read labels.
//!
//! GitHub resolves node IDs, follows renames and validates the document
//! itself; the broker never rewrites the request.

use super::strict_json::Strict;
use crate::graphql::{Document, Field, OpType, Selection, Value};
use audit::Reason;
use netguard::CanonicalHost;
use policy::RepoId;
use std::collections::HashSet;

#[path = "graphql_walk.rs"]
mod walk;
use walk::Walk;

/// Largest GraphQL request body the adapter reads.
pub const MAX_BODY: usize = 1 << 20;
/// Most root fields in one mutation (each may cost a node lookup).
pub const MAX_MUTATIONS: usize = 16;
/// Most repositories one request may read (each may cost a lookup).
pub const MAX_REPOS: usize = 16;
/// Most selections visited in one document (fragments memoised).
const MAX_STEPS: usize = 200_000;

/// Known mutations: (field, verb, input key naming the node, payload type).
const MUTATIONS: &[(&str, &str, &str, &str)] = &[
    ("createPullRequest", "pr.create", "repositoryId", "CreatePullRequestPayload"),
    ("mergePullRequest", "pr.merge", "pullRequestId", "MergePullRequestPayload"),
    ("enablePullRequestAutoMerge", "pr.merge", "pullRequestId", "EnablePullRequestAutoMergePayload"),
    ("enqueuePullRequest", "pr.merge", "pullRequestId", "EnqueuePullRequestPayload"),
    ("addComment", "issue.comment", "subjectId", "AddCommentPayload"),
];

/// The node types a verb's node ID must resolve to.
pub fn node_types(verb: &str) -> &'static [&'static str] {
    match verb {
        "pr.create" => &["Repository"],
        "pr.merge" => &["PullRequest"],
        "issue.comment" => &["Issue", "PullRequest"],
        // A mutation result's read of the written object's repository.
        "repo.read" => &["Repository", "PullRequest", "Issue"],
        _ => &[],
    }
}

/// One verb a GraphQL request amounts to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapped {
    pub verb: &'static str,
    pub repo: Option<RepoId>,
    /// A node ID the broker must resolve to the repository (mutations).
    pub node: Option<String>,
    /// The root field, for the audit row.
    pub field: String,
    pub bodies: bool,
    /// Reads only public data (no labels).
    pub public: bool,
}

fn invalid<T>(_why: &'static str) -> Result<T, Reason> {
    Err(Reason::GithubGraphqlInvalid)
}

/// Map a GraphQL request body. `authority` is the repository host
/// (`github.com` for api.github.com).
pub fn map(authority: &CanonicalHost, body: &[u8]) -> Result<Vec<Mapped>, Reason> {
    if body.len() > MAX_BODY {
        return invalid("body too large");
    }
    let Ok(Strict(v)) = serde_json::from_slice::<Strict>(body) else { return invalid("not strict JSON") };
    let serde_json::Value::Object(req) = v else { return invalid("not an object") };
    if req.keys().any(|k| !matches!(k.as_str(), "query" | "variables" | "operationName")) {
        return invalid("unknown request key");
    }
    let Some(serde_json::Value::String(src)) = req.get("query") else { return invalid("no query") };
    let empty = serde_json::Map::new();
    let vars = match req.get("variables") {
        None | Some(serde_json::Value::Null) => &empty,
        Some(serde_json::Value::Object(m)) => m,
        Some(_) => return invalid("variables not an object"),
    };
    let op_name = match req.get("operationName") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(s.as_str()),
        Some(_) => return invalid("operationName not a string"),
    };
    let doc = crate::graphql::parse(src).or_else(invalid)?;
    let op = select(&doc, op_name)?;
    if op.ty == OpType::Subscription {
        return invalid("subscription");
    }
    let mut w = Walk::new(&doc)?;
    let roots = w.roots(&op.selection, op.ty)?;
    let ctx = Vars { vars, defs: &op.vars };
    let mut out: Vec<Mapped> = Vec::new();
    match op.ty {
        OpType::Subscription => return invalid("subscription"),
        OpType::Mutation => {
            if roots.len() > MAX_MUTATIONS {
                return invalid("too many mutations");
            }
            for f in roots {
                if f.name == "__typename" {
                    continue;
                }
                let Some((_, verb, key, payload)) = MUTATIONS.iter().find(|(n, ..)| *n == f.name) else {
                    return Err(Reason::GithubGraphqlMutationUnknown);
                };
                let [(arg, input)] = f.args.as_slice() else { return invalid("mutation arguments") };
                if arg != "input" {
                    return invalid("mutation arguments");
                }
                let node = ctx.input_id(input, key).ok_or(Reason::GithubGraphqlInvalid)?;
                out.push(Mapped {
                    verb,
                    repo: None,
                    node: Some(node.clone()),
                    field: f.name.clone(),
                    bodies: false,
                    public: false,
                });
                let result = f.selection.as_deref().unwrap_or(&[]);
                let s = w.sel(result, payload)?;
                if s.unconfined {
                    out.push(unconfined(&f.name));
                }
                // A result that reads more than the written object's identity
                // (its repository's issues, comments, text) is a read of that
                // repository, resolved from the same node.
                if !w.identity_only(result)? {
                    out.push(Mapped {
                        verb: "repo.read",
                        repo: None,
                        node: Some(node),
                        field: f.name.clone(),
                        bodies: s.bodies,
                        public: false,
                    });
                }
            }
        }
        OpType::Query => {
            for f in roots {
                query_field(authority, f, &ctx, &mut w, &mut out)?;
            }
        }
    }
    if out.is_empty() {
        // Only `__typename`: still one verb, so an empty grant denies it.
        out.push(public("__typename"));
    }
    let out = dedup(out);
    // Each repository read may cost a visibility lookup with the user's
    // credential: bound them per request.
    if out.iter().filter(|m| m.verb == "repo.read").count() > MAX_REPOS {
        return invalid("too many repositories");
    }
    Ok(out)
}

fn unconfined(field: &str) -> Mapped {
    Mapped { verb: "github.read", repo: None, node: None, field: field.to_string(), bodies: true, public: false }
}

fn public(field: &str) -> Mapped {
    Mapped { verb: "github.read", repo: None, node: None, field: field.to_string(), bodies: false, public: true }
}

fn query_field<'d>(
    authority: &CanonicalHost,
    f: &'d Field,
    ctx: &Vars,
    w: &mut Walk<'d>,
    out: &mut Vec<Mapped>,
) -> Result<(), Reason> {
    let sel: &'d [Selection] = f.selection.as_deref().unwrap_or(&[]);
    let host_type = match f.name.as_str() {
        "viewer" | "user" => Some("User"),
        "repositoryOwner" => Some("RepositoryOwner"),
        "rateLimit" => Some("RateLimit"),
        _ => None,
    };
    if let Some(ty) = host_type {
        let s = w.sel(sel, ty)?;
        out.push(if s.unconfined { unconfined(&f.name) } else { public(&f.name) });
        return Ok(());
    }
    match f.name.as_str() {
        "__typename" => Ok(()),
        // Introspection describes the schema only.
        "__schema" | "__type" => {
            out.push(public(&f.name));
            Ok(())
        }
        "repository" => {
            let (mut owner, mut name) = (None, None);
            for (k, v) in &f.args {
                match k.as_str() {
                    "owner" if owner.is_none() => owner = Some(ctx.string(v).ok_or(Reason::GithubGraphqlInvalid)?),
                    "name" if name.is_none() => name = Some(ctx.string(v).ok_or(Reason::GithubGraphqlInvalid)?),
                    "followRenames" => {}
                    _ => return invalid("repository arguments"),
                }
            }
            let (Some(o), Some(n)) = (owner, name) else { return invalid("repository needs owner and name") };
            let repo = RepoId::new(authority, 443, &o, &n).ok_or(Reason::GithubGraphqlInvalid)?;
            let s = w.sel(sel, "Repository")?;
            out.push(Mapped {
                verb: "repo.read",
                repo: Some(repo),
                node: None,
                field: f.name.clone(),
                bodies: s.bodies,
                public: false,
            });
            if s.unconfined {
                out.push(unconfined(&f.name));
            }
            Ok(())
        }
        _ => {
            out.push(unconfined(&f.name));
            Ok(())
        }
    }
}

/// One `repo.read` per repository (bodies merged) and at most one
/// `github.read` (unconfined wins over public); writes kept in order.
fn dedup(v: Vec<Mapped>) -> Vec<Mapped> {
    let mut out: Vec<Mapped> = Vec::new();
    for m in v {
        let same = out.iter_mut().find(|o| match (o.verb, m.verb) {
            ("repo.read", "repo.read") => o.repo == m.repo && o.node == m.node,
            ("github.read", "github.read") => true,
            _ => false,
        });
        match same {
            Some(o) => {
                o.bodies |= m.bodies;
                o.public &= m.public;
            }
            None => out.push(m),
        }
    }
    out
}

/// The operation GitHub runs: the named one, or the only one.
fn select<'d>(doc: &'d Document, name: Option<&str>) -> Result<&'d crate::graphql::Operation, Reason> {
    let mut names = HashSet::new();
    for o in &doc.operations {
        match &o.name {
            Some(n) if !names.insert(n.as_str()) => return invalid("duplicate operation name"),
            None if doc.operations.len() > 1 => return invalid("anonymous operation among others"),
            _ => {}
        }
    }
    match name {
        Some(n) => doc.operations.iter().find(|o| o.name.as_deref() == Some(n)).ok_or(Reason::GithubGraphqlInvalid),
        None => match doc.operations.as_slice() {
            [o] => Ok(o),
            _ => invalid("several operations and no operationName"),
        },
    }
}

/// Variable values: from the request's `variables`, else the default.
struct Vars<'a> {
    vars: &'a serde_json::Map<String, serde_json::Value>,
    defs: &'a [(String, Option<Value>)],
}

enum Resolved<'a> {
    Json(&'a serde_json::Value),
    Gql(&'a Value),
}

impl<'a> Vars<'a> {
    fn var(&self, n: &str) -> Option<Resolved<'a>> {
        let (_, default) = self.defs.iter().find(|(d, _)| d == n)?;
        match (self.vars.get(n), default) {
            (Some(j), _) => Some(Resolved::Json(j)),
            (None, Some(d)) => Some(Resolved::Gql(d)),
            (None, None) => None,
        }
    }

    fn string(&self, v: &Value) -> Option<String> {
        match v {
            Value::Str(s) => Some(s.clone()),
            Value::Var(n) => match self.var(n)? {
                Resolved::Json(serde_json::Value::String(s)) => Some(s.clone()),
                Resolved::Gql(Value::Str(s)) => Some(s.clone()),
                _ => None,
            },
            _ => None,
        }
    }

    /// `input.<key>` as a node ID, from a literal object or a variable.
    fn input_id(&self, input: &Value, key: &str) -> Option<String> {
        let id = match input {
            Value::Object(fields) => {
                let mut seen = HashSet::new();
                if !fields.iter().all(|(k, _)| seen.insert(k.as_str())) {
                    return None;
                }
                let (_, v) = fields.iter().find(|(k, _)| k == key)?;
                self.string(v)?
            }
            Value::Var(n) => match self.var(n)? {
                Resolved::Json(j) => j.as_object()?.get(key)?.as_str()?.to_string(),
                Resolved::Gql(g @ Value::Object(_)) => return self.input_id(g, key),
                Resolved::Gql(_) => return None,
            },
            _ => return None,
        };
        let ok = !id.is_empty()
            && id.len() <= 200
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'=' | b'+' | b'/'));
        ok.then_some(id)
    }
}

#[cfg(test)]
#[path = "graphql_tests.rs"]
mod tests;
