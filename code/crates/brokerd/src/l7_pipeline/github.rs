//! GitHub on the L7 path (GitHub API Adapter, Trifecta Session Labels):
//! repository visibility from a broker-originated metadata read with the
//! credential the decision bound, GraphQL node IDs resolved to their
//! repository the same way, and the labels a request raises. Labels are
//! raised only by the broker, from API facts, and never lowered.

use super::{Conn, RespBody};
use audit::{EventKind, Reason, RequestId};
use bytes::Bytes;
use creds::Issued;
use http::{HeaderValue, Request, Response};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use policy::github::{Label, Visibility, labels_for};
use policy::{Action, AttachSpec, RepoId};
use std::time::Duration;

/// Largest repository metadata document read for visibility.
const MAX_META: usize = 1 << 20;

/// The broker's own node lookup: the repository a node ID names.
const NODE_QUERY: &str = "query($id: ID!) { node(id: $id) { __typename \
    ... on Repository { nameWithOwner visibility } \
    ... on PullRequest { repository { nameWithOwner visibility } } \
    ... on Issue { repository { nameWithOwner visibility } } } }";

/// A resolved node: its type, repository and that repository's visibility.
type Node = (String, RepoId, Visibility);

impl Conn {
    /// GraphQL mutations name repositories by node ID: resolve them with the
    /// credential of the grant admitting this host and fill each verb's
    /// repository. Returns the credential the lookups used (the final
    /// decision must bind the same one), or the deny for a verb whose node
    /// stays unresolved.
    pub(super) async fn graphql_nodes(
        &self,
        rid: &RequestId,
        actions: &mut [Action],
    ) -> Result<Option<Option<String>>, Response<RespBody>> {
        let mut node_cred = None;
        let pending = self.unresolved_nodes(actions);
        if !pending.is_empty() {
            let http: Vec<Action> = actions.iter().filter(|a| matches!(a, Action::Http { .. })).cloned().collect();
            let pre = self.ctx.policy.authorize_l7(&self.adm, &http);
            if let Err(reason) = pre.result {
                return Err(self.deny(rid, reason, pre.policy_ids, &[], None, None));
            }
            let cred = match &pre.binding {
                None => None,
                Some(b) => match self.l7.creds.get(b).await {
                    Ok((i, _)) => Some((i, b.credential().attach.clone())),
                    Err(e) => {
                        let err = Some(("error", e.to_string().into()));
                        return Err(self.deny(rid, Reason::MintFailed, pre.policy_ids, &[], err, None));
                    }
                },
            };
            self.resolve_nodes(&pending, cred.as_ref().map(|(i, spec)| (i.as_ref(), spec))).await;
            node_cred = Some(pre.binding.as_ref().map(|b| b.credential().id.clone()));
        }
        self.fill_nodes(actions);
        let unresolved = actions.iter().find_map(|a| match a {
            Action::GitHub { node: Some(n), repo: None, .. } => Some(n.clone()),
            _ => None,
        });
        if let Some(n) = unresolved {
            // The same reason as an ungranted repository: the agent learns
            // nothing about which node IDs exist.
            let verbs: Vec<String> = actions.iter().map(|a| a.verb()).collect();
            let note = Some(("node_unresolved", n.into()));
            return Err(self.deny(rid, Reason::GithubRepoNotAllowed, vec![], &verbs, note, None));
        }
        Ok(node_cred)
    }

    /// GraphQL node IDs in `actions` not resolved yet this session.
    fn unresolved_nodes(&self, actions: &[Action]) -> Vec<String> {
        let cache = self.l7.nodes.lock().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<String> = actions
            .iter()
            .filter_map(|a| match a {
                Action::GitHub { node: Some(n), repo: None, .. } if !cache.contains_key(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        out.dedup();
        out
    }

    /// Resolve node IDs with the given credential (the one the grant
    /// admitting this host binds) and cache the results; a failed lookup
    /// caches nothing and leaves the verb unresolved, which denies.
    async fn resolve_nodes(&self, ids: &[String], cred: Option<(&Issued, &AttachSpec)>) {
        for id in ids {
            let found = tokio::time::timeout(Duration::from_secs(10), self.node_lookup(id, cred)).await.ok().flatten();
            if let Some((ty, repo, vis)) = found {
                self.l7.visibility.lock().unwrap_or_else(|p| p.into_inner()).insert(repo.to_string(), vis);
                self.l7.nodes.lock().unwrap_or_else(|p| p.into_inner()).insert(id.clone(), (ty, repo, vis));
            }
        }
    }

    /// Fill each GraphQL verb's repository from its resolved node, only
    /// when the node has a type that verb acts on (a PR ID for a merge).
    fn fill_nodes(&self, actions: &mut [Action]) {
        let cache = self.l7.nodes.lock().unwrap_or_else(|p| p.into_inner());
        for a in actions {
            if let Action::GitHub { verb, node: Some(n), repo: repo @ None, .. } = a
                && let Some((ty, r, _)) = cache.get(n.as_str())
                && l7::github::graphql::node_types(verb).contains(&ty.as_str())
            {
                *repo = Some(r.clone());
            }
        }
    }

    async fn node_lookup(&self, id: &str, cred: Option<(&Issued, &AttachSpec)>) -> Option<Node> {
        let path = if self.host.as_str() == "api.github.com" { "/graphql" } else { "/api/graphql" };
        let body = serde_json::to_vec(&serde_json::json!({ "query": NODE_QUERY, "variables": { "id": id } })).ok()?;
        let mut req = Request::post(path).body(Full::new(Bytes::from(body))).ok()?;
        req.headers_mut().insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let v = self.api_json(req, cred).await?;
        let node = v.get("data")?.get("node")?;
        let ty = node.get("__typename")?.as_str()?;
        let r = if ty == "Repository" { node } else { node.get("repository")? };
        let (owner, name) = r.get("nameWithOwner")?.as_str()?.split_once('/')?;
        let vis = match r.get("visibility").and_then(|v| v.as_str()) {
            Some("PUBLIC") => Visibility::Public,
            Some(_) => Visibility::Private,
            None => Visibility::Unknown,
        };
        let authority = l7::github::repo_host(&self.host)?;
        Some((ty.to_string(), RepoId::new(&authority, 443, owner, name)?, vis))
    }

    /// One broker-originated API request on this host with the credential;
    /// the JSON body of a 200 response.
    async fn api_json(
        &self,
        mut req: Request<Full<Bytes>>,
        cred: Option<(&Issued, &AttachSpec)>,
    ) -> Option<serde_json::Value> {
        let h = req.headers_mut();
        h.insert(http::header::HOST, HeaderValue::from_str(&self.authority()).ok()?);
        h.insert(http::header::USER_AGENT, HeaderValue::from_static("broker"));
        h.insert(http::header::ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
        h.insert(http::header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        if let Some((i, spec)) = cred {
            creds::attach(i, spec, h).ok()?;
        }
        let tcp = crate::upstream::connect_addrs(&self.addrs, self.port).await?;
        let tls = crate::upstream::tls_connect(&self.l7.upstream_tls, &self.host, tcp).await.ok()?;
        let (mut s, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.ok()?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = s.send_request(req).await.ok()?;
        if resp.status() != http::StatusCode::OK {
            return None;
        }
        let body = Limited::new(resp.into_body(), MAX_META).collect().await.ok()?;
        serde_json::from_slice(&body.to_bytes()).ok()
    }

    /// Fill each GitHub action's visibility from the session cache.
    pub(super) fn fill_visibility(&self, actions: &mut [Action]) {
        let cache = self.l7.visibility.lock().unwrap_or_else(|p| p.into_inner());
        for a in actions {
            if let Action::GitHub { repo: Some(r), visibility, .. } = a {
                *visibility = cache.get(&r.to_string()).copied().unwrap_or(Visibility::Unknown);
            }
        }
    }

    /// Repositories this request touches whose visibility is not known yet.
    pub(super) fn unknown_repos(&self, actions: &[Action]) -> Vec<policy::RepoId> {
        let cache = self.l7.visibility.lock().unwrap_or_else(|p| p.into_inner());
        actions
            .iter()
            .filter_map(|a| match a {
                Action::GitHub { repo: Some(r), .. } if !cache.contains_key(&r.to_string()) => Some(r.clone()),
                _ => None,
            })
            .collect()
    }

    /// Read `GET /repos/{o}/{r}` on this API host with the bound credential
    /// (a metadata read of the repository the request already reads or
    /// writes) and cache the result; any failure caches `Unknown`, which
    /// only narrows.
    pub(super) async fn resolve_visibility(&self, repos: &[policy::RepoId], cred: Option<(&Issued, &AttachSpec)>) {
        for r in repos {
            let v = tokio::time::timeout(Duration::from_secs(10), self.lookup(r, cred))
                .await
                .unwrap_or(Visibility::Unknown);
            self.l7.visibility.lock().unwrap_or_else(|p| p.into_inner()).insert(r.to_string(), v);
        }
    }

    async fn lookup(&self, r: &policy::RepoId, cred: Option<(&Issued, &AttachSpec)>) -> Visibility {
        let prefix = if self.host.as_str() == "api.github.com" { "" } else { "/api/v3" };
        let path = format!("{prefix}/repos/{}/{}", r.owner(), r.name());
        let Ok(req) = Request::get(path.as_str()).body(Full::new(Bytes::new())) else { return Visibility::Unknown };
        let Some(v) = self.api_json(req, cred).await else { return Visibility::Unknown };
        // `private` (boolean) is required in GitHub's schema; `visibility`
        // may also say `internal` (GitHub Enterprise), which is not public.
        match (v.get("private").and_then(|p| p.as_bool()), v.get("visibility").and_then(|x| x.as_str())) {
            (Some(false), None | Some("public")) => Visibility::Public,
            (Some(_), _) | (None, Some(_)) => Visibility::Private,
            (None, None) => Visibility::Unknown,
        }
    }

    /// Raise the labels an allowed request implies, before it is forwarded,
    /// and record each label that this request raised.
    pub(super) fn raise_labels(&self, rid: &RequestId, actions: &[Action], high_risk_credential: bool) {
        let mut raise: Vec<(Label, String)> = Vec::new();
        // On GitHub and S3 hosts the verb or operation says what a request
        // does (a GraphQL query is a POST that writes nothing).
        let adapted = actions.iter().any(|a| matches!(a, Action::GitHub { .. } | Action::S3 { .. }));
        for a in actions {
            match a {
                Action::GitHub { verb, visibility, bodies, .. } => {
                    raise.extend(labels_for(verb, *visibility, *bodies).into_iter().map(|l| (l, a.verb())));
                }
                Action::Http { method, .. } if !adapted && !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") => {
                    raise.push((Label::ExternalEffect, a.verb()))
                }
                Action::GitPush { .. } => raise.push((Label::ExternalEffect, a.verb())),
                Action::S3 { op, .. } => {
                    raise.extend(policy::s3::labels_for(op).into_iter().map(|l| (l, a.verb())));
                }
                _ => {}
            }
        }
        if high_risk_credential {
            raise.push((Label::SensitiveRead, "a high-risk credential".into()));
        }
        let labels = self.ctx.policy.labels();
        for (l, cause) in raise {
            if labels.raise(l) {
                let ev = self
                    .ctx
                    .event(EventKind::SessionLabel, rid)
                    .dest(self.dest.clone())
                    .detail("label", l.as_str())
                    .detail("cause", cause);
                if let Err(e) = self.ctx.recorder.append(&ev) {
                    eprintln!("brokerd: audit append failed for label {}: {e:#}", l.as_str());
                }
            }
        }
    }

    /// The labels as they stood for this decision.
    pub(super) fn labels_detail(&self) -> serde_json::Value {
        serde_json::to_value(self.ctx.policy.labels().snapshot()).unwrap_or_default()
    }
}
