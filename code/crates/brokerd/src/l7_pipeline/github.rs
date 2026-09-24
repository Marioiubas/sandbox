//! GitHub on the L7 path (GitHub API Adapter, Trifecta Session Labels):
//! repository visibility from a broker-originated metadata read with the
//! credential the decision bound, and the labels a request raises. Labels
//! are raised only by the broker, from API facts, and never lowered.

use super::Conn;
use audit::{EventKind, RequestId};
use bytes::Bytes;
use creds::Issued;
use http::{HeaderValue, Request};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use policy::github::{Label, Visibility, labels_for};
use policy::{Action, AttachSpec};
use std::time::Duration;

/// Largest repository metadata document read for visibility.
const MAX_META: usize = 1 << 20;

impl Conn {
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
        let Ok(mut req) = Request::get(path.as_str()).body(Empty::<Bytes>::new()) else { return Visibility::Unknown };
        let h = req.headers_mut();
        let Ok(auth) = HeaderValue::from_str(&self.authority()) else { return Visibility::Unknown };
        h.insert(http::header::HOST, auth);
        h.insert(http::header::USER_AGENT, HeaderValue::from_static("broker"));
        h.insert(http::header::ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
        h.insert(http::header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        if let Some((i, spec)) = cred
            && creds::attach(i, spec, h).is_err()
        {
            return Visibility::Unknown;
        }
        let Some(tcp) = crate::upstream::connect_addrs(&self.addrs, self.port).await else {
            return Visibility::Unknown;
        };
        let Ok(tls) = crate::upstream::tls_connect(&self.l7.upstream_tls, &self.host, tcp).await else {
            return Visibility::Unknown;
        };
        let Ok((mut s, conn)) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await else {
            return Visibility::Unknown;
        };
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let Ok(resp) = s.send_request(req).await else { return Visibility::Unknown };
        if resp.status() != http::StatusCode::OK {
            return Visibility::Unknown;
        }
        let Ok(body) = Limited::new(resp.into_body(), MAX_META).collect().await else { return Visibility::Unknown };
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body.to_bytes()) else { return Visibility::Unknown };
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
        for a in actions {
            match a {
                Action::GitHub { verb, visibility, bodies, .. } => {
                    raise.extend(labels_for(verb, *visibility, *bodies).into_iter().map(|l| (l, a.verb())));
                }
                Action::Http { method, .. } if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") => {
                    raise.push((Label::ExternalEffect, a.verb()))
                }
                Action::GitPush { .. } => raise.push((Label::ExternalEffect, a.verb())),
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
