//! Local answers of the L7 path: the deny row and response (git-native
//! for pushes), the withheld-response answer, request body collection and
//! decoding, and the response body that appends the outcome row.

use super::{Conn, RespBody};
use audit::{AuditEvent, EventKind, Reason, Recorder, RequestId};
use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use l7::filter::BoxError;
use l7::git::PushInfo;
use std::convert::Infallible;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) fn full(b: impl Into<Bytes>) -> RespBody {
    Full::new(b.into()).map_err(|n: Infallible| match n {}).boxed_unsync()
}

/// Serve one terminated tunnel. `peeked` holds the ClientHello bytes.
/// Decode a request body for inspection (identity or gzip only).
pub(super) fn decode_body(headers: &http::HeaderMap, raw: &Bytes, max: usize) -> Result<Vec<u8>, Reason> {
    match l7::filter::coding(headers) {
        Some(l7::filter::Coding::Identity) => Ok(raw.to_vec()),
        Some(l7::filter::Coding::Gzip) => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(&raw[..])
                .take(max as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|_| Reason::GitParseError)?;
            if out.len() > max {
                return Err(Reason::BodyTooLarge);
            }
            Ok(out)
        }
        _ => Err(Reason::UnsupportedEncoding),
    }
}

pub(super) async fn collect(body: Incoming, max: usize) -> Result<Bytes, Reason> {
    match Limited::new(body, max).collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() => Err(Reason::BodyTooLarge),
        Err(_) => Err(Reason::MalformedRequest),
    }
}

impl Conn {
    pub(super) fn base_event(&self, kind: EventKind, rid: &RequestId, verbs: &[String]) -> AuditEvent {
        let mut ev = self.ctx.event(kind, rid).dest(self.dest.clone()).detail("layer", "l7");
        if !verbs.is_empty() {
            ev = ev.detail("verb", verbs.join("; "));
        }
        ev
    }

    /// The shadow candidate's verdict on these actions (shadow mode only).
    pub(super) fn shadow_note(&self, actions: &[policy::Action], applied_allow: bool) -> Option<serde_json::Value> {
        let s = self.ctx.shadow.as_ref()?;
        let verdict = match self.shadow_adm.as_ref()? {
            Ok(adm) => s.authorize_l7(adm, actions).result,
            Err(r) => Err(*r),
        };
        Some(crate::shadow::note(&verdict, applied_allow, true))
    }

    /// Record a deny and answer the client (git-native for pushes).
    pub(super) fn deny(
        &self,
        rid: &RequestId,
        reason: Reason,
        policy_ids: Vec<String>,
        verbs: &[String],
        extra: Option<(&str, serde_json::Value)>,
        push: Option<&PushInfo>,
    ) -> Response<RespBody> {
        self.deny_with(rid, reason, policy_ids, verbs, extra.into_iter().collect(), push)
    }

    pub(super) fn deny_with(
        &self,
        rid: &RequestId,
        reason: Reason,
        policy_ids: Vec<String>,
        verbs: &[String],
        extra: Vec<(&str, serde_json::Value)>,
        push: Option<&PushInfo>,
    ) -> Response<RespBody> {
        self.ctx.stats.denied.fetch_add(1, Ordering::Relaxed);
        let approval = extra.iter().find(|(k, _)| *k == "approval").and_then(|(_, v)| v.as_str().map(str::to_string));
        let mut ev = self
            .base_event(EventKind::RequestDecision, rid, verbs)
            .deny(reason, policy_ids)
            .detail("labels", self.labels_detail());
        for (k, v) in extra {
            ev = ev.detail(k, v);
        }
        if let Some(p) = push.and_then(|p| p.pack_note.clone()) {
            ev = ev.detail("pack", p);
        }
        if let Err(e) = self.ctx.recorder.append(&ev) {
            eprintln!("brokerd: audit append failed for deny {rid}: {e:#}");
        }
        let mut hint = format!("broker: denied ({}): {}; run `broker why {rid}`", reason.as_str(), reason.explain());
        if let Some(a) = approval {
            // The control socket is unreachable from the sandbox: only the
            // user, outside it, can approve.
            hint.push_str(&format!(
                "; it needs the user's approval: ask them to run `broker approve {a}` outside the sandbox, then retry"
            ));
        }
        if let Some(p) = push.filter(|p| l7::git::receive_pack::wants_report(&p.capabilities)) {
            let rejected: Vec<(String, String)> = p
                .refs
                .iter()
                .map(|r| (r.clone(), format!("broker denied: {} (broker why {rid})", reason.as_str())))
                .collect();
            let body = l7::git::receive_pack::rejection(&p.capabilities, &rejected, &hint);
            return self.local(StatusCode::OK, rid, reason, "application/x-git-receive-pack-result", body);
        }
        let status = match reason {
            Reason::MintFailed | Reason::UpstreamTls | Reason::UpstreamConnectFailed | Reason::AuditUnavailable => {
                StatusCode::BAD_GATEWAY
            }
            Reason::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Reason::HeadTooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Reason::HostHeaderMismatch => StatusCode::MISDIRECTED_REQUEST,
            _ => StatusCode::FORBIDDEN,
        };
        self.local(status, rid, reason, "text/plain; charset=utf-8", format!("{hint}\n").into_bytes())
    }

    pub(super) fn local(
        &self,
        status: StatusCode,
        rid: &RequestId,
        reason: Reason,
        ct: &str,
        body: Vec<u8>,
    ) -> Response<RespBody> {
        let mut r = Response::new(full(body));
        *r.status_mut() = status;
        let h = r.headers_mut();
        h.insert("content-type", HeaderValue::from_str(ct).unwrap_or(HeaderValue::from_static("text/plain")));
        if let Ok(v) = HeaderValue::from_str(rid.as_str()) {
            h.insert("x-broker-request-id", v);
        }
        h.insert("x-broker-reason", HeaderValue::from_static(reason.as_str()));
        h.insert("cache-control", HeaderValue::from_static("no-store"));
        r
    }

    pub(super) fn cut_response(&self, rid: &RequestId, verbs: &[String], status: u16) -> Response<RespBody> {
        let mut ev = self.base_event(EventKind::RequestOutcome, rid, verbs).detail("status", status);
        ev.reason = Some(Reason::SecretReflected);
        let _ = self.ctx.recorder.append(&ev);
        self.local(
            StatusCode::BAD_GATEWAY,
            rid,
            Reason::SecretReflected,
            "text/plain; charset=utf-8",
            format!(
                "broker: the upstream response reflected an injected secret and was withheld; run `broker why {rid}`\n"
            )
            .into_bytes(),
        )
    }
}

/// Counts response bytes and appends the outcome row when the body ends
/// (or is dropped, for example when the filter cut it).
pub(super) struct OutcomeBody {
    pub(super) inner: RespBody,
    pub(super) bytes: u64,
    pub(super) ev: Option<AuditEvent>,
    pub(super) recorder: Arc<dyn Recorder>,
    pub(super) cut: Arc<AtomicBool>,
}

impl http_body::Body for OutcomeBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, BoxError>>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_frame(cx);
        if let std::task::Poll::Ready(Some(Ok(f))) = &r
            && let Some(d) = f.data_ref()
        {
            self.bytes += d.len() as u64;
        }
        r
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for OutcomeBody {
    fn drop(&mut self) {
        if let Some(mut ev) = self.ev.take() {
            ev = ev.detail("bytes_in", self.bytes);
            if self.cut.load(Ordering::SeqCst) {
                ev.reason = Some(Reason::SecretReflected);
            }
            if let Err(e) = self.recorder.append(&ev) {
                eprintln!("brokerd: audit append failed for outcome: {e:#}");
            }
        }
    }
}
