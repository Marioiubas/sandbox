//! The L7 path (TLS Termination and Per-Session CA), per request, in one
//! place so the order can be reviewed:
//!
//! - (1) terminate TLS with a per-session-CA leaf for exactly the admitted host;
//! - (2) CONNECT host = SNI = `Host` (canonical values), canonical path;
//! - (3) classify with the protocol adapter (git receive-pack bodies parsed);
//! - (5a) inspect client credentials: only this session's sentinel for this
//!   host is acceptable; anything else is a foreign credential (I7);
//! - (4) authorize every action; unmatched requests deny (ADR-006);
//! - (6) mint or load the bound credential (only with an `AllowedBinding`);
//!   append the decision before forwarding (I9);
//! - (5b) strip every client credential; attach the broker's;
//! - (7) forward over verified TLS to an admitted address;
//! - (8) filter the response: no injected secret flows back (I1), no cookies.
//!
//! The broker does not follow redirects: the client's next request is a
//! new request through this pipeline, evaluated from step 1 (and a
//! cross-origin hop reaches a host whose rules carry no credential).

use crate::pipeline::{Outcome, PipelineCtx};
use crate::rewind::Rewind;
use crate::upstream;
use audit::{AuditEvent, Dest, EventKind, Reason, Recorder, RequestId};
use bytes::Bytes;
use creds::SessionCreds;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::{TokioIo, TokioTimer};
use l7::filter::{BoxError, FilteredBody};
use l7::git::PushInfo;
use netguard::CanonicalHost;
use policy::Admission;
use policy::l7::Protocol;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

/// Largest request body the broker buffers for inspection (git pushes,
/// body sentinel swap). Larger bodies are denied, not streamed unchecked.
pub const MAX_INSPECTED_BODY: usize = 256 << 20;

type ReqBody = UnsyncBoxBody<Bytes, BoxError>;
type RespBody = UnsyncBoxBody<Bytes, BoxError>;

/// Per-session L7 state.
pub struct L7Ctx {
    pub ca: Arc<tls::session_ca::SessionCa>,
    pub upstream_tls: Arc<rustls::ClientConfig>,
    pub creds: Arc<SessionCreds>,
    /// The macOS loopback proxy sentinel, tolerated (and stripped) if a
    /// client repeats it inside the tunnel.
    pub channel_sentinel: Option<Vec<u8>>,
    pub max_body: usize,
}

struct Upstream {
    first: Option<TcpStream>,
    sender: Option<SendRequest<ReqBody>>,
}

struct Conn {
    ctx: Arc<PipelineCtx>,
    l7: Arc<L7Ctx>,
    host: CanonicalHost,
    port: u16,
    adm: Admission,
    addrs: Vec<IpAddr>,
    dest: Dest,
    protocols: BTreeSet<Protocol>,
    upstream: tokio::sync::Mutex<Upstream>,
    requests: AtomicU64,
}

fn full(b: impl Into<Bytes>) -> RespBody {
    Full::new(b.into()).map_err(|n: Infallible| match n {}).boxed_unsync()
}

/// Serve one terminated tunnel. `peeked` holds the ClientHello bytes.
#[allow(clippy::too_many_arguments)]
pub async fn serve<S>(
    ctx: Arc<PipelineCtx>,
    l7: Arc<L7Ctx>,
    client: S,
    peeked: Vec<u8>,
    upstream_tcp: TcpStream,
    host: CanonicalHost,
    port: u16,
    adm: Admission,
    addrs: Vec<IpAddr>,
    dest: Dest,
    conn_rid: RequestId,
) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let cfg = match l7.ca.server_config(&host) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("brokerd: leaf for {host}: {e:#}");
            return Outcome::Denied { request_id: conn_rid, reason: Reason::UpstreamTls };
        }
    };
    let accepted =
        tokio::time::timeout(Duration::from_secs(15), TlsAcceptor::from(cfg).accept(Rewind::new(peeked, client))).await;
    let tls = match accepted {
        Ok(Ok(s)) => s,
        _ => {
            // The client did not complete TLS with the session CA (it may not
            // trust the bundle). Nothing was forwarded.
            let ev = ctx.event(EventKind::RequestOutcome, &conn_rid).dest(dest).detail("client_tls", "failed");
            let _ = ctx.recorder.append(&ev);
            return Outcome::Terminated { request_id: conn_rid, requests: 0 };
        }
    };
    let protocols = ctx.policy.protocols(&adm);
    let conn = Arc::new(Conn {
        ctx,
        l7,
        host,
        port,
        adm,
        addrs,
        dest,
        protocols,
        upstream: tokio::sync::Mutex::new(Upstream { first: Some(upstream_tcp), sender: None }),
        requests: AtomicU64::new(0),
    });
    let c2 = conn.clone();
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let c = c2.clone();
        async move { Ok::<_, Infallible>(c.handle(req).await) }
    });
    let served = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(60))
        .max_buf_size(256 << 10)
        .keep_alive(true)
        .serve_connection(TokioIo::new(tls), svc)
        .await;
    // Requests hyper refused to parse (ambiguous framing, bad bytes) never
    // reached `handle`; they are still denies and are logged as such.
    if let Err(e) = served
        && e.is_parse()
    {
        let rid = RequestId::new();
        conn.ctx.stats.denied.fetch_add(1, Ordering::Relaxed);
        let ev = conn
            .base_event(EventKind::RequestDecision, &rid, &[])
            .deny(Reason::MalformedRequest, vec![])
            .detail("http_error", e.to_string())
            .detail("connection", conn_rid.as_str());
        if let Err(e) = conn.ctx.recorder.append(&ev) {
            eprintln!("brokerd: audit append failed for parse deny {rid}: {e:#}");
        }
    }
    Outcome::Terminated { request_id: conn_rid, requests: conn.requests.load(Ordering::Relaxed) }
}

/// Decode a request body for inspection (identity or gzip only).
fn decode_body(headers: &http::HeaderMap, raw: &Bytes, max: usize) -> Result<Vec<u8>, Reason> {
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

async fn collect(body: Incoming, max: usize) -> Result<Bytes, Reason> {
    match Limited::new(body, max).collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() => Err(Reason::BodyTooLarge),
        Err(_) => Err(Reason::MalformedRequest),
    }
}

impl Conn {
    fn authority(&self) -> String {
        if self.port == 443 { self.host.as_str().to_string() } else { format!("{}:{}", self.host, self.port) }
    }

    fn base_event(&self, kind: EventKind, rid: &RequestId, verbs: &[String]) -> AuditEvent {
        let mut ev = self.ctx.event(kind, rid).dest(self.dest.clone()).detail("layer", "l7");
        if !verbs.is_empty() {
            ev = ev.detail("verb", verbs.join("; "));
        }
        ev
    }

    /// Record a deny and answer the client (git-native for pushes).
    fn deny(
        &self,
        rid: &RequestId,
        reason: Reason,
        policy_ids: Vec<String>,
        verbs: &[String],
        extra: Option<(&str, String)>,
        push: Option<&PushInfo>,
    ) -> Response<RespBody> {
        self.ctx.stats.denied.fetch_add(1, Ordering::Relaxed);
        let mut ev = self.base_event(EventKind::RequestDecision, rid, verbs).deny(reason, policy_ids);
        if let Some((k, v)) = extra {
            ev = ev.detail(k, v);
        }
        if let Some(p) = push.and_then(|p| p.pack_note.clone()) {
            ev = ev.detail("pack", p);
        }
        if let Err(e) = self.ctx.recorder.append(&ev) {
            eprintln!("brokerd: audit append failed for deny {rid}: {e:#}");
        }
        let hint = format!("broker: denied ({}): {}; run `broker why {rid}`", reason.as_str(), reason.explain());
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

    fn local(
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

    async fn handle(self: &Arc<Self>, req: Request<Incoming>) -> Response<RespBody> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let rid = RequestId::new();
        let (mut parts, body) = req.into_parts();

        // 2. Host/SNI/CONNECT agreement and the canonical path.
        let path = match l7::head::check(&parts, &self.host, self.port) {
            Ok(p) => p,
            Err(r) => return self.deny(&rid, r, vec![], &[], None, None),
        };
        let method = parts.method.as_str().to_string();
        let plan = l7::classify::plan(&self.protocols, &self.host, self.port, &method, path.path(), path.query());

        // 5a. Client credentials: sentinels for this host only (I7).
        let sentinels = &self.l7.creds.sentinels;
        let uses = match creds::inspect(
            &parts.headers,
            path.query(),
            sentinels,
            &self.host,
            self.l7.channel_sentinel.as_deref(),
        ) {
            Ok(u) => u,
            Err(rej) => {
                let verb = format!("http {method} {}", path.path());
                return self.deny(&rid, rej.reason, vec![], &[verb], Some(("credential_location", rej.location)), None);
            }
        };

        // 3. Classify (buffering the body only when the adapter must read it).
        let mut body = Some(body);
        let mut buffered: Option<Bytes> = None;
        let decoded = if plan.needs_body() {
            let raw = match collect(body.take().expect("body"), self.l7.max_body).await {
                Ok(b) => b,
                Err(r) => return self.deny(&rid, r, vec![], &[], None, None),
            };
            let d = match decode_body(&parts.headers, &raw, self.l7.max_body) {
                Ok(d) => d,
                Err(r) => return self.deny(&rid, r, vec![], &[], None, None),
            };
            buffered = Some(raw);
            Some(d)
        } else {
            None
        };
        let (actions, push) = match l7::classify::actions(&plan, decoded.as_deref()) {
            Ok(a) => a,
            Err(r) => return self.deny(&rid, r, vec![], &[], None, None),
        };
        drop(decoded);
        let verbs: Vec<String> = actions.iter().map(|a| a.verb()).collect();

        // 4. Authorize: every action must be allowed.
        let dec = self.ctx.policy.authorize_l7(&self.adm, &actions);
        if let Err(reason) = dec.result {
            let per: Vec<String> = dec
                .actions
                .iter()
                .map(|(v, r)| format!("{v} => {}", r.map(|_| "allow").unwrap_or_else(|e| e.as_str())))
                .collect();
            return self.deny(&rid, reason, dec.policy_ids, &per, None, push.as_ref());
        }

        // 6. Credential: only through the binding the decision produced.
        let issued = match &dec.binding {
            None => None,
            Some(b) => match self.l7.creds.get(b).await {
                Ok((i, reused)) => Some((i, reused, b.credential().attach.clone(), b.credential().swap_body)),
                Err(e) => {
                    return self.deny(
                        &rid,
                        Reason::MintFailed,
                        dec.policy_ids,
                        &verbs,
                        Some(("error", e.to_string())),
                        push.as_ref(),
                    );
                }
            },
        };

        // Write-ahead audit of the allow (I9): no row, no request.
        let mut ev = self.base_event(EventKind::RequestDecision, &rid, &verbs).allow(dec.policy_ids.clone());
        if let Some((i, reused, _, _)) = &issued {
            ev = ev
                .detail("credential_id", i.credential_id.as_str())
                .detail("credential_kind", i.kind)
                .detail("credential_origin", if *reused { "reuse" } else { i.origin })
                .detail("credential_fp", i.fingerprint());
        }
        if !uses.is_empty() {
            ev = ev.detail("sentinels_presented", uses.iter().map(|u| u.credential_id.clone()).collect::<Vec<_>>());
        }
        if let Some(p) = push.as_ref().and_then(|p| p.pack_note.clone()) {
            ev = ev.detail("pack", p);
        }
        if self.ctx.recorder.append(&ev).is_err() {
            return self.deny(&rid, Reason::AuditUnavailable, dec.policy_ids, &verbs, None, push.as_ref());
        }
        self.ctx.stats.allowed.fetch_add(1, Ordering::Relaxed);

        // 5b. Strip client credentials and hop-by-hop headers; attach ours.
        let query = creds::strip(&mut parts.headers, path.query());
        l7::head::strip_hop_by_hop(&mut parts.headers);
        parts.headers.remove(http::header::EXPECT);
        parts.headers.remove(http::header::HOST);
        parts
            .headers
            .insert(http::header::HOST, HeaderValue::from_str(&self.authority()).expect("canonical authority"));
        let target = match &query {
            Some(q) => format!("{}?{q}", path.path()),
            None => path.path().to_string(),
        };
        parts.uri = match target.parse() {
            Ok(u) => u,
            Err(_) => return self.deny(&rid, Reason::NonCanonicalPath, vec![], &verbs, None, None),
        };
        parts.version = http::Version::HTTP_11;
        let mut needles: Vec<Vec<u8>> = Vec::new();
        if let Some((i, _, spec, _)) = &issued {
            if creds::attach(i, spec, &mut parts.headers).is_err() {
                return self.deny(&rid, Reason::MintFailed, vec![], &verbs, None, None);
            }
            needles = creds::issuers::needles(i, spec);
            // Ask for an encoding the response filter can read.
            parts.headers.insert(http::header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        }

        // Body: buffered (inspected or swapped) or streamed as received.
        let swap = issued.as_ref().filter(|(_, _, _, swap)| *swap);
        let req_body: ReqBody = match (buffered, swap) {
            (b, Some((i, _, _, _))) => {
                let raw = match b {
                    Some(b) => b,
                    None => match collect(body.take().expect("body"), self.l7.max_body).await {
                        Ok(b) => b,
                        Err(r) => return self.deny(&rid, r, vec![], &verbs, None, None),
                    },
                };
                let (swapped, _) = sentinels.swap_in_body(&raw, &i.credential_id, i.secret().expose());
                parts.headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(swapped.len()));
                parts.headers.remove(http::header::CONTENT_ENCODING);
                Full::new(Bytes::from(swapped)).map_err(|n: Infallible| match n {}).boxed_unsync()
            }
            (Some(b), None) => {
                parts.headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from(b.len()));
                Full::new(b).map_err(|n: Infallible| match n {}).boxed_unsync()
            }
            (None, None) => body.take().expect("body").map_err(|e| Box::new(e) as BoxError).boxed_unsync(),
        };

        // 7. Forward over verified TLS.
        let resp = match self.send(Request::from_parts(parts, req_body)).await {
            Ok(r) => r,
            Err(reason) => return self.deny(&rid, reason, vec![], &verbs, None, None),
        };

        // 8. Response filter.
        let (mut rparts, rbody) = resp.into_parts();
        let status = rparts.status.as_u16();
        l7::head::strip_hop_by_hop(&mut rparts.headers);
        rparts.headers.remove(http::header::SET_COOKIE);
        rparts.headers.remove("set-cookie2");
        rparts.headers.remove(http::header::ALT_SVC);
        let needles = Arc::new(needles);
        if !needles.is_empty() && l7::filter::headers_contain(&rparts.headers, &needles) {
            return self.cut_response(&rid, &verbs, status);
        }
        let coding = match l7::filter::coding(&rparts.headers) {
            Some(c) => c,
            None if needles.is_empty() => l7::filter::Coding::Identity,
            None => return self.deny(&rid, Reason::UnsupportedEncoding, vec![], &verbs, None, None),
        };
        let cut = Arc::new(AtomicBool::new(false));
        let redirect = rparts.headers.get(http::header::LOCATION).and_then(|v| v.to_str().ok()).map(str::to_string);
        let mut out = self.base_event(EventKind::RequestOutcome, &rid, &[]).detail("status", status);
        if let Some(l) = redirect {
            // Logged, not followed: the client's next request is evaluated afresh.
            out = out.detail("redirect", audit::event::describe_raw_host(l.as_bytes()));
        }
        let filtered: RespBody = if needles.is_empty() {
            rbody.map_err(|e| Box::new(e) as BoxError).boxed_unsync()
        } else {
            FilteredBody::new(rbody, needles, coding, cut.clone()).boxed_unsync()
        };
        let body = OutcomeBody { inner: filtered, bytes: 0, ev: Some(out), recorder: self.ctx.recorder.clone(), cut };
        Response::from_parts(rparts, body.boxed_unsync())
    }

    fn cut_response(&self, rid: &RequestId, verbs: &[String], status: u16) -> Response<RespBody> {
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

    async fn send(&self, req: Request<ReqBody>) -> Result<Response<Incoming>, Reason> {
        let mut up = self.upstream.lock().await;
        if up.sender.as_ref().is_none_or(|s| s.is_closed()) {
            let tcp = match up.first.take() {
                Some(t) => t,
                None => upstream::connect_addrs(&self.addrs, self.port).await.ok_or(Reason::UpstreamConnectFailed)?,
            };
            let tls = upstream::tls_connect(&self.l7.upstream_tls, &self.host, tcp).await?;
            let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .map_err(|_| Reason::UpstreamConnectFailed)?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            up.sender = Some(sender);
        }
        let s = up.sender.as_mut().ok_or(Reason::UpstreamConnectFailed)?;
        s.ready().await.map_err(|_| Reason::UpstreamConnectFailed)?;
        s.send_request(req).await.map_err(|_| Reason::UpstreamConnectFailed)
    }
}

/// Counts response bytes and appends the outcome row when the body ends
/// (or is dropped, for example when the filter cut it).
struct OutcomeBody {
    inner: RespBody,
    bytes: u64,
    ev: Option<AuditEvent>,
    recorder: Arc<dyn Recorder>,
    cut: Arc<AtomicBool>,
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
