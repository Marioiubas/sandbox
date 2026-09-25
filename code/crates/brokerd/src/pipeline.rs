//! The L4 egress pipeline, in one function so the order can be reviewed in
//! one place (Request and Session Lifecycle, steps 3-5):
//!
//! 1. ingress handshake (CONNECT or SOCKS5; session sentinel on loopback);
//! 2. canonicalise the destination bytes (I6), reject what cannot be;
//! 3. admit the canonical name and port against the egress grants;
//! 4. resolve **only** admitted names, in the broker (no query otherwise);
//! 5. admit every resolved address (metadata, private, loopback... denied);
//! 6. append the allow decision to the audit chain *before* connecting (I9);
//! 7. connect to exactly an admitted address;
//! 8. require a TLS ClientHello whose SNI canonicalises to the same host;
//! 9. splice, then append the outcome — or, when a grant for the host has
//!    L7 rules or a credential, hand the tunnel to the L7 path
//!    (`l7_pipeline`), which terminates TLS and authorizes each request.
//!
//! Every deny is appended with a reason before the client gets the reply,
//! and an audit failure turns an allow into a deny.

use crate::l7_pipeline::{self, L7Ctx};
use audit::event::describe_raw_host;
use audit::{AuditEvent, Dest, EventKind, Reason, Recorder, RequestId, SessionId};
use netguard::ingress::{self, ChannelAuth, IngressKind, IngressReject};
use netguard::resolver::PolicyResolver;
use netguard::{CanonicalHost, canon_host};
use policy::{EgressPolicy, PathChoice};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tls::sni_peek::{MAX_HELLO, Peek, peek};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;

#[derive(Debug, Default)]
pub struct Stats {
    pub connections: AtomicU64,
    pub allowed: AtomicU64,
    pub denied: AtomicU64,
    pub bytes_out: AtomicU64,
    pub bytes_in: AtomicU64,
}

impl Stats {
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "connections": self.connections.load(Ordering::Relaxed),
            "allowed": self.allowed.load(Ordering::Relaxed),
            "denied": self.denied.load(Ordering::Relaxed),
            "bytes_out": self.bytes_out.load(Ordering::Relaxed),
            "bytes_in": self.bytes_in.load(Ordering::Relaxed),
        })
    }
}

pub struct PipelineCtx {
    pub session: SessionId,
    pub enduser: String,
    /// The end user's IdP groups (on every row).
    pub groups: Vec<String>,
    pub agent: String,
    pub sandbox: String,
    pub policy: Arc<EgressPolicy>,
    pub resolver: Arc<dyn PolicyResolver>,
    pub recorder: Arc<dyn Recorder>,
    pub auth: ChannelAuth,
    pub stats: Arc<Stats>,
    pub connect_timeout: Duration,
    pub sni_timeout: Duration,
    /// Session CA, credentials and upstream TLS for terminated hosts. When
    /// absent, a host that needs L7 is denied (never spliced unchecked).
    pub l7: Option<Arc<L7Ctx>>,
    /// Shadow mode: the candidate policy, evaluated and logged, never applied.
    pub shadow: Option<Arc<EgressPolicy>>,
    /// Agent sessions with pinned MCP servers (MCP Guard); `None` for an
    /// MCP server's own session and for sessions without servers.
    pub mcp: Option<Arc<crate::mcp::McpCtx>>,
}

/// What happened to one connection (returned for tests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Denied {
        request_id: RequestId,
        reason: Reason,
    },
    Spliced {
        request_id: RequestId,
        bytes_out: u64,
        bytes_in: u64,
    },
    /// Terminated on the L7 path; each request has its own decision row.
    Terminated {
        request_id: RequestId,
        requests: u64,
    },
}

impl PipelineCtx {
    pub(crate) fn event(&self, kind: EventKind, rid: &RequestId) -> AuditEvent {
        let mut ev = AuditEvent::new(kind).session(&self.session).request(rid);
        ev.enduser = Some(self.enduser.clone());
        ev.enduser_groups = self.groups.clone();
        ev.agent = Some(self.agent.clone());
        ev.sandbox = Some(self.sandbox.clone());
        ev
    }
}

fn dest_for(
    kind: Option<IngressKind>,
    host: Option<&CanonicalHost>,
    raw: Option<&[u8]>,
    port: Option<u16>,
    addrs: &[IpAddr],
) -> Dest {
    Dest {
        ingress: kind.map(|k| k.as_str().to_string()),
        host: host.map(|h| h.as_str().to_string()).or_else(|| raw.map(describe_raw_host)),
        registrable: host.and_then(|h| h.registrable().map(str::to_string)),
        port,
        addrs: addrs.iter().map(|a| a.to_string()).collect(),
    }
}

async fn deny<S: AsyncWrite + Unpin>(
    ctx: &PipelineCtx,
    client: &mut S,
    kind: Option<IngressKind>,
    rid: RequestId,
    reason: Reason,
    dest: Dest,
    policy_ids: Vec<String>,
) -> Outcome {
    deny_noted(ctx, client, kind, rid, reason, dest, policy_ids, None).await
}

/// A deny carrying the shadow candidate's verdict.
#[allow(clippy::too_many_arguments)]
async fn deny_noted<S: AsyncWrite + Unpin>(
    ctx: &PipelineCtx,
    client: &mut S,
    kind: Option<IngressKind>,
    rid: RequestId,
    reason: Reason,
    dest: Dest,
    policy_ids: Vec<String>,
    shadow: Option<serde_json::Value>,
) -> Outcome {
    ctx.stats.denied.fetch_add(1, Ordering::Relaxed);
    let mut ev = ctx.event(EventKind::RequestDecision, &rid).deny(reason, policy_ids).dest(dest);
    if let Some(s) = shadow {
        ev = ev.detail("shadow", s);
    }
    if let Err(e) = ctx.recorder.append(&ev) {
        // The deny stands either way; the missing row is itself reported.
        eprintln!("brokerd: audit append failed for deny {rid}: {e:#}");
    }
    let _ = ingress::reply_deny(client, kind, reason, &rid).await;
    Outcome::Denied { request_id: rid, reason }
}

pub async fn handle<S>(ctx: &Arc<PipelineCtx>, mut client: S) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ctx.stats.connections.fetch_add(1, Ordering::Relaxed);
    let rid = RequestId::new();

    // 1. Handshake.
    let raw = match ingress::handshake(&mut client, &ctx.auth).await {
        Ok(d) => d,
        Err(IngressReject { kind, reason, host_bytes }) => {
            let dest = dest_for(kind, None, host_bytes.as_deref(), None, &[]);
            return deny(ctx, &mut client, kind, rid, reason, dest, vec![]).await;
        }
    };
    let kind = Some(raw.kind);

    // 2. Canonicalise (the only way to a CanonicalHost).
    let canon = match raw.binary_addr {
        Some(ip) => CanonicalHost::from_ip(ip),
        None => canon_host(&raw.host_bytes),
    };
    let host = match canon {
        Ok(h) => h,
        Err(rej) => {
            let dest = dest_for(kind, None, Some(&raw.host_bytes), Some(raw.port), &[]);
            return deny(ctx, &mut client, kind, rid, rej.reason(), dest, vec![]).await;
        }
    };

    // 2b. MCP Guard: a pinned server by name, over this session's proxy.
    // Reserved names never reach admission, DNS or the network.
    if host.as_str().ends_with(crate::mcp::RESERVED_SUFFIX) {
        let dest = dest_for(kind, Some(&host), None, Some(raw.port), &[]);
        let Some(name) = crate::mcp::server_for(ctx, &host, raw.port).map(str::to_string) else {
            return deny(ctx, &mut client, kind, rid, Reason::McpServerUnknown, dest, vec![]).await;
        };
        if ingress::reply_ok(&mut client, raw.kind).await.is_err() {
            return Outcome::Terminated { request_id: rid, requests: 0 };
        }
        return crate::mcp::serve(ctx.clone(), name, client, raw.kind).await;
    }

    // 3. Name and port admission. No network I/O has happened yet.
    let mut adm = match ctx.policy.admit_host(&host, raw.port) {
        Ok(a) => a,
        Err((reason, ids)) => {
            let dest = dest_for(kind, Some(&host), None, Some(raw.port), &[]);
            let sh = ctx.shadow.as_ref().map(|s| {
                crate::shadow::note(&crate::shadow::admission(s, &host, raw.port, None).map(|_| ()), false, false)
            });
            return deny_noted(ctx, &mut client, kind, rid, reason, dest, ids, sh).await;
        }
    };

    // 4. Broker-owned resolution, only for admitted names.
    let addrs = if !adm.pinned.is_empty() {
        adm.pinned.clone()
    } else {
        match ctx.resolver.resolve(&host).await {
            Ok(a) => a,
            Err(reason) => {
                let dest = dest_for(kind, Some(&host), None, Some(raw.port), &[]);
                return deny(ctx, &mut client, kind, rid, reason, dest, adm.policy_ids.clone()).await;
            }
        }
    };

    // 5. Every resolved address must be of an admitted class.
    let shadow_verdict = ctx.shadow.as_ref().map(|s| crate::shadow::admission(s, &host, raw.port, Some(&addrs)));
    let shadow_note = |applied: bool| {
        shadow_verdict.as_ref().map(|v| crate::shadow::note(&v.as_ref().map(|_| ()).map_err(|r| *r), applied, true))
    };
    if let Err((reason, _bad)) = ctx.policy.admit_addrs(&mut adm, &addrs) {
        let dest = dest_for(kind, Some(&host), None, Some(raw.port), &addrs);
        return deny_noted(ctx, &mut client, kind, rid, reason, dest, adm.policy_ids.clone(), shadow_note(false)).await;
    }

    // 6. Write-ahead audit of the allow.
    let dest = dest_for(kind, Some(&host), None, Some(raw.port), &addrs);
    let mut allow_ev = ctx.event(EventKind::RequestDecision, &rid).allow(adm.policy_ids.clone()).dest(dest.clone());
    if let Some(w) = adm.would_deny {
        // Record mode: what enforce mode would have decided (for the learner).
        allow_ev = allow_ev.audit_mode().detail("would_deny", w.as_str());
    }
    if let Some(s) = shadow_note(true) {
        allow_ev = allow_ev.detail("shadow", s);
    }
    if ctx.recorder.append(&allow_ev).is_err() {
        return deny(ctx, &mut client, kind, rid, Reason::AuditUnavailable, dest, adm.policy_ids.clone()).await;
    }

    // 7. Connect to exactly an admitted address (IPv4 first).
    let mut ordered = addrs.clone();
    ordered.sort_by_key(|a| a.is_ipv6());
    let mut upstream = None;
    for a in &ordered {
        let sa = SocketAddr::new(*a, raw.port);
        if let Ok(Ok(s)) = tokio::time::timeout(ctx.connect_timeout, TcpStream::connect(sa)).await {
            // Relay writes at once. With Nagle, a small write after another
            // (TLS handshake records) waits for the upstream's delayed ACK,
            // which added ~50 ms to every new connection on Linux.
            let _ = s.set_nodelay(true);
            upstream = Some(s);
            break;
        }
    }
    let Some(mut upstream) = upstream else {
        return deny(ctx, &mut client, kind, rid, Reason::UpstreamConnectFailed, dest, adm.policy_ids.clone()).await;
    };
    if ingress::reply_ok(&mut client, raw.kind).await.is_err() {
        return Outcome::Denied { request_id: rid, reason: Reason::MalformedRequest };
    }

    // 8. The tunnel must start with a ClientHello whose SNI is this host
    //    (domain fronting, non-TLS protocols and SNI-less tunnels denied).
    let mut buf = raw.leftover;
    let sni_result = tokio::time::timeout(ctx.sni_timeout, async {
        loop {
            match peek(&buf) {
                Peek::Incomplete => {
                    if buf.len() > MAX_HELLO + 64 {
                        return Peek::Malformed("too large");
                    }
                    let mut chunk = [0u8; 4096];
                    match client.read(&mut chunk).await {
                        Ok(0) | Err(_) => return Peek::Malformed("closed before ClientHello"),
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                other => return other,
            }
        }
    })
    .await
    .unwrap_or(Peek::Malformed("timeout waiting for ClientHello"));
    let sni_reason = match &sni_result {
        Peek::Hello { sni: Some(name) } => match canon_host(name) {
            Ok(sni_host) if sni_host == host => None,
            Ok(_) => Some(Reason::ConnectSniMismatch),
            Err(_) => Some(Reason::ConnectSniMismatch),
        },
        // TLS to an explicitly granted IP literal carries no SNI.
        Peek::Hello { sni: None } if host.is_ip_literal() => None,
        _ => Some(Reason::SniLess),
    };
    if let Some(reason) = sni_reason {
        ctx.stats.denied.fetch_add(1, Ordering::Relaxed);
        let ev = ctx.event(EventKind::RequestDecision, &rid).deny(reason, adm.policy_ids.clone()).dest(dest);
        let _ = ctx.recorder.append(&ev);
        // The tunnel is already "established" from the client's view; close it.
        drop(upstream);
        return Outcome::Denied { request_id: rid, reason };
    }

    // 9a. Hosts with L7 rules or credentials are terminated, never spliced.
    if ctx.policy.path_choice(&adm) == PathChoice::L7 {
        let Some(l7) = ctx.l7.clone() else {
            ctx.stats.denied.fetch_add(1, Ordering::Relaxed);
            let ev = ctx
                .event(EventKind::RequestDecision, &rid)
                .deny(Reason::L7NoRuleMatched, adm.policy_ids.clone())
                .dest(dest)
                .detail("l7", "unavailable");
            let _ = ctx.recorder.append(&ev);
            return Outcome::Denied { request_id: rid, reason: Reason::L7NoRuleMatched };
        };
        let shadow_adm = shadow_verdict;
        return l7_pipeline::serve(
            ctx.clone(),
            l7,
            client,
            buf,
            upstream,
            host,
            raw.port,
            adm,
            addrs,
            dest,
            rid,
            shadow_adm,
        )
        .await;
    }

    // 9b. Splice and record the outcome.
    ctx.stats.allowed.fetch_add(1, Ordering::Relaxed);
    let stats = netguard::splice::splice(&mut client, &mut upstream, &buf).await.unwrap_or_default();
    ctx.stats.bytes_out.fetch_add(stats.bytes_out, Ordering::Relaxed);
    ctx.stats.bytes_in.fetch_add(stats.bytes_in, Ordering::Relaxed);
    let out = ctx
        .event(EventKind::RequestOutcome, &rid)
        .dest(dest)
        .detail("bytes_out", stats.bytes_out)
        .detail("bytes_in", stats.bytes_in);
    if let Err(e) = ctx.recorder.append(&out) {
        eprintln!("brokerd: audit append failed for outcome {rid}: {e:#}");
    }
    Outcome::Spliced { request_id: rid, bytes_out: stats.bytes_out, bytes_in: stats.bytes_in }
}
