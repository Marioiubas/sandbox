//! The MCP relay (MCP Guard): the daemon pins the server's manifest before
//! relaying anything, answers `initialize` and `tools/list` itself from the
//! pinned state, authorizes each `tools/call` (write-ahead audit, then
//! labels, then forward), and refuses what it does not relay: other
//! methods, server-to-client requests (sampling, roots, elicitation) and
//! any frame that is not strict JSON-RPC 2.0 on one line.

use super::pin::{self, Manifest};
use crate::pipeline::PipelineCtx;
use audit::{Dest, EventKind, Reason, RequestId};
use mcpguard::frame::{Frame, Kind, Lines, classify};
use policy::github::Label;
use policy::mcp::McpServerConfig;
use serde_json::{Value, json};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

const PIN_TIMEOUT: Duration = Duration::from_secs(20);
const DRAIN: Duration = Duration::from_secs(20);
/// JSON-RPC error code for a broker denial.
const DENIED: i64 = -32020;

pub(super) enum Pin {
    Pinned(Manifest),
    Unapproved(Manifest),
    Changed { expected: String, got: Manifest, diff: Vec<String> },
    Failed(String),
}

impl Pin {
    fn reason(&self) -> Option<Reason> {
        match self {
            Pin::Pinned(_) => None,
            Pin::Unapproved(_) => Some(Reason::McpManifestUnapproved),
            Pin::Changed { .. } => Some(Reason::McpManifestChanged),
            Pin::Failed(_) => Some(Reason::McpLaunchFailed),
        }
    }
}

/// A stream of frames, each bounded by `mcpguard::frame::MAX_FRAME`.
pub(super) struct FrameReader<R> {
    r: R,
    lines: Lines,
    queue: VecDeque<Frame>,
}

impl<R: AsyncBufRead + Unpin> FrameReader<R> {
    pub fn new(r: R) -> Self {
        FrameReader { r, lines: Lines::default(), queue: VecDeque::new() }
    }

    /// The next frame: `Ok(None)` at end of stream, `Ok(Some(None))` for an
    /// oversized frame (dropped whole).
    pub async fn next(&mut self) -> std::io::Result<Option<Option<Vec<u8>>>> {
        let open = |f: Frame| match f {
            Frame::Line(b) => Some(b),
            Frame::TooLong => None,
        };
        loop {
            if let Some(f) = self.queue.pop_front() {
                return Ok(Some(open(f)));
            }
            let avail = self.r.fill_buf().await?;
            if avail.is_empty() {
                return Ok(self.lines.finish().map(open));
            }
            let n = avail.len();
            let frames = self.lines.push(avail);
            self.queue.extend(frames);
            self.r.consume(n);
        }
    }
}

pub(super) async fn send<W: AsyncWrite + Unpin>(w: &mut W, v: &Value) -> std::io::Result<()> {
    let mut line = v.to_string().into_bytes();
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await
}

fn parse(bytes: &[u8]) -> Option<Value> {
    match classify(bytes) {
        (Kind::Malformed, _) => None,
        (_, v) => v,
    }
}

/// Initialize the server and read its tools (every page) before anything
/// from the agent is relayed. Server requests during the handshake are
/// refused (their methods are returned for the audit); notifications are
/// dropped.
pub(super) async fn handshake<R, W>(r: &mut FrameReader<R>, w: &mut W) -> Result<(Value, Manifest, Vec<String>), String>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    async fn call<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        r: &mut FrameReader<R>,
        w: &mut W,
        id: &str,
        method: &str,
        params: Value,
        refused: &mut Vec<String>,
    ) -> Result<Value, String> {
        send(w, &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await
            .map_err(|e| format!("writing to the server: {e}"))?;
        loop {
            let line = r.next().await.map_err(|e| format!("reading the server: {e}"))?;
            let Some(Some(b)) = line else { return Err("the server closed or sent an oversized frame".into()) };
            let Some(v) = parse(&b) else { continue };
            if let Some(m) = v.get("method").and_then(|m| m.as_str()) {
                if let Some(sid) = v.get("id") {
                    refused.push(m.to_string());
                    let _ = send(w, &refusal(sid.clone())).await;
                }
                continue;
            }
            if v.get("id").and_then(|i| i.as_str()) == Some(id) {
                if let Some(e) = v.get("error") {
                    return Err(format!("{method} failed: {e}"));
                }
                return v.get("result").cloned().ok_or_else(|| format!("{method}: no result"));
            }
        }
    }
    let mut refused = Vec::new();
    let init = call(
        r,
        w,
        "broker-init",
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "broker", "version": env!("CARGO_PKG_VERSION")}}),
        &mut refused,
    )
    .await?;
    send(w, &json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await.map_err(|e| e.to_string())?;
    let mut tools = Vec::new();
    let mut cursor: Option<Value> = None;
    for page in 0..20 {
        let params = match &cursor {
            Some(c) => json!({"cursor": c}),
            None => json!({}),
        };
        let res = call(r, w, &format!("broker-tools-{page}"), "tools/list", params, &mut refused).await?;
        tools.extend(res.get("tools").and_then(|t| t.as_array()).cloned().ok_or("tools/list: no tools array")?);
        cursor = res.get("nextCursor").filter(|c| !c.is_null()).cloned();
        if cursor.is_none() {
            return Ok((init, pin::manifest(tools)?, refused));
        }
    }
    Err("tools/list has more than 20 pages".into())
}

fn refusal(id: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id,
           "error": {"code": -32601, "message": "broker: server-to-client requests are not relayed"}})
}

/// The relay's state for one agent connection.
pub(super) struct Relay<'a> {
    pub ctx: &'a Arc<PipelineCtx>,
    pub name: &'a str,
    pub cfg: &'a McpServerConfig,
    pub dest: Dest,
    pub server_session: String,
    pub pin: Pin,
    pub init: Value,
    pub pending: HashSet<String>,
    pub relist: Option<(u32, Vec<Value>)>,
    pub relists: u32,
}

impl Relay<'_> {
    fn event(&self, rid: &RequestId, verb: String) -> audit::AuditEvent {
        self.ctx
            .event(EventKind::RequestDecision, rid)
            .dest(self.dest.clone())
            .detail("layer", "mcp")
            .detail("server", self.name)
            .detail("server_session", self.server_session.as_str())
            .detail("verb", verb)
            .detail("labels", serde_json::to_value(self.ctx.policy.labels().snapshot()).unwrap_or_default())
    }

    /// Log a deny and build the JSON-RPC error the agent receives.
    pub fn deny(&self, id: Option<Value>, reason: Reason, verb: String, extra: Vec<(&str, Value)>) -> Option<Value> {
        let rid = RequestId::new();
        self.ctx.stats.denied.fetch_add(1, Ordering::Relaxed);
        let mut ev = self.event(&rid, verb).deny(reason, vec![]);
        for (k, v) in extra {
            ev = ev.detail(k, v);
        }
        if let Err(e) = self.ctx.recorder.append(&ev) {
            eprintln!("brokerd: audit append failed for mcp deny {rid}: {e:#}");
        }
        id.map(|id| {
            json!({"jsonrpc": "2.0", "id": id, "error": {
                "code": DENIED,
                "message": format!("broker: denied ({}): {}; run `broker why {rid}`", reason.as_str(), reason.explain()),
                "data": {"reason": reason.as_str(), "request_id": rid.as_str()},
            }})
        })
    }

    /// The connect decision (one row per connection).
    pub fn record_connect(&self) {
        let rid = RequestId::new();
        let verb = format!("mcp.connect {}", self.name);
        let ev = match &self.pin {
            Pin::Pinned(m) => {
                self.ctx.stats.allowed.fetch_add(1, Ordering::Relaxed);
                self.event(&rid, verb)
                    .allow(vec![format!("mcp:{}#call", self.name)])
                    .detail("manifest", m.sha256.as_str())
            }
            Pin::Unapproved(m) => self
                .event(&rid, verb)
                .deny(Reason::McpManifestUnapproved, vec![])
                .detail("manifest", m.sha256.as_str())
                .detail("tools", m.tools.len()),
            Pin::Changed { expected, got, diff } => self
                .event(&rid, verb)
                .deny(Reason::McpManifestChanged, vec![])
                .detail("expected", expected.as_str())
                .detail("manifest", got.sha256.as_str())
                .detail("diff", diff.clone()),
            Pin::Failed(m) => self.event(&rid, verb).deny(Reason::McpLaunchFailed, vec![]).detail("error", m.as_str()),
        };
        if let Err(e) = self.ctx.recorder.append(&ev) {
            eprintln!("brokerd: audit append failed for mcp connect: {e:#}");
        }
    }

    /// Handle one agent frame: `(reply to agent, frame for the server)`.
    pub fn on_agent(&mut self, bytes: &[u8]) -> (Option<Value>, Option<Value>) {
        let (kind, v) = classify(bytes);
        let v = match (kind, v) {
            (Kind::Request { id, method }, Some(v)) => return self.request(id, method, v),
            (Kind::Notification { method }, Some(v)) => Some((method, v)),
            (Kind::Response { .. }, _) => return (None, None),
            (_, v) => {
                let id = v.and_then(|v| v.get("id").cloned()).filter(|i| i.is_string() || i.is_i64() || i.is_u64());
                return (self.deny(id, Reason::McpMalformed, "mcp.frame".into(), vec![]), None);
            }
        };
        match v {
            Some((m, v)) if m == "notifications/cancelled" && matches!(self.pin, Pin::Pinned(_)) => (None, Some(v)),
            _ => (None, None),
        }
    }

    fn request(&mut self, id: Value, m: String, v: Value) -> (Option<Value>, Option<Value>) {
        let manifest = match (&self.pin, self.pin.reason()) {
            (Pin::Pinned(man), _) => man.clone(),
            (_, Some(r)) => return (self.deny(Some(id), r, format!("mcp.{m} {}", self.name), vec![]), None),
            _ => unreachable!("a pin without a manifest has a reason"),
        };
        match m.as_str() {
            "initialize" => (Some(json!({"jsonrpc": "2.0", "id": id, "result": self.init})), None),
            "ping" => (Some(json!({"jsonrpc": "2.0", "id": id, "result": {}})), None),
            "tools/list" => (Some(json!({"jsonrpc": "2.0", "id": id, "result": {"tools": manifest.tools}})), None),
            "tools/call" => self.call(id, v, &manifest),
            other => {
                (self.deny(Some(id), Reason::McpMethodNotAllowed, format!("mcp.{other} {}", self.name), vec![]), None)
            }
        }
    }

    fn call(&mut self, id: Value, v: Value, manifest: &Manifest) -> (Option<Value>, Option<Value>) {
        let params = v.get("params");
        let tool = params.and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string();
        let args = params.and_then(|p| p.get("arguments")).cloned().unwrap_or_else(|| json!({}));
        let verb = format!("mcp.call_tool {} {tool}", self.name);
        if !args.is_object() || tool.is_empty() {
            return (self.deny(Some(id), Reason::McpMalformed, verb, vec![]), None);
        }
        if !manifest.tools.iter().any(|t| t.get("name").and_then(|n| n.as_str()) == Some(tool.as_str())) {
            return (self.deny(Some(id), Reason::McpToolUnknown, verb, vec![("tool", tool.clone().into())]), None);
        }
        let write = self.cfg.tools.write.contains(&tool);
        let untrusted = self.cfg.tools.untrusted.contains(&tool);
        let integrity = pin::digest(&args);
        let extra = || -> Vec<(&str, Value)> {
            vec![
                ("tool", tool.clone().into()),
                ("manifest", manifest.sha256.clone().into()),
                ("args_integrity", integrity.clone().into()),
                ("write", write.into()),
            ]
        };
        match self.ctx.policy.authorize_mcp(self.name, &manifest.sha256, true, &tool, &integrity, write) {
            Err((reason, _)) => (self.deny(Some(id), reason, verb, extra()), None),
            Ok(ids) => {
                // Write-ahead (I9): no row, no call.
                let rid = RequestId::new();
                let mut ev = self.event(&rid, verb.clone()).allow(ids);
                for (k, x) in extra() {
                    ev = ev.detail(k, x);
                }
                if self.ctx.recorder.append(&ev).is_err() {
                    return (self.deny(Some(id), Reason::AuditUnavailable, verb, vec![]), None);
                }
                self.ctx.stats.allowed.fetch_add(1, Ordering::Relaxed);
                let labels = self.ctx.policy.labels();
                for (l, on) in [(Label::ExternalEffect, write), (Label::UntrustedInput, untrusted)] {
                    if on && labels.raise(l) {
                        let ev = self
                            .ctx
                            .event(EventKind::SessionLabel, &rid)
                            .dest(self.dest.clone())
                            .detail("label", l.as_str())
                            .detail("cause", verb.clone());
                        let _ = self.ctx.recorder.append(&ev);
                    }
                }
                self.pending.insert(id.to_string());
                (None, Some(v))
            }
        }
    }

    /// Handle one server frame: `(frame for the agent, reply to the server)`.
    pub fn on_server(&mut self, bytes: &[u8]) -> (Option<Value>, Option<Value>) {
        match classify(bytes) {
            (Kind::Request { id, method }, _) => {
                let _ =
                    self.deny(None, Reason::McpMethodNotAllowed, format!("mcp.server.{method} {}", self.name), vec![]);
                (None, Some(refusal(id)))
            }
            (Kind::Notification { method }, Some(v)) => {
                if method == "notifications/tools/list_changed" {
                    (None, self.start_relist())
                } else {
                    (Some(v), None)
                }
            }
            (Kind::Response { id }, Some(v)) => {
                if let Some(s) = id.as_str().filter(|s| s.starts_with("broker-relist-")) {
                    let s = s.to_string();
                    return (None, self.on_relist(&s, &v));
                }
                (self.pending.remove(&id.to_string()).then_some(v), None)
            }
            _ => (None, None),
        }
    }

    fn start_relist(&mut self) -> Option<Value> {
        if !matches!(self.pin, Pin::Pinned(_)) {
            return None;
        }
        self.relists += 1;
        self.relist = Some((0, Vec::new()));
        Some(
            json!({"jsonrpc": "2.0", "id": format!("broker-relist-{}-0", self.relists), "method": "tools/list", "params": {}}),
        )
    }

    /// A page of a re-listing: fetch the next page, or compare the whole.
    fn on_relist(&mut self, id: &str, v: &Value) -> Option<Value> {
        let expected_prefix = format!("broker-relist-{}-", self.relists);
        let (page, mut acc) = self.relist.take().filter(|_| id.starts_with(&expected_prefix))?;
        let res = v.get("result");
        let tools = res.and_then(|r| r.get("tools")).and_then(|t| t.as_array());
        let next = res.and_then(|r| r.get("nextCursor")).filter(|c| !c.is_null()).cloned();
        let revoke = |this: &mut Self, got: Result<Manifest, String>| {
            let Pin::Pinned(old) = &this.pin else { return };
            let (got, diff) = match got {
                Ok(m) if m.sha256 == old.sha256 => return,
                Ok(m) => {
                    let d = pin::diff(&old.tools, &m.tools);
                    (m, d)
                }
                Err(e) => (Manifest { sha256: "unpinnable".into(), tools: vec![] }, vec![e]),
            };
            this.pin = Pin::Changed { expected: old.sha256.clone(), got, diff };
            this.record_connect();
        };
        match (tools, next) {
            (None, _) => revoke(self, Err("tools/list failed while re-listing".into())),
            (Some(t), Some(c)) if page < 19 => {
                acc.extend(t.iter().cloned());
                self.relist = Some((page + 1, acc));
                return Some(json!({"jsonrpc": "2.0", "id": format!("{expected_prefix}{}", page + 1),
                                   "method": "tools/list", "params": {"cursor": c}}));
            }
            (Some(_), Some(_)) => revoke(self, Err("tools/list has more than 20 pages".into())),
            (Some(t), None) => {
                acc.extend(t.iter().cloned());
                revoke(self, pin::manifest(acc));
            }
        }
        None
    }
}

/// How long to wait for outstanding calls after the agent closed its side.
pub(super) fn drain() -> Duration {
    DRAIN
}

pub(super) fn pin_timeout() -> Duration {
    PIN_TIMEOUT
}
