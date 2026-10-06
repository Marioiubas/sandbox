//! The MCP relay (MCP Guard): the daemon pins the server's manifest before
//! relaying anything, answers `initialize` and `tools/list` itself from the
//! pinned state (ADR-047: the `initialize` answer is a fixed projection of
//! the server's, and part of the pin), authorizes each `tools/call`
//! (write-ahead audit, then labels, then forward), and refuses what it does
//! not relay: other methods, server-to-client requests (sampling, roots,
//! elicitation), and any frame that is not strict JSON-RPC 2.0 on one line.
//! What the server sends back is handled in `from_server`.

use super::pin::{self, Manifest};
use crate::pipeline::PipelineCtx;
use audit::{Dest, EventKind, Reason, RequestId};
use mcpguard::frame::{Frame, Kind, Lines, classify};
use policy::github::Label;
use policy::mcp::McpServerConfig;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
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
    Changed {
        expected: String,
        got: Manifest,
        diff: Vec<String>,
    },
    Failed(String),
    /// The server was not started: its command names a path inside a
    /// writable mount of the agent session (ADR-047).
    Writable(String),
}

impl Pin {
    pub(super) fn reason(&self) -> Option<Reason> {
        match self {
            Pin::Pinned(_) => None,
            Pin::Unapproved(_) => Some(Reason::McpManifestUnapproved),
            Pin::Changed { .. } => Some(Reason::McpManifestChanged),
            Pin::Failed(_) => Some(Reason::McpLaunchFailed),
            Pin::Writable(_) => Some(Reason::McpCommandWritable),
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
/// from the agent is relayed. Returns the `initialize` result as it will be
/// forwarded to the agent (`forwarded_init`) and the manifest pinning it
/// with the tools (the daemon attaches the command). Server requests during
/// the handshake are refused (their methods are returned for the audit);
/// notifications are dropped.
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
    let init = pin::forwarded_init(&init)?;
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
            let man = pin::build(Value::Null, init.clone(), tools)?;
            return Ok((init, man, refused));
        }
    }
    Err("tools/list has more than 20 pages".into())
}

pub(super) fn refusal(id: Value) -> Value {
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
    /// Requests forwarded to the server whose replies the agent awaits.
    pub pending: HashSet<String>,
    /// Progress tokens of pending calls (canonical JSON) → their request.
    pub progress: HashMap<String, String>,
    /// Server notification methods already logged as dropped.
    pub dropped: HashSet<String>,
    pub relist: Option<(u32, Vec<Value>)>,
    pub relists: u32,
}

impl<'a> Relay<'a> {
    pub fn new(
        ctx: &'a Arc<PipelineCtx>,
        name: &'a str,
        cfg: &'a McpServerConfig,
        dest: Dest,
        server_session: String,
        pin: Pin,
        init: Value,
    ) -> Self {
        Relay {
            ctx,
            name,
            cfg,
            dest,
            server_session,
            pin,
            init,
            pending: HashSet::new(),
            progress: HashMap::new(),
            dropped: HashSet::new(),
            relist: None,
            relists: 0,
        }
    }
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
        self.deny_as(&RequestId::new(), id, reason, verb, extra, None)
    }

    /// As [`deny`](Self::deny) for request `rid`, naming a pending approval
    /// the user can grant outside the sandbox (ADR-037).
    pub fn deny_as(
        &self,
        rid: &RequestId,
        id: Option<Value>,
        reason: Reason,
        verb: String,
        mut extra: Vec<(&str, Value)>,
        approval: Option<String>,
    ) -> Option<Value> {
        self.ctx.stats.denied.fetch_add(1, Ordering::Relaxed);
        if let Some(a) = &approval {
            extra.push(("approval", a.as_str().into()));
        }
        let mut ev = self.event(rid, verb).deny(reason, vec![]);
        for (k, v) in extra {
            ev = ev.detail(k, v);
        }
        if let Err(e) = self.ctx.recorder.append(&ev) {
            eprintln!("brokerd: audit append failed for mcp deny {rid}: {e:#}");
        }
        let ask = approval
            .as_ref()
            .map(|a| format!("; it needs the user's approval: ask them to run `broker approve {a}` outside the sandbox, then retry"))
            .unwrap_or_default();
        id.map(|id| {
            json!({"jsonrpc": "2.0", "id": id, "error": {
                "code": DENIED,
                "message": format!("broker: denied ({}): {}{ask}; run `broker why {rid}`", reason.as_str(), reason.explain()),
                "data": {"reason": reason.as_str(), "request_id": rid.as_str(), "approval": approval},
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
            Pin::Writable(m) => {
                self.event(&rid, verb).deny(Reason::McpCommandWritable, vec![]).detail("error", m.as_str())
            }
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
            Err((reason, _)) if policy::approvals::is_approval_reason(reason) => {
                // Held for a human: the exact call, with its arguments shown.
                let rid = RequestId::new();
                let key = policy::approvals::mcp_approval_key(self.name, &tool, &integrity);
                let approval = self.pending_approval(&rid, reason, key, &args);
                (self.deny_as(&rid, Some(id), reason, verb, extra(), approval), None)
            }
            Err((reason, _)) => (self.deny(Some(id), reason, verb, extra()), None),
            Ok((ids, used)) => {
                // The approval this call relied on, claimed at once (a
                // single-use approval allows one call).
                if !self.ctx.policy.approvals().claim(used.as_slice()) {
                    return (self.deny(Some(id), Reason::ApprovalUsed, verb, extra()), None);
                }
                // Write-ahead (I9): no row, no call.
                let rid = RequestId::new();
                let mut ev = self.event(&rid, verb.clone()).allow(ids);
                for (k, x) in extra() {
                    ev = ev.detail(k, x);
                }
                if let Some(k) = &used {
                    ev = ev.detail("approvals_used", vec![k.clone()]);
                }
                if self.ctx.recorder.append(&ev).is_err() {
                    return (self.deny(Some(id), Reason::AuditUnavailable, verb, vec![]), None);
                }
                self.ctx.stats.allowed.fetch_add(1, Ordering::Relaxed);
                // What the server itself reads or writes raises these same
                // labels from its own session (ADR-038); the configured
                // lists add what its egress cannot show (tool semantics).
                for (l, on) in [(Label::ExternalEffect, write), (Label::UntrustedInput, untrusted)] {
                    if on {
                        self.ctx.raise_label(&rid, &self.dest, l, verb.clone());
                    }
                }
                let key = id.to_string();
                if let Some(t) =
                    params.and_then(|p| p.pointer("/_meta/progressToken")).filter(|t| t.is_string() || t.is_number())
                {
                    self.progress.insert(t.to_string(), key.clone());
                }
                self.pending.insert(key);
                (None, Some(v))
            }
        }
    }
}

/// How long to wait for outstanding calls after the agent closed its side.
pub(super) fn drain() -> Duration {
    DRAIN
}

pub(super) fn pin_timeout() -> Duration {
    PIN_TIMEOUT
}

#[cfg(test)]
#[path = "relay_tests.rs"]
mod tests;
