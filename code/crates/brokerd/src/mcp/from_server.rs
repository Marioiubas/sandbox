//! What the server sends back (MCP Guard, ADR-047). Nothing reaches the
//! agent from a server that is not pinned (unapproved, changed, revoked):
//! the result of a call forwarded before a revocation comes back as a
//! denial. From a pinned server the agent receives only replies to calls it
//! made and the notifications the relay understands: `notifications/progress`
//! for a pending call's token, rebuilt from its numbers (its free-text
//! `message` is not pinned, so it is dropped). `tools/list_changed` triggers
//! a re-pin; every other notification is dropped and logged (once per
//! method per connection), and server-to-client requests are refused.

use super::pin::Manifest;
use super::relay::{Pin, Relay, refusal};
use audit::Reason;
use mcpguard::frame::{Kind, classify};
use serde_json::{Map, Value, json};

impl Relay<'_> {
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
                    return (None, self.start_relist());
                }
                if method == "notifications/progress"
                    && matches!(self.pin, Pin::Pinned(_))
                    && let Some(p) = self.progress_for_agent(&v)
                {
                    return (Some(p), None);
                }
                self.drop_notification(&method);
                (None, None)
            }
            (Kind::Response { id }, Some(v)) => {
                if let Some(s) = id.as_str().filter(|s| s.starts_with("broker-relist-")) {
                    let s = s.to_string();
                    return (None, self.on_relist(&s, &v));
                }
                let key = id.to_string();
                if !self.pending.remove(&key) {
                    return (None, None);
                }
                self.progress.retain(|_, k| *k != key);
                match self.pin.reason() {
                    None => (Some(v), None),
                    // Revoked while the call ran: its result is withheld.
                    Some(r) => (self.deny(Some(id), r, format!("mcp.server.result {}", self.name), vec![]), None),
                }
            }
            _ => (None, None),
        }
    }

    /// A progress notification for a pending call, with only the fields
    /// the relay vouches for (the agent's token and the numbers).
    fn progress_for_agent(&self, v: &Value) -> Option<Value> {
        let p = v.get("params")?;
        let token = p.get("progressToken").filter(|t| t.is_string() || t.is_number())?;
        self.progress.get(&token.to_string())?;
        let mut out = Map::new();
        out.insert("progressToken".into(), token.clone());
        out.insert("progress".into(), p.get("progress").filter(|n| n.is_number())?.clone());
        if let Some(t) = p.get("total").filter(|n| n.is_number()) {
            out.insert("total".into(), t.clone());
        }
        Some(json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": out}))
    }

    fn drop_notification(&mut self, method: &str) {
        if self.dropped.len() < 64 && self.dropped.insert(method.to_string()) {
            let verb = format!("mcp.server.{method} {}", self.name);
            let _ = self.deny(None, Reason::McpMethodNotAllowed, verb, vec![("dropped", "notification".into())]);
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

    /// A page of a re-listing: fetch the next page, or compare the whole
    /// (with the pinned command and `initialize` result: only the tools are
    /// re-read).
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
                    let d = mcpguard::manifest::changes(old, &m);
                    (m, d)
                }
                Err(e) => (
                    Manifest { sha256: "unpinnable".into(), command: Value::Null, server: Value::Null, tools: vec![] },
                    vec![e],
                ),
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
                let got = match &self.pin {
                    Pin::Pinned(old) => old.with_tools(acc),
                    _ => return None,
                };
                revoke(self, got);
            }
        }
        None
    }
}
