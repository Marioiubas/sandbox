//! Manifest pinning: everything a server puts in front of the agent, hashed
//! over canonical JSON. A manifest has three parts (ADR-047): the server's
//! command by content (argv and the digest of every file it names; the
//! daemon computes it), the fields of its `initialize` result the relay
//! forwards to the agent ([`forwarded_init`]), and every tool object (keys
//! sorted, tools sorted by name). Any change to any part changes the digest.

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// A server's pinned manifest and its digest.
#[derive(Clone, Debug, PartialEq)]
pub struct Manifest {
    pub sha256: String,
    /// `{"argv": [...], "files": {"<path as named>": "sha256:..."}}`, or
    /// null where no command was attached (approvals made before ADR-047).
    pub command: Value,
    /// The `initialize` result exactly as the relay forwards it to the
    /// agent ([`forwarded_init`]), or null (approvals made before ADR-047).
    pub server: Value,
    pub tools: Vec<Value>,
}

/// `v` with every object's keys sorted (serde_json keeps insertion order here).
pub fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), canonical(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

pub fn digest(v: &Value) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(canonical(v).to_string().as_bytes())))
}

/// The manifest of a command, a forwarded `initialize` result and a tool
/// list; a tool without a string `name`, or two tools with one name, makes
/// it unpinnable.
pub fn build(command: Value, server: Value, tools: Vec<Value>) -> Result<Manifest, String> {
    let mut by_name: BTreeMap<String, Value> = BTreeMap::new();
    for t in tools {
        let name = t.get("name").and_then(|n| n.as_str()).ok_or("a tool without a string name")?.to_string();
        if by_name.insert(name.clone(), canonical(&t)).is_some() {
            return Err(format!("two tools named {name:?}"));
        }
    }
    let tools: Vec<Value> = by_name.into_values().collect();
    let (command, server) = (canonical(&command), canonical(&server));
    let sha256 = digest(&json!({"command": command, "server": server, "tools": tools}));
    Ok(Manifest { sha256, command, server, tools })
}

/// The manifest of a tool list alone (no command, no `initialize` result).
pub fn manifest(tools: Vec<Value>) -> Result<Manifest, String> {
    build(Value::Null, Value::Null, tools)
}

impl Manifest {
    /// This manifest with the server's command attached (and re-digested).
    pub fn with_command(&self, command: Value) -> Manifest {
        build(command, self.server.clone(), self.tools.clone()).expect("the tools were pinnable already")
    }

    /// This manifest's command and `initialize` result with another tool
    /// list (a re-listing after `notifications/tools/list_changed`).
    pub fn with_tools(&self, tools: Vec<Value>) -> Result<Manifest, String> {
        build(self.command.clone(), self.server.clone(), tools)
    }
}

/// The fields of a server's `initialize` result the relay forwards to the
/// agent, and nothing else: `protocolVersion`, `serverInfo` (its `name`,
/// `title` and `version`), `instructions` (which clients put in the model's
/// context), and `capabilities` fixed by the relay to `{"tools": {}}` (it
/// relays tools only and handles list changes itself). Everything else
/// (`_meta`, other capabilities, icons, unknown fields) is dropped. A field
/// of the wrong type makes the server unpinnable rather than being guessed at.
pub fn forwarded_init(result: &Value) -> Result<Value, String> {
    let r = result.as_object().ok_or("initialize: the result is not an object")?;
    let version = r.get("protocolVersion").and_then(Value::as_str).ok_or("initialize: no protocolVersion string")?;
    let mut out = Map::new();
    out.insert("protocolVersion".into(), version.into());
    out.insert("capabilities".into(), json!({"tools": {}}));
    if let Some(info) = r.get("serverInfo") {
        let info = info.as_object().ok_or("initialize: serverInfo is not an object")?;
        let mut kept = Map::new();
        for k in ["name", "title", "version"] {
            match info.get(k) {
                None => {}
                Some(Value::String(s)) => {
                    kept.insert(k.into(), s.as_str().into());
                }
                Some(_) => return Err(format!("initialize: serverInfo.{k} is not a string")),
            }
        }
        out.insert("serverInfo".into(), Value::Object(kept));
    }
    match r.get("instructions") {
        None => {}
        Some(Value::String(s)) => {
            out.insert("instructions".into(), s.as_str().into());
        }
        Some(_) => return Err("initialize: instructions is not a string".into()),
    }
    Ok(Value::Object(out))
}

/// What changed between two manifests: the command, the forwarded
/// `initialize` result, then tool by tool.
pub fn changes(old: &Manifest, new: &Manifest) -> Vec<String> {
    let mut out = Vec::new();
    if old.command != new.command {
        if old.command.is_null() {
            out.push("+ command (now pinned by content)".to_string());
        } else {
            if old.command.get("argv") != new.command.get("argv") {
                out.push("~ command argv changed".to_string());
            }
            out.extend(keyed(&old.command["files"], &new.command["files"], "command file", "content changed"));
        }
    }
    if old.server != new.server {
        if old.server.is_null() {
            out.push("+ server initialize result (now pinned)".to_string());
        } else {
            out.extend(keyed(&old.server, &new.server, "server", "changed"));
        }
    }
    out.extend(diff(&old.tools, &new.tools));
    out
}

/// `+`, `-` and `~` lines for the keys of two objects.
fn keyed(old: &Value, new: &Value, what: &str, changed: &str) -> Vec<String> {
    let empty = Map::new();
    let (o, n) = (old.as_object().unwrap_or(&empty), new.as_object().unwrap_or(&empty));
    let mut out = Vec::new();
    for (k, v) in n {
        match o.get(k) {
            None => out.push(format!("+ {what} {k}")),
            Some(prev) if prev == v => {}
            Some(_) => out.push(format!("~ {what} {k}: {changed}")),
        }
    }
    for k in o.keys().filter(|k| !n.contains_key(*k)) {
        out.push(format!("- {what} {k}"));
    }
    out
}

/// What changed between two tool lists, tool by tool.
pub fn diff(old: &[Value], new: &[Value]) -> Vec<String> {
    let index = |ts: &[Value]| -> BTreeMap<String, Value> {
        ts.iter().filter_map(|t| Some((t.get("name")?.as_str()?.to_string(), t.clone()))).collect()
    };
    let (o, n) = (index(old), index(new));
    let mut out = Vec::new();
    for (name, t) in &n {
        match o.get(name) {
            None => out.push(format!("+ tool {name}")),
            Some(prev) if prev == t => {}
            Some(prev) => {
                let what: Vec<&str> = ["description", "inputSchema", "annotations", "title"]
                    .into_iter()
                    .filter(|k| prev.get(*k) != t.get(*k))
                    .collect();
                let what = if what.is_empty() { "changed".to_string() } else { format!("{} changed", what.join(", ")) };
                out.push(format!("~ tool {name}: {what}"));
            }
        }
    }
    for name in o.keys().filter(|k| !n.contains_key(*k)) {
        out.push(format!("- tool {name}"));
    }
    out
}

#[cfg(test)]
#[path = "manifest_tests.rs"]
mod tests;
