//! MCP servers (MCP Guard): pinned stdio servers, defined only in user or
//! org policy (never a repository, I5), their `mcp.call_tool` permits, and
//! the call decision. A call also needs the server's approved manifest:
//! the `pinned-mcp-only` forbid denies an unpinned server.

use crate::cedar::Compiled;
use crate::cedar::compile::lit;
use crate::config::EgressEntry;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpServerConfig {
    /// The pinned command: an absolute executable path and its arguments.
    pub command: Vec<String>,
    /// The server's own egress grants: its sandbox reaches nothing else.
    #[serde(default)]
    pub egress: Vec<EgressEntry>,
    #[serde(default)]
    pub tools: McpTools,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpTools {
    /// Tools with external effects: `external_effect`, and the Rule of Two.
    #[serde(default)]
    pub write: Vec<String>,
    /// Tools whose results are content anyone can write: `untrusted_input`.
    #[serde(default)]
    pub untrusted: Vec<String>,
    /// Tools that are never allowed.
    #[serde(default)]
    pub deny: Vec<String>,
}

/// A server name: 1-32 of `a-z`, `0-9`, `-`, starting with a letter or digit.
pub fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 32
        && !n.starts_with('-')
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Fail closed on anything a pinned definition must not be.
pub fn validate(servers: &BTreeMap<String, McpServerConfig>) -> Result<(), String> {
    for (name, s) in servers {
        if !valid_name(name) {
            return Err(format!("mcp server name {name:?} must be 1-32 of a-z, 0-9 and -"));
        }
        match s.command.first() {
            Some(c) if c.starts_with('/') => {}
            _ => return Err(format!("mcp.{name}: command must start with an absolute executable path")),
        }
        if s.command.iter().any(|a| a.contains('\0')) {
            return Err(format!("mcp.{name}: command contains a NUL byte"));
        }
        for t in s.tools.write.iter().chain(&s.tools.untrusted).chain(&s.tools.deny) {
            if t.is_empty() || t.len() > 128 {
                return Err(format!("mcp.{name}: tool name {t:?} must be 1-128 bytes"));
            }
        }
    }
    Ok(())
}

/// One permit per server for calls to it, minus its denied tools.
pub(crate) fn policies(servers: &BTreeMap<String, McpServerConfig>) -> Vec<Compiled> {
    servers
        .iter()
        .map(|(name, s)| {
            let id = format!("mcp:{name}#call");
            let unless = if s.tools.deny.is_empty() {
                String::new()
            } else {
                let d: Vec<String> = s.tools.deny.iter().map(|t| lit(t)).collect();
                format!("\nunless {{ [{}].contains(context.tool) }}", d.join(", "))
            };
            Compiled {
                id: id.clone(),
                grant: None,
                src: format!(
                    "@id({})\npermit (principal, action == Broker::Action::\"mcp.call_tool\", resource == Broker::McpServer::{}){unless};",
                    lit(&id),
                    lit(name)
                ),
            }
        })
        .collect()
}
