//! MCP calls (MCP Guard): the pinned servers' call permits and the
//! decision for one `tools/call`.

use super::*;

/// An allowed `tools/call`: the determining policy IDs and the approval it
/// relied on, if any (single use until consumed).
pub type McpAllowed = (Vec<String>, Option<String>);

impl EgressPolicy {
    /// Compile the pinned MCP servers' call permits into the base set.
    /// Call before any repository layer is conjoined.
    pub fn with_mcp(
        mut self,
        servers: &std::collections::BTreeMap<String, crate::mcp::McpServerConfig>,
    ) -> Result<Self, CompileError> {
        crate::mcp::validate(servers).map_err(CompileError::Cedar)?;
        let mut compiled = compile_all(&self.grants)?;
        compiled.extend(self.options.iter().cloned());
        compiled.extend(crate::mcp::policies(servers));
        self.engine = Engine::new(&compiled).map_err(CompileError::Cedar)?;
        Ok(self)
    }

    /// Decide one `tools/call` to a pinned server: the manifest must be
    /// approved (`pinned`), the server's permit must cover the tool, and a
    /// write tool is subject to the Rule of Two.
    pub fn authorize_mcp(
        &self,
        server: &str,
        manifest_sha256: &str,
        pinned: bool,
        tool: &str,
        args_integrity: &str,
        write: bool,
    ) -> Result<McpAllowed, (Reason, Vec<String>)> {
        let mut ents = ent::principal_entities(&self.session);
        ents.push(json!({
            "uid": { "type": "Broker::McpServer", "id": server },
            "attrs": { "manifest_sha256": manifest_sha256, "pinned": pinned },
            "parents": [],
        }));
        let ctx = |approved: bool| {
            move |m: Mode| {
                let mut s = self.session_ctx(m);
                s["approved"] = json!(approved);
                json!({ "session": s, "tool": tool, "args_integrity": args_integrity, "write": write })
            }
        };
        let res = json!({ "type": "Broker::McpServer", "id": server });
        // A human approval of exactly this call (ADR-037), if one is held.
        let key = crate::approvals::mcp_approval_key(server, tool, args_integrity);
        let approved = self.approvals().is_approved(&key);
        let (v, _) = self.eval("mcp.call_tool", &res, ents.clone(), ctx(approved));
        if v.allowed {
            return Ok((v.determining, approved.then_some(key)));
        }
        let forbid = |v: &Verdict| v.determining.iter().find_map(|id| self.engine.reason_of(id)).map(reason_from);
        let reason = match forbid(&v) {
            _ if !v.errors.is_empty() => Reason::PolicyError,
            // Would approval help? Only if the call is allowed once approved.
            Some(r @ (Reason::NeedsApproval | Reason::RuleOfTwo)) if !approved => {
                let (a, _) = self.eval("mcp.call_tool", &res, ents, ctx(true));
                if a.allowed { r } else { forbid(&a).unwrap_or(Reason::McpToolNotAllowed) }
            }
            Some(r) => r,
            None => Reason::McpToolNotAllowed,
        };
        Err((reason, v.determining))
    }
}
