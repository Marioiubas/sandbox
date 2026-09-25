//! MCP calls (MCP Guard): the pinned servers' call permits and the
//! decision for one `tools/call`.

use super::*;

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
    ) -> Result<Vec<String>, (Reason, Vec<String>)> {
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
        let (v, _) = self.eval("mcp.call_tool", &res, ents.clone(), ctx(false));
        if v.allowed {
            return Ok(v.determining);
        }
        let forbid = |v: &Verdict| v.determining.iter().find_map(|id| self.engine.reason_of(id)).map(reason_from);
        let reason = match forbid(&v) {
            _ if !v.errors.is_empty() => Reason::PolicyError,
            // Would approval help? Only if the call is allowed once approved.
            Some(r @ (Reason::NeedsApproval | Reason::RuleOfTwo)) => {
                let (a, _) = self.eval("mcp.call_tool", &res, ents, ctx(true));
                if a.allowed { r } else { forbid(&a).unwrap_or(Reason::McpToolNotAllowed) }
            }
            Some(r) => r,
            None => Reason::McpToolNotAllowed,
        };
        Err((reason, v.determining))
    }
}
