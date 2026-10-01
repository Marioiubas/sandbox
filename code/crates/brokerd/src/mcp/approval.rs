//! Step-up approvals for MCP tool calls (ADR-037): a `tools/call` denied
//! only for want of a human approval (`rule-of-two-mcp`) leaves a pending
//! approval naming the exact call (server, tool, digest of the arguments)
//! and carrying the arguments themselves, so the user approves what will
//! run, not a hash. Logged before the agent hears of it (I9).

use super::relay::Relay;
use audit::{EventKind, Reason, RequestId};
use serde_json::Value;

/// Largest arguments kept with a pending approval (shown to the user).
const MAX_SUBJECT: usize = 64 << 10;

impl Relay<'_> {
    pub(super) fn pending_approval(
        &self,
        rid: &RequestId,
        reason: Reason,
        key: String,
        args: &Value,
    ) -> Option<String> {
        let shown = serde_json::to_string(args).ok()?;
        let subject = if shown.len() <= MAX_SUBJECT {
            serde_json::json!({ "tool_arguments": args })
        } else {
            // Too large to show whole: the user would approve unseen bytes.
            return None;
        };
        let id = self.ctx.approvals.request(
            self.ctx.session.as_str(),
            self.ctx.labels_session.as_str(),
            rid.as_str(),
            reason,
            vec![key.clone()],
            Some(subject),
        )?;
        let ev = self
            .ctx
            .event(EventKind::ApprovalRequested, rid)
            .dest(self.dest.clone())
            .detail("approval", id.as_str())
            .detail("reason", reason.as_str())
            .detail("authority_diff", vec![format!("+ {key}")])
            .detail("server", self.name)
            .detail("labels", serde_json::to_value(self.ctx.policy.labels().snapshot()).unwrap_or_default());
        if let Err(e) = self.ctx.recorder.append(&ev) {
            eprintln!("brokerd: audit append failed for approval {id}: {e:#}");
            self.ctx.approvals.cancel(&id);
            return None;
        }
        Some(id)
    }
}
