//! Step-up approvals on the L7 path (ADR-037): a request denied only for
//! want of a human approval leaves a pending approval naming the exact
//! actions; an allowed request uses up the single-use approvals it relied
//! on. The pending approval is logged before the agent hears of it (I9).

use super::Conn;
use audit::{EventKind, RequestId};
use policy::{Action, L7Decision};

impl Conn {
    /// When approving the blocked actions would allow the request, record a
    /// pending approval and an `approval.requested` event, and return the
    /// deny-row detail that names it.
    pub(super) fn pending_approval(
        &self,
        rid: &RequestId,
        actions: &[Action],
        dec: &L7Decision,
    ) -> Option<(&'static str, serde_json::Value)> {
        let reason = dec.result.as_ref().err().copied()?;
        let keys = self.ctx.policy.approvable(&self.adm, actions, dec)?;
        let id = self.ctx.approvals.request(self.ctx.session.as_str(), rid.as_str(), reason, keys.clone())?;
        let ev = self
            .ctx
            .event(EventKind::ApprovalRequested, rid)
            .dest(self.dest.clone())
            .detail("approval", id.as_str())
            .detail("reason", reason.as_str())
            .detail("authority_diff", keys.iter().map(|k| format!("+ {k}")).collect::<Vec<_>>())
            .detail("labels", self.labels_detail());
        if let Err(e) = self.ctx.recorder.append(&ev) {
            eprintln!("brokerd: audit append failed for approval {id}: {e:#}");
            self.ctx.approvals.cancel(&id);
            return None;
        }
        Some(("approval", id.into()))
    }
}
