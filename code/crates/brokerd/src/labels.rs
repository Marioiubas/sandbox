//! Session labels in the daemon (Trifecta Session Labels): raising one and
//! putting on record which request raised it. A pinned MCP server's session
//! carries the labels of the agent session it was started for, never fresh
//! ones (ADR-038): what the server reads raises the agent's labels, and the
//! server's own requests are judged with them. The `session.label` row is
//! written on the session whose labels changed and names the request that
//! raised them and, when that request was made in another session (the
//! server's), that session.

use crate::pipeline::PipelineCtx;
use audit::{AuditEvent, Dest, EventKind, RequestId, SessionId};
use policy::github::{Label, Labels};
use std::sync::Arc;

/// A session's labels and the session they belong to. Starting a pinned
/// MCP server needs one (ADR-038): there is no way to start a server
/// session with labels of its own.
#[derive(Clone, Debug)]
pub struct LabelOwner {
    pub session: SessionId,
    pub labels: Arc<Labels>,
    /// That session's attribution: its `session.label` rows carry it (I9),
    /// whichever session's request raised the label.
    pub attribution: AuditEvent,
}

impl LabelOwner {
    /// The labels a session's requests are judged with, and whose they are.
    pub fn of(ctx: &PipelineCtx) -> Self {
        LabelOwner {
            session: ctx.labels_session.clone(),
            labels: ctx.policy.labels().clone(),
            attribution: ctx.labels_attribution.clone().unwrap_or_else(|| ctx.attribution()),
        }
    }
}

impl PipelineCtx {
    /// The `session.label` row for `label`, raised by request `rid` of this
    /// session: on the session whose labels changed, naming this session
    /// when that is another one.
    pub fn label_event(&self, rid: &RequestId, dest: Dest, label: Label, cause: String) -> AuditEvent {
        let mut ev = self.event(EventKind::SessionLabel, rid);
        ev = match &self.labels_attribution {
            Some(a) => ev.attributed_as(a),
            None => ev.session(&self.labels_session),
        };
        let mut ev = ev.dest(dest).detail("label", label.as_str()).detail("cause", cause);
        if self.labels_session != self.session {
            ev = ev.detail("raised_in_session", self.session.as_str());
        }
        ev
    }

    /// Raise `label` (raise-only: it is raised even if the row cannot be
    /// written) and, when this call raised it, append the row. True when
    /// this call raised it.
    pub fn raise_label(&self, rid: &RequestId, dest: &Dest, label: Label, cause: String) -> bool {
        if !self.policy.labels().raise(label) {
            return false;
        }
        if let Err(e) = self.recorder.append(&self.label_event(rid, dest.clone(), label, cause)) {
            eprintln!("brokerd: audit append failed for label {}: {e:#}", label.as_str());
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::Stats;
    use audit::{ChainHash, Recorder};
    use netguard::ingress::ChannelAuth;
    use netguard::resolver::StaticResolver;
    use policy::EgressPolicy;
    use policy::github::Trifecta;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct Mem(Mutex<Vec<AuditEvent>>);

    impl Recorder for Mem {
        fn append(&self, ev: &AuditEvent) -> anyhow::Result<ChainHash> {
            self.0.lock().unwrap().push(ev.clone());
            Ok(ChainHash([0; 32]))
        }
    }

    fn ctx(session: SessionId, owner: Option<&LabelOwner>, rec: Arc<Mem>) -> PipelineCtx {
        let mut policy = EgressPolicy::default();
        if let Some(o) = owner {
            policy = policy.with_labels(o.labels.clone());
        }
        PipelineCtx {
            labels_session: owner.map(|o| o.session.clone()).unwrap_or_else(|| session.clone()),
            labels_attribution: owner.map(|o| o.attribution.clone()),
            session,
            enduser: "local:test".into(),
            groups: vec![],
            agent: "probe".into(),
            agent_sha256: None,
            task: None,
            sandbox: "test".into(),
            policy: Arc::new(policy),
            resolver: Arc::new(StaticResolver::default()),
            recorder: rec,
            auth: ChannelAuth::Implicit,
            stats: Arc::new(Stats::default()),
            connect_timeout: Duration::from_secs(1),
            sni_timeout: Duration::from_secs(1),
            l7: None,
            shadow: None,
            mcp: None,
            approvals: Default::default(),
        }
    }

    /// A server session started for an agent session raises the agent's
    /// labels, and the row is on the agent's session, naming the server's
    /// session and request.
    #[test]
    fn a_server_session_raises_the_agent_sessions_labels_on_its_record() {
        let rec = Arc::new(Mem::default());
        let agent = ctx(SessionId::new(), None, rec.clone());
        let owner = LabelOwner::of(&agent);
        assert_eq!(owner.session, agent.session);
        let server = ctx(SessionId::new(), Some(&owner), rec.clone());
        assert_ne!(server.session, agent.session);

        let rid = RequestId::new();
        let cause = "github repo.read api.test/acme/web".to_string();
        assert!(server.raise_label(&rid, &Dest::default(), Label::SensitiveRead, cause.clone()));
        let want = Trifecta { sensitive_read: true, ..Default::default() };
        assert_eq!(agent.policy.labels().snapshot(), want, "the agent session's labels changed");
        assert_eq!(server.policy.labels().snapshot(), want, "the server is judged with them");

        let evs = rec.0.lock().unwrap().clone();
        assert_eq!(evs.len(), 1);
        let ev = &evs[0];
        assert_eq!(ev.kind, EventKind::SessionLabel);
        assert_eq!(ev.session.as_ref(), Some(&agent.session), "the row is on the session whose labels changed");
        assert_eq!(ev.request_id.as_ref(), Some(&rid), "naming the server's request");
        assert_eq!(ev.detail["raised_in_session"], server.session.as_str());
        assert_eq!(ev.detail["label"], "sensitive_read");
        assert_eq!(ev.detail["cause"], cause.as_str());

        // Raised once: a second raise from either side writes nothing.
        assert!(!server.raise_label(&RequestId::new(), &Dest::default(), Label::SensitiveRead, "again".into()));
        assert!(!agent.raise_label(&RequestId::new(), &Dest::default(), Label::SensitiveRead, "again".into()));
        assert_eq!(rec.0.lock().unwrap().len(), 1);

        // The agent's own raise is visible to the server; its row has no
        // `raised_in_session`.
        assert!(agent.raise_label(&RequestId::new(), &Dest::default(), Label::UntrustedInput, "issue".into()));
        assert!(server.policy.labels().get(Label::UntrustedInput));
        let evs = rec.0.lock().unwrap().clone();
        assert_eq!(evs[1].session.as_ref(), Some(&agent.session));
        assert!(evs[1].detail.get("raised_in_session").is_none());
    }

    /// Two agent sessions using the same server name each start their own
    /// server session: labels never cross from one agent session to another.
    #[test]
    fn server_sessions_of_different_agents_do_not_share_labels() {
        let rec = Arc::new(Mem::default());
        let a = ctx(SessionId::new(), None, rec.clone());
        let b = ctx(SessionId::new(), None, rec.clone());
        let server_a = ctx(SessionId::new(), Some(&LabelOwner::of(&a)), rec.clone());
        let server_b = ctx(SessionId::new(), Some(&LabelOwner::of(&b)), rec.clone());
        server_a.raise_label(&RequestId::new(), &Dest::default(), Label::SensitiveRead, "private".into());
        assert!(a.policy.labels().get(Label::SensitiveRead));
        assert!(!b.policy.labels().get(Label::SensitiveRead));
        assert!(!server_b.policy.labels().get(Label::SensitiveRead));
    }
}
