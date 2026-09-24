//! Audit: the single writer of decision evidence (I9).
//!
//! Every crate that decides calls [`Recorder::append`] *before* the decision
//! takes effect; an `Err` from `append` must be treated as a deny
//! (`Reason::AuditUnavailable`). Events carry identifiers (session, request,
//! credential ID), never secret values (I1).
//!
//! This crate also owns the vocabulary shared by every deciding crate:
//! [`SessionId`], [`RequestId`] and the enumerated deny [`Reason`] that
//! `broker why` renders.

pub mod canonical;
pub mod event;
pub mod ids;
pub mod ocsf;
pub mod otlp;
pub mod reason;
pub mod store;
pub mod time;

pub use event::{AuditEvent, Decision, DecisionResult, Dest, EventKind, Mode};
pub use ids::{RequestId, SessionId};
pub use reason::Reason;
pub use store::{SqliteRecorder, StoredEvent, VerifyError};

/// SHA-256 chain hash of a stored event: `H(prev || canonical_json(ev))`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainHash(pub [u8; 32]);

impl ChainHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for ChainHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChainHash({})", self.to_hex())
    }
}

/// Append-only, hash-chained decision log.
///
/// `append` returns only after the event is durable and yields the new chain
/// hash. Callers must treat `Err` as deny.
pub trait Recorder: Send + Sync {
    fn append(&self, ev: &AuditEvent) -> anyhow::Result<ChainHash>;
}

/// A recorder that always fails; used to prove that an audit failure denies.
#[derive(Debug, Default)]
pub struct FailingRecorder;

impl Recorder for FailingRecorder {
    fn append(&self, _ev: &AuditEvent) -> anyhow::Result<ChainHash> {
        anyhow::bail!("audit store unavailable")
    }
}
