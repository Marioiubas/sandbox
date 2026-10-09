//! SQLite WAL store with a SHA-256 hash chain.
//!
//! Row `n` stores `body_n = canonical_json(event with seq = n)` and
//! `hash_n = SHA-256(hash_{n-1} || body_n)`, with `hash_0` the per-database
//! genesis recorded in `meta`. Deleting, reordering or editing any row breaks
//! [`SqliteRecorder::verify`] at the first affected sequence number.
//!
//! The chain is tamper *evidence*, not tamper resistance, against a local
//! attacker with the user's privileges; export anchoring arrives in M2.

use crate::canonical::canonical_json;
use crate::{AuditEvent, ChainHash, Recorder, RequestId, SessionId};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

pub const FORMAT_VERSION: i64 = 1;
pub const HASH_ALG: &str = "sha256(prev||canonical_json)";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("audit database has no meta row")]
    MissingMeta,
    #[error("unsupported audit format version {0}")]
    UnsupportedVersion(i64),
    #[error("sequence gap: expected seq {expected}, found {found}")]
    SequenceGap { expected: i64, found: i64 },
    #[error("seq {0}: prev hash does not match the previous row")]
    BrokenLink(i64),
    #[error("seq {0}: stored hash does not match the recomputed hash")]
    HashMismatch(i64),
    #[error("seq {0}: body is not a valid version-1 event with a matching seq")]
    BadBody(i64),
    #[error("seq {0}: the indexed columns (ts, kind, session, request_id) differ from the chained body")]
    ColumnMismatch(i64),
    #[error("database error: {0}")]
    Db(String),
}

/// One stored row, as read back for `broker why` and `broker audit`.
#[derive(Clone, Debug)]
pub struct StoredEvent {
    pub seq: i64,
    pub event: AuditEvent,
    pub hash: ChainHash,
}

struct Inner {
    conn: Connection,
    prev: [u8; 32],
    next_seq: i64,
}

pub struct SqliteRecorder {
    inner: Mutex<Inner>,
    group: group::Group,
}

mod group;

fn hash_link(prev: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(body);
    h.finalize().into()
}

fn blob32(v: Vec<u8>) -> anyhow::Result<[u8; 32]> {
    v.try_into().map_err(|_| anyhow::anyhow!("hash column is not 32 bytes"))
}

impl SqliteRecorder {
    /// Open (or create) the audit database. Refuses a database whose chain
    /// does not verify, because appending to a broken chain would hide the
    /// break (fail closed: sessions cannot start without a working audit).
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (format_version INTEGER NOT NULL, hash_alg TEXT NOT NULL, genesis BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, kind TEXT NOT NULL,
                 session TEXT, request_id TEXT, body BLOB NOT NULL, prev BLOB NOT NULL, hash BLOB NOT NULL);
             CREATE INDEX IF NOT EXISTS events_session ON events(session);
             CREATE INDEX IF NOT EXISTS events_request ON events(request_id);",
        )?;
        let meta: Option<(i64, Vec<u8>)> = conn
            .query_row("SELECT format_version, genesis FROM meta", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let genesis = match meta {
            Some((v, _)) if v != FORMAT_VERSION => anyhow::bail!(VerifyError::UnsupportedVersion(v)),
            Some((_, g)) => blob32(g)?,
            None => {
                let mut seed = [0u8; 16];
                getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("randomness: {e}"))?;
                let mut h = Sha256::new();
                h.update(b"broker-audit-v1");
                h.update(seed);
                let g: [u8; 32] = h.finalize().into();
                conn.execute(
                    "INSERT INTO meta (format_version, hash_alg, genesis) VALUES (?1, ?2, ?3)",
                    params![FORMAT_VERSION, HASH_ALG, g.to_vec()],
                )?;
                g
            }
        };
        verify_conn(&conn)?;
        let last: Option<(i64, Vec<u8>)> = conn
            .query_row("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;
        let (prev, next_seq) = match last {
            Some((seq, h)) => (blob32(h)?, seq + 1),
            None => (genesis, 1),
        };
        Ok(SqliteRecorder { inner: Mutex::new(Inner { conn, prev, next_seq }), group: Default::default() })
    }

    /// Open an existing database read-only (for `broker why` and `broker
    /// audit`); `append` on it fails.
    pub fn open_read_only(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(SqliteRecorder {
            inner: Mutex::new(Inner { conn, prev: [0; 32], next_seq: i64::MAX }),
            group: Default::default(),
        })
    }

    /// Verify the whole chain of the database at `path` (one read
    /// transaction, so a concurrent writer cannot produce a torn view).
    pub fn verify_path(path: &Path) -> Result<u64, VerifyError> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| VerifyError::Db(e.to_string()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5)).map_err(|e| VerifyError::Db(e.to_string()))?;
        conn.execute_batch("BEGIN").map_err(|e| VerifyError::Db(e.to_string()))?;
        let r = verify_conn(&conn);
        let _ = conn.execute_batch("COMMIT");
        r
    }

    pub fn verify(&self) -> Result<u64, VerifyError> {
        let inner = self.inner.lock().map_err(|_| VerifyError::Db("poisoned".into()))?;
        verify_conn(&inner.conn)
    }

    pub fn by_request(&self, id: &RequestId) -> anyhow::Result<Vec<StoredEvent>> {
        self.query("WHERE request_id = ?1 ORDER BY seq", params![id.as_str()])
    }

    pub fn by_session(&self, id: &SessionId) -> anyhow::Result<Vec<StoredEvent>> {
        self.query("WHERE session = ?1 ORDER BY seq", params![id.as_str()])
    }

    pub fn tail(&self, n: u32) -> anyhow::Result<Vec<StoredEvent>> {
        let mut v = self.query("ORDER BY seq DESC LIMIT ?1", params![n])?;
        v.reverse();
        Ok(v)
    }

    /// Filtered rows, oldest first (`audit.query`). Filters are bound
    /// parameters; the caller validates and canonicalises them.
    pub fn query_filtered(&self, q: &Query) -> anyhow::Result<Vec<StoredEvent>> {
        self.query(
            "WHERE seq > ?1 AND (?2 IS NULL OR session = ?2) AND (?3 IS NULL OR kind = ?3)
               AND (?4 IS NULL OR json_extract(body, '$.decision.result') = ?4)
               AND (?5 IS NULL OR json_extract(body, '$.reason') = ?5)
               AND (?6 IS NULL OR json_extract(body, '$.dest.host') = ?6)
             ORDER BY seq LIMIT ?7",
            params![
                q.after_seq,
                q.session.as_deref(),
                q.kind.map(|k| k.as_str()),
                q.decision.map(|d| match d {
                    crate::DecisionResult::Allow => "allow",
                    crate::DecisionResult::Deny => "deny",
                }),
                q.reason.map(|r| r.as_str()),
                q.host.as_deref(),
                q.limit.min(Query::MAX_LIMIT),
            ],
        )
    }

    /// Rows with `after < seq <= upto`, oldest first (a verified prefix).
    pub fn range(&self, after: i64, upto: i64) -> anyhow::Result<Vec<StoredEvent>> {
        self.query("WHERE seq > ?1 AND seq <= ?2 ORDER BY seq", params![after, upto])
    }

    fn query(&self, clause: &str, p: impl rusqlite::Params) -> anyhow::Result<Vec<StoredEvent>> {
        let inner = self.inner.lock().map_err(|_| anyhow::anyhow!("audit lock poisoned"))?;
        let sql = format!("SELECT seq, body, hash FROM events {clause}");
        let mut stmt = inner.conn.prepare(&sql)?;
        let rows =
            stmt.query_map(p, |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, body, hash) = row?;
            let event: AuditEvent = serde_json::from_slice(&body)?;
            out.push(StoredEvent { seq, event, hash: ChainHash(blob32(hash)?) });
        }
        Ok(out)
    }
}

/// An `audit.query` filter. `host` must already be canonical.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    pub after_seq: i64,
    pub session: Option<String>,
    pub kind: Option<crate::EventKind>,
    pub decision: Option<crate::DecisionResult>,
    pub reason: Option<crate::Reason>,
    pub host: Option<String>,
    pub limit: u32,
}

impl Query {
    pub const MAX_LIMIT: u32 = 1000;
}

/// The hashed body: the event plus its sequence number.
fn body_for(ev: &AuditEvent, seq: i64) -> anyhow::Result<Vec<u8>> {
    let mut value = serde_json::to_value(ev)?;
    value.as_object_mut().ok_or_else(|| anyhow::anyhow!("event is not an object"))?.insert("seq".into(), seq.into());
    canonical_json(&value)
}

fn verify_conn(conn: &Connection) -> Result<u64, VerifyError> {
    let db = |e: rusqlite::Error| VerifyError::Db(e.to_string());
    let (version, genesis): (i64, Vec<u8>) = conn
        .query_row("SELECT format_version, genesis FROM meta", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()
        .map_err(db)?
        .ok_or(VerifyError::MissingMeta)?;
    if version != FORMAT_VERSION {
        return Err(VerifyError::UnsupportedVersion(version));
    }
    let mut prev: [u8; 32] = genesis.try_into().map_err(|_| VerifyError::MissingMeta)?;
    let mut stmt = conn
        .prepare("SELECT seq, body, prev, hash, ts, kind, session, request_id FROM events ORDER BY seq")
        .map_err(db)?;
    let mut rows = stmt.query([]).map_err(db)?;
    let mut expected = 1i64;
    let mut count = 0u64;
    while let Some(row) = rows.next().map_err(db)? {
        let seq: i64 = row.get(0).map_err(db)?;
        let body: Vec<u8> = row.get(1).map_err(db)?;
        let row_prev: Vec<u8> = row.get(2).map_err(db)?;
        let hash: Vec<u8> = row.get(3).map_err(db)?;
        if seq != expected {
            return Err(VerifyError::SequenceGap { expected, found: seq });
        }
        if row_prev.as_slice() != prev.as_slice() {
            return Err(VerifyError::BrokenLink(seq));
        }
        let recomputed = hash_link(&prev, &body);
        if hash.as_slice() != recomputed.as_slice() {
            return Err(VerifyError::HashMismatch(seq));
        }
        let parsed: serde_json::Value = serde_json::from_slice(&body).map_err(|_| VerifyError::BadBody(seq))?;
        if parsed.get("seq").and_then(|s| s.as_i64()) != Some(seq)
            || parsed.get("v").and_then(|v| v.as_u64()) != Some(1)
        {
            return Err(VerifyError::BadBody(seq));
        }
        // The columns lookups select on (`broker why`, `audit.query`, label
        // provenance) are not hashed themselves: they must equal the body.
        let col = |i: usize| -> Result<Option<String>, VerifyError> { row.get(i).map_err(db) };
        let field = |k: &str| parsed.get(k).and_then(|v| v.as_str()).map(str::to_string);
        if col(4)? != field("ts")
            || col(5)? != field("kind")
            || col(6)? != field("session")
            || col(7)? != field("request_id")
        {
            return Err(VerifyError::ColumnMismatch(seq));
        }
        prev = recomputed;
        expected += 1;
        count += 1;
    }
    Ok(count)
}

impl SqliteRecorder {
    /// Write a batch in order, in one transaction: one durable commit
    /// (synchronous=FULL) for all of it. The in-memory chain head moves only
    /// when the commit succeeds.
    fn commit_batch(&self, batch: &[AuditEvent]) -> anyhow::Result<Vec<ChainHash>> {
        let mut inner = self.inner.lock().map_err(|_| anyhow::anyhow!("audit lock poisoned"))?;
        let (mut prev, mut seq) = (inner.prev, inner.next_seq);
        let mut out = Vec::with_capacity(batch.len());
        let tx = inner.conn.transaction()?;
        for ev in batch {
            let body = body_for(ev, seq)?;
            let hash = hash_link(&prev, &body);
            tx.execute(
                "INSERT INTO events (seq, ts, kind, session, request_id, body, prev, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    seq,
                    ev.ts,
                    ev.kind.as_str(),
                    ev.session.as_ref().map(|s| s.as_str().to_string()),
                    ev.request_id.as_ref().map(|r| r.as_str().to_string()),
                    body,
                    prev.to_vec(),
                    hash.to_vec()
                ],
            )?;
            prev = hash;
            seq += 1;
            out.push(ChainHash(hash));
        }
        tx.commit()?;
        inner.prev = prev;
        inner.next_seq = seq;
        Ok(out)
    }
}

impl Recorder for SqliteRecorder {
    /// Durable before it returns (write-ahead, I9); concurrent appends share
    /// a commit (group commit).
    fn append(&self, ev: &AuditEvent) -> anyhow::Result<ChainHash> {
        self.group.append(ev, |batch| self.commit_batch(batch))
    }
}

#[cfg(test)]
mod tests;
