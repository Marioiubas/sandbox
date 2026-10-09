use super::*;
use crate::{EventKind, Reason};

fn sample(i: u32) -> AuditEvent {
    let s = SessionId::new();
    let ev = AuditEvent::new(EventKind::RequestDecision).session(&s).request(&RequestId::new());
    if i.is_multiple_of(2) {
        ev.deny(Reason::HostNotAllowed, vec![]).detail("i", i)
    } else {
        ev.allow(vec!["grant:egress[0]".into()]).detail("i", i)
    }
}

fn fresh(n: u32) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let rec = SqliteRecorder::open(&path).unwrap();
    for i in 0..n {
        rec.append(&sample(i)).unwrap();
    }
    (dir, path)
}

#[test]
fn concurrent_appends_share_commits_and_keep_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let rec = std::sync::Arc::new(SqliteRecorder::open(&path).unwrap());
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let r = rec.clone();
            std::thread::spawn(move || (0..50).map(|i| r.append(&sample(t * 100 + i)).unwrap()).collect::<Vec<_>>())
        })
        .collect();
    let mut hashes: Vec<ChainHash> = threads.into_iter().flat_map(|h| h.join().unwrap()).collect();
    assert_eq!(SqliteRecorder::verify_path(&path).unwrap(), 400, "one gap-free chain");
    hashes.sort_by_key(|h| h.to_hex());
    hashes.dedup();
    assert_eq!(hashes.len(), 400, "every caller got its own row");
}

#[test]
fn a_failed_commit_fails_its_callers_and_leaves_the_chain_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let rec = SqliteRecorder::open(&path).unwrap();
    rec.append(&sample(1)).unwrap();
    rec.inner.lock().unwrap().conn.pragma_update(None, "query_only", true).unwrap();
    assert!(rec.append(&sample(2)).is_err(), "no durable row, no success (I9)");
    rec.inner.lock().unwrap().conn.pragma_update(None, "query_only", false).unwrap();
    rec.append(&sample(3)).unwrap();
    assert_eq!(SqliteRecorder::verify_path(&path).unwrap(), 2);
}

#[test]
fn chain_verifies_and_survives_reopen() {
    let (_d, path) = fresh(5);
    assert_eq!(SqliteRecorder::verify_path(&path), Ok(5));
    let rec = SqliteRecorder::open(&path).unwrap();
    rec.append(&sample(9)).unwrap();
    assert_eq!(rec.verify(), Ok(6));
}

#[test]
fn tamper_one_byte_fails_at_that_row() {
    let (_d, path) = fresh(5);
    let c = Connection::open(&path).unwrap();
    let body: Vec<u8> = c.query_row("SELECT body FROM events WHERE seq = 3", [], |r| r.get(0)).unwrap();
    // Row 3 carries detail i = 2; change it to 7 (one byte).
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("\"i\":2"));
    let tampered = text.replacen("\"i\":2", "\"i\":7", 1);
    c.execute("UPDATE events SET body = ?1 WHERE seq = 3", params![tampered.into_bytes()]).unwrap();
    assert_eq!(SqliteRecorder::verify_path(&path), Err(VerifyError::HashMismatch(3)));
    assert!(SqliteRecorder::open(&path).is_err(), "open must refuse a broken chain");
}

#[test]
fn delete_row_fails() {
    let (_d, path) = fresh(5);
    let c = Connection::open(&path).unwrap();
    c.execute("DELETE FROM events WHERE seq = 2", []).unwrap();
    assert_eq!(SqliteRecorder::verify_path(&path), Err(VerifyError::SequenceGap { expected: 2, found: 3 }));
}

#[test]
fn delete_tail_is_detected_only_by_anchor() {
    // Truncating the tail leaves a valid prefix; that is why exports carry
    // the last chain hash as an anchor (M2). Document the limit in a test.
    let (_d, path) = fresh(5);
    let c = Connection::open(&path).unwrap();
    c.execute("DELETE FROM events WHERE seq = 5", []).unwrap();
    assert_eq!(SqliteRecorder::verify_path(&path), Ok(4));
}

#[test]
fn swap_rows_fails() {
    let (_d, path) = fresh(5);
    let c = Connection::open(&path).unwrap();
    let b2: Vec<u8> = c.query_row("SELECT body FROM events WHERE seq = 2", [], |r| r.get(0)).unwrap();
    let b4: Vec<u8> = c.query_row("SELECT body FROM events WHERE seq = 4", [], |r| r.get(0)).unwrap();
    c.execute("UPDATE events SET body = ?1 WHERE seq = 2", params![b4]).unwrap();
    c.execute("UPDATE events SET body = ?1 WHERE seq = 4", params![b2]).unwrap();
    assert_eq!(SqliteRecorder::verify_path(&path), Err(VerifyError::HashMismatch(2)));
}

#[test]
fn rehashed_edit_breaks_next_link() {
    // An attacker who recomputes row 3's hash still breaks row 4's link.
    let (_d, path) = fresh(5);
    let c = Connection::open(&path).unwrap();
    let (prev, ts, kind): (Vec<u8>, String, String) = c
        .query_row("SELECT prev, ts, kind FROM events WHERE seq = 3", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap();
    // A forged body consistent with its columns (so only the link can tell).
    let body = serde_json::to_vec(&serde_json::json!({"seq": 3, "v": 1, "ts": ts, "kind": kind})).unwrap();
    let h = hash_link(&prev.try_into().unwrap(), &body);
    c.execute(
        "UPDATE events SET body = ?1, hash = ?2, session = NULL, request_id = NULL WHERE seq = 3",
        params![body, h.to_vec()],
    )
    .unwrap();
    assert_eq!(SqliteRecorder::verify_path(&path), Err(VerifyError::BrokenLink(4)));
}

#[test]
fn query_by_request_and_session() {
    let dir = tempfile::tempdir().unwrap();
    let rec = SqliteRecorder::open(&dir.path().join("a.db")).unwrap();
    let s = SessionId::new();
    let r = RequestId::new();
    rec.append(&AuditEvent::new(EventKind::RequestDecision).session(&s).request(&r).deny(Reason::MetadataAddr, vec![]))
        .unwrap();
    rec.append(&AuditEvent::new(EventKind::SessionStop).session(&s)).unwrap();
    let got = rec.by_request(&r).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].event.reason, Some(Reason::MetadataAddr));
    assert_eq!(rec.by_session(&s).unwrap().len(), 2);
    assert_eq!(rec.tail(1).unwrap()[0].event.kind, EventKind::SessionStop);
}

/// Review (I9 points 3 and 5): every row stores `session`, `request_id`
/// and `kind` in columns beside the chained `body`, and those columns
/// are what `broker why` (`by_request`), `by_session`, `audit.query`
/// (`query_filtered`) and the approval view's provenance select on.
/// `verify` never compares them with the body, so editing them hides a
/// decision from `broker why <request-id>` (or moves it to another
/// session or kind) while `broker audit verify` still reports the chain
/// intact, and exported anchors still match.
#[test]
fn review_query_columns_are_covered_by_verification() {
    let (_d, path) = fresh(5);
    let row3 = SqliteRecorder::open_read_only(&path).unwrap().range(2, 3).unwrap().remove(0);
    let rid = row3.event.request_id.clone().unwrap();
    let c = Connection::open(&path).unwrap();
    c.execute(
        "UPDATE events SET request_id = ?1, session = NULL, kind = 'session.ready' WHERE seq = 3",
        params![RequestId::new().as_str()],
    )
    .unwrap();
    drop(c);
    let found = SqliteRecorder::open_read_only(&path).unwrap().by_request(&rid).unwrap();
    assert!(found.is_empty(), "precondition: the edit hides row 3 from `broker why {rid}`");
    assert!(
        SqliteRecorder::verify_path(&path).is_err(),
        "row 3 no longer answers `broker why {rid}`, `audit.query` by session or kind (its request_id, session and \
         kind columns were edited), yet the chain verifies: {:?}",
        SqliteRecorder::verify_path(&path)
    );
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]
    #[test]
    fn any_single_body_mutation_is_detected(n in 2u32..8, victim in 1i64..8, flip in 0usize..64) {
        let (_d, path) = fresh(n);
        let victim = 1 + (victim - 1) % n as i64;
        let c = Connection::open(&path).unwrap();
        let mut body: Vec<u8> = c.query_row("SELECT body FROM events WHERE seq = ?1", [victim], |r| r.get(0)).unwrap();
        let idx = flip % body.len();
        body[idx] ^= 0x01;
        c.execute("UPDATE events SET body = ?1 WHERE seq = ?2", params![body, victim]).unwrap();
        proptest::prop_assert!(SqliteRecorder::verify_path(&path).is_err());
    }
}
