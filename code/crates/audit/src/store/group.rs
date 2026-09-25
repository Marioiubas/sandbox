//! Group commit (Audit Recorder and Event Schema, design point 3): appends
//! that arrive while a commit is in progress wait and go into the next
//! commit together, so concurrent decisions share one durable write. Every
//! caller still returns only after the commit that holds its event
//! (write-ahead, I9); a failed commit fails every event in it, and the
//! chain state is left as it was.

use crate::{AuditEvent, ChainHash};
use std::collections::HashMap;
use std::sync::{Condvar, Mutex};

#[derive(Default)]
struct State {
    queue: Vec<(u64, AuditEvent)>,
    done: HashMap<u64, Result<ChainHash, String>>,
    next: u64,
    committing: bool,
}

#[derive(Default)]
pub(super) struct Group {
    state: Mutex<State>,
    cv: Condvar,
}

/// Marks a leader's batch failed if the commit unwinds, so the waiters
/// return an error instead of waiting forever.
struct Guard<'a> {
    group: &'a Group,
    tickets: Vec<u64>,
    finished: bool,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Ok(mut st) = self.group.state.lock() {
            for t in &self.tickets {
                st.done.insert(*t, Err("the audit commit failed".into()));
            }
            st.committing = false;
        }
        self.group.cv.notify_all();
    }
}

impl Group {
    /// Queue `ev` and return once a commit holding it has finished.
    /// `commit` writes a batch in order, in one transaction, and returns
    /// one chain hash per event.
    pub(super) fn append(
        &self,
        ev: &AuditEvent,
        commit: impl Fn(&[AuditEvent]) -> anyhow::Result<Vec<ChainHash>>,
    ) -> anyhow::Result<ChainHash> {
        let poisoned = || anyhow::anyhow!("audit lock poisoned");
        let mut st = self.state.lock().map_err(|_| poisoned())?;
        let ticket = st.next;
        st.next += 1;
        st.queue.push((ticket, ev.clone()));
        loop {
            if let Some(r) = st.done.remove(&ticket) {
                return r.map_err(|e| anyhow::anyhow!(e));
            }
            if st.committing {
                st = self.cv.wait(st).map_err(|_| poisoned())?;
                continue;
            }
            // Lead: take everything queued so far and commit it at once.
            st.committing = true;
            let (tickets, events): (Vec<u64>, Vec<AuditEvent>) = std::mem::take(&mut st.queue).into_iter().unzip();
            drop(st);
            let mut guard = Guard { group: self, tickets: tickets.clone(), finished: false };
            let res = commit(&events);
            st = self.state.lock().map_err(|_| poisoned())?;
            match res {
                Ok(hashes) if hashes.len() == tickets.len() => {
                    for (t, h) in tickets.into_iter().zip(hashes) {
                        st.done.insert(t, Ok(h));
                    }
                }
                Ok(_) => {
                    for t in tickets {
                        st.done.insert(t, Err("the audit commit returned the wrong number of rows".into()));
                    }
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    for t in tickets {
                        st.done.insert(t, Err(msg.clone()));
                    }
                }
            }
            st.committing = false;
            guard.finished = true;
            self.cv.notify_all();
        }
    }
}
