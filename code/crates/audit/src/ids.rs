//! Session and request identifiers (ULID text form, Crockford base32).

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 48-bit millisecond timestamp plus 80 random bits, 26 characters.
fn new_ulid() -> String {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) & 0xFFFF_FFFF_FFFF;
    let mut rnd = [0u8; 10];
    getrandom::fill(&mut rnd).expect("OS randomness unavailable");
    let mut v: u128 = (ms as u128) << 80;
    for (i, b) in rnd.iter().enumerate() {
        v |= (*b as u128) << (8 * (9 - i));
    }
    let mut out = [0u8; 26];
    for (i, slot) in out.iter_mut().enumerate() {
        let shift = 5 * (25 - i);
        *slot = CROCKFORD[((v >> shift) & 0x1F) as usize];
    }
    String::from_utf8(out.to_vec()).expect("ascii")
}

fn is_ulid(s: &str) -> bool {
    s.len() == 26 && s.bytes().all(|b| CROCKFORD.contains(&b))
}

/// Identifies one sandboxed session. Only [`SessionId::new`] and a validated
/// parse can construct it, so a session ID is always a well-formed ULID.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionId(String);

impl SessionId {
    pub fn new() -> Self {
        SessionId(new_ulid())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<String> for SessionId {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        if is_ulid(&s) { Ok(SessionId(s)) } else { Err(format!("invalid session id: {s:?}")) }
    }
}

impl From<SessionId> for String {
    fn from(s: SessionId) -> String {
        s.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", self.0)
    }
}

/// Identifies one decision; shown to the sandbox in deny responses so that
/// `broker why <request-id>` can explain it.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RequestId(String);

impl RequestId {
    pub fn new() -> Self {
        RequestId(format!("req-{}", new_ulid()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<String> for RequestId {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        match s.strip_prefix("req-") {
            Some(rest) if is_ulid(rest) => Ok(RequestId(s)),
            _ => Err(format!("invalid request id: {s:?}")),
        }
    }
}

impl From<RequestId> for String {
    fn from(r: RequestId) -> String {
        r.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestId({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_well_formed_and_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
        assert!(is_ulid(a.as_str()));
        let r = RequestId::new();
        assert!(RequestId::try_from(r.as_str().to_string()).is_ok());
        assert!(SessionId::try_from("../../etc".to_string()).is_err());
        assert!(RequestId::try_from("req-lowercase".to_string()).is_err());
    }
}
