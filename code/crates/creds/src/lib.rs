//! creds: the only code that touches real credential material, and it runs
//! only inside brokerd (Credential Injector and Issuers).
//!
//! - [`sentinel`]: per-session placeholders, bound to hosts; the only
//!   "credentials" the sandbox ever sees (I1).
//! - [`foreign`]: strip client credentials; reject any the broker did not
//!   issue (I7).
//! - [`secrets`]: read roots from the OS keychain, brokerd's environment or
//!   the broker config directory.
//! - [`issuers`]: `static` and `github_app` (installation tokens limited to
//!   repositories and permissions, always both).
//! - [`session`]: per-session issued-token cache keyed by scope digest.
//!
//! Secret material lives in [`Secret`] (zeroized on drop, no `Clone`,
//! redacted `Debug`) and never reaches an audit row, an error message or the
//! sandbox environment.

pub mod foreign;
pub mod issuers;
pub mod secrets;
pub mod sentinel;
pub mod session;

use std::time::SystemTime;
use zeroize::Zeroizing;

/// Secret bytes. Deliberately not `Clone`; `Debug` never prints them.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    pub fn new(v: Vec<u8>) -> Secret {
        Secret(Zeroizing::new(v))
    }
    /// The bytes, for attaching to an outgoing request only.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// A non-reversible identifier for audit rows (`sha256` prefix).
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(&*self.0);
        format!("sha256:{}", &hex::encode(d)[..16])
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(<{} bytes redacted>)", self.0.len())
    }
}

/// A credential ready to attach: the secret plus what the audit log may
/// know about it.
pub struct Issued {
    pub credential_id: String,
    pub kind: &'static str,
    secret: Secret,
    /// Upstream expiry, if the issuer reported one.
    pub expires_at: Option<SystemTime>,
    /// When this handle stops being reused (min of expiry and declared ttl).
    pub reuse_until: Option<SystemTime>,
    pub scope_digest: [u8; 32],
    /// `mint` or `load`, for audit rows.
    pub origin: &'static str,
}

impl Issued {
    pub fn new(
        credential_id: &str,
        kind: &'static str,
        secret: Secret,
        expires_at: Option<SystemTime>,
        reuse_until: Option<SystemTime>,
        scope_digest: [u8; 32],
        origin: &'static str,
    ) -> Issued {
        Issued { credential_id: credential_id.to_string(), kind, secret, expires_at, reuse_until, scope_digest, origin }
    }
    pub fn secret(&self) -> &Secret {
        &self.secret
    }
    pub fn fingerprint(&self) -> String {
        self.secret.fingerprint()
    }
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("credential_id", &self.credential_id)
            .field("kind", &self.kind)
            .field("expires_at", &self.expires_at)
            .field("secret", &self.secret)
            .finish()
    }
}

pub use foreign::{CredentialUse, inspect, strip};
pub use issuers::attach;
pub use sentinel::{SentinelCheck, Sentinels};
pub use session::{MintError, SessionCreds};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new(b"canary-secret-value".to_vec());
        let d = format!("{s:?}");
        assert!(!d.contains("canary"));
        let i = Issued::new("c", "static", s, None, None, [0; 32], "load");
        assert!(!format!("{i:?}").contains("canary"));
        assert!(i.fingerprint().starts_with("sha256:"));
        assert!(!i.fingerprint().contains("canary"));
    }
}
