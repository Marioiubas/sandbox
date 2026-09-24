//! netguard: the only route out of the sandbox.
//!
//! - [`canon`]: the single canonicaliser (I6); `CanonicalHost` and
//!   `CanonicalPath` can only be built here.
//! - [`resolver`]: broker-owned DNS; the only caller of the system resolver.
//! - [`ingress`]: CONNECT and SOCKS5 handshakes on the per-session channel.
//! - [`splice`]: the L4 relay.
//!
//! Enforcement never depends on proxy environment variables: the sandbox has
//! no other route (topology, ADR-003).

pub mod canon;
pub mod ingress;
pub mod resolver;
pub mod splice;

pub use canon::{
    AddrClass, CanonicalHost, CanonicalPath, HostKind, HostPattern, Reject, canon_host, canon_path, classify_addr,
};
