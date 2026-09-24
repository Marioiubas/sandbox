//! tls: everything TLS-shaped on the broker side.
//!
//! - [`sni_peek`]: strict ClientHello parser (L4 path, M0).
//! - [`session_ca`]: per-session CA and cached leaf certificates (L7 path).
//! - [`trust_bundle`]: the sandbox's bundle (session CA + public roots) and
//!   the environment variables that point clients at it.
//! - [`upstream`]: verified TLS toward upstreams.
//!
//! The session CA is never installed into a host trust store, and its key
//! never leaves brokerd memory.

pub mod session_ca;
pub mod sni_peek;
pub mod trust_bundle;
pub mod upstream;
