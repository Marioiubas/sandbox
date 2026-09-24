//! tls: TLS-facing helpers.
//!
//! M0 ships only [`sni_peek`], used by the L4 path to require that a tunnel
//! starts with a ClientHello whose SNI canonicalises to the admitted host.
//! The per-session CA, leaf cache and trust-bundle writer arrive in M1
//! (TLS Termination and Per-Session CA). The CA is never installed into a
//! host trust store.

pub mod sni_peek;
