//! l7: what happens on a terminated connection, minus the I/O.
//!
//! - [`head`]: CONNECT = SNI = Host, canonical path, no upgrades.
//! - [`git`]: smart-HTTP routes, pkt-line, receive-pack and pack parsing,
//!   per-ref `git.push` actions with force derived from the pushed pack.
//! - [`filter`]: the streaming response filter (I1).
//! - [`classify`]: request → policy actions for the protocols a host has.
//!
//! brokerd wires these into the TLS/HTTP pipeline; every parser here has
//! property tests and a cargo-fuzz target (`tests/fuzz`).

pub mod classify;
pub mod filter;
pub mod git;
pub mod head;
