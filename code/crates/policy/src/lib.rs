//! policy: what a session may reach.
//!
//! M0 ships the host-admission slice: an egress allowlist of canonical host
//! patterns and ports, address-class grants, and the built-in DNS-over-HTTPS
//! deny list. Every rule is fail-closed: an empty list grants nothing, an
//! unknown key is a compile error, an entry with no ports reaches nothing.
//! Cedar, the TOML→Cedar compiler and repo-layer narrowing arrive in M2
//! (Policy Engine and Entity Builder); until then repository `.broker/`
//! files are never loaded (I4, I5).

pub mod config;
pub mod doh;
pub mod egress;

pub use config::{AgentSection, FsSection, PolicyFile, ProfileFile, load_policy_file, load_profile_str};
pub use egress::{Admission, EgressPolicy, Grant};
