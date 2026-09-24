//! brokerd: the per-user broker daemon.
//!
//! It owns everything with authority on the endpoint: the session table, the
//! data-plane listeners, the policy, the resolver and the audit writer. It
//! never listens on TCP for control, and no sandbox can reach `ctl.sock`.

pub mod audit_query;
pub mod dirs;
pub mod l7_pipeline;
pub mod mcp;
pub mod pipeline;
pub mod profiles;
pub mod proto;
pub mod repo_policy;
pub mod rewind;
pub mod server;
pub mod session;
pub mod session_l7;
pub mod session_util;
pub mod shadow;
pub mod upstream;
