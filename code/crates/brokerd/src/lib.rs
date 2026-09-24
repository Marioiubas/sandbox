//! brokerd: the per-user broker daemon.
//!
//! It owns everything with authority on the endpoint: the session table, the
//! data-plane listeners, the policy, the resolver and the audit writer. It
//! never listens on TCP for control, and no sandbox can reach `ctl.sock`.

pub mod dirs;
pub mod pipeline;
pub mod profiles;
pub mod proto;
pub mod server;
pub mod session;
