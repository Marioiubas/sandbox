pub mod approve;
pub mod audit;
pub mod audit_stats;
pub mod ctl;
pub mod daemon;
pub mod doctor;
pub mod export;
pub mod login;
pub mod mcp;
mod mcp_view;
pub mod policy;
pub mod run;
pub mod shadow;
pub mod suggest;
pub mod term;
pub mod why;

/// Exit code when the broker itself refuses or fails (not the agent's code).
pub const EXIT_BROKER: i32 = 125;
