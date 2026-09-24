pub mod audit;
pub mod ctl;
pub mod daemon;
pub mod doctor;
pub mod run;
pub mod why;

/// Exit code when the broker itself refuses or fails (not the agent's code).
pub const EXIT_BROKER: i32 = 125;
