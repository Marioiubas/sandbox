//! `broker`: the command-line client.
//!
//! A thin client: it holds no secrets and decides nothing. There is
//! deliberately no flag that disables the sandbox, the proxy or brokering
//! (I8); everything after `--` goes to the agent verbatim.

mod cmd;

use clap::{Parser, Subcommand};
use std::ffi::OsString;

const ABOUT: &str = "Run coding agents inside an OS sandbox whose only way out is the broker's egress proxy.";

const AFTER: &str = "\
What this does NOT do: it does not stop an injected agent from misusing \
authority the task legitimately holds; it limits what a hijacked agent can \
reach to the task's grants and records every decision outside the sandbox. \
Agent flags such as --dangerously-skip-permissions or --yolo change only \
the agent's own prompts, never the sandbox or the proxy. \
See docs/threat-model.md.";

#[derive(Parser, Debug)]
#[command(name = "broker", version, about = ABOUT, after_help = AFTER)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run a command (an agent) inside a sandboxed, brokered session.
    Run {
        /// Built-in agent profile (default: detected from the command name).
        #[arg(long)]
        profile: Option<String>,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<OsString>,
    },
    /// Run a command in record mode for policy learning: the same sandbox,
    /// proxy and credential rules; task permits relaxed to the org ceiling;
    /// every would-be deny recorded (then `broker suggest`).
    Learn {
        /// Built-in agent profile (default: detected from the command name).
        #[arg(long)]
        profile: Option<String>,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true, num_args = 1..)]
        command: Vec<OsString>,
    },
    /// Mine `broker learn` sessions into a proposed broker.toml diff with
    /// evidence and replay statistics (nothing is applied automatically).
    Suggest {
        /// Minimum number of sessions a request must appear in (P1).
        #[arg(long, default_value_t = 2)]
        min_runs: usize,
        /// Write the proposed TOML here instead of printing it.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
    /// Check every isolation layer on this host and show the active policy.
    Doctor,
    /// Explain a decision from the audit log.
    Why {
        /// The request ID printed in a deny (for example req-01J...).
        request_id: String,
    },
    /// Inspect the hash-chained audit log.
    Audit {
        #[command(subcommand)]
        action: AuditCmd,
    },
    /// Repository policy in `.broker/`: show its status or approve its
    /// current content (it only ever narrows your policy).
    Policy {
        #[command(subcommand)]
        action: PolicyCmd,
    },
    /// Manage the per-user daemon.
    Daemon {
        #[command(subcommand)]
        action: DaemonCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuditCmd {
    /// Verify the hash chain; exits non-zero at the first broken row.
    Verify,
    /// Show the most recent events.
    Tail {
        #[arg(short = 'n', default_value_t = 20)]
        n: u32,
    },
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Show whether this repository's policy is present and approved.
    Status,
    /// Approve the repository policy's current content hash.
    Approve,
}

#[derive(Subcommand, Debug)]
pub enum DaemonCmd {
    Status,
    Stop,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Run { profile, command } => cmd::run::run(profile, command),
        Command::Learn { profile, command } => cmd::run::learn(profile, command),
        Command::Suggest { min_runs, out } => cmd::suggest::suggest(min_runs, out),
        Command::Doctor => cmd::doctor::doctor(),
        Command::Why { request_id } => cmd::why::why(&request_id),
        Command::Audit { action: AuditCmd::Verify } => cmd::audit::verify(),
        Command::Audit { action: AuditCmd::Tail { n } } => cmd::audit::tail(n),
        Command::Policy { action: PolicyCmd::Status } => cmd::policy::status(),
        Command::Policy { action: PolicyCmd::Approve } => cmd::policy::approve(),
        Command::Daemon { action: DaemonCmd::Status } => cmd::daemon::status(),
        Command::Daemon { action: DaemonCmd::Stop } => cmd::daemon::stop(),
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// I8: enumerate every flag of every subcommand; none may name a way to
    /// turn off isolation, egress control or brokering.
    #[test]
    fn no_flag_disables_isolation() {
        let forbidden = [
            "sandbox",
            "insecure",
            "direct",
            "allow-all",
            "no-proxy",
            "unsafe",
            "yolo",
            "skip",
            "disable",
            "bypass",
            "trust",
            "host-network",
            "no-audit",
        ];
        let root = Cli::command();
        let mut stack = vec![root];
        let mut seen = 0;
        while let Some(c) = stack.pop() {
            for a in c.get_arguments() {
                let name = a.get_long().unwrap_or(a.get_id().as_str()).to_lowercase();
                seen += 1;
                for f in forbidden {
                    assert!(!name.contains(f), "flag --{name} on `{}` looks like an isolation bypass", c.get_name());
                }
            }
            stack.extend(c.get_subcommands().cloned());
        }
        assert!(seen > 0);
        let run = Cli::command().find_subcommand("run").unwrap().clone();
        let longs: Vec<_> = run.get_arguments().filter_map(|a| a.get_long()).collect();
        assert_eq!(longs, vec!["profile"], "run accepts exactly one option; review any addition against I8");
        let learn = Cli::command().find_subcommand("learn").unwrap().clone();
        let longs: Vec<_> = learn.get_arguments().filter_map(|a| a.get_long()).collect();
        assert_eq!(longs, vec!["profile"], "learn accepts exactly one option; review any addition against I8");
    }

    #[test]
    fn agent_flags_after_dashdash_are_passed_verbatim() {
        let cli =
            Cli::try_parse_from(["broker", "run", "--", "claude", "--dangerously-skip-permissions", "--profile", "x"])
                .unwrap();
        match cli.command {
            Command::Run { profile, command } => {
                assert_eq!(profile, None);
                assert_eq!(command, vec!["claude", "--dangerously-skip-permissions", "--profile", "x"]);
            }
            _ => panic!(),
        }
        assert!(Cli::try_parse_from(["broker", "run"]).is_err(), "a command is required");
    }
}
