//! A pinned MCP server as its own sandboxed session (MCP Guard): the pinned
//! command from user or org policy, checked by content right before it
//! starts (ADR-047: `mcp::command`), the server's own egress grants (its
//! credentials reach it as sentinels), a fresh working directory per
//! session (never inside broker state, which no sandbox may write: I5).
//! Never the agent's policy, a shadow candidate or another MCP server; but
//! always the agent session's labels (ADR-038): a server is started for one
//! agent session, what it reads raises that session's labels, and its own
//! requests are judged with them.

use super::{Daemon, Running, SessionKind, StartFailure};
use crate::dirs::passwd_user;
use crate::labels::LabelOwner;
use crate::mcp::command::{Gate, Refusal};
use crate::proto::StartParams;
use audit::SessionId;
use policy::mcp::McpServerConfig;
use policy::{PolicyFile, ProfileFile};
use std::collections::BTreeMap;
use std::future::Future;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::Arc;

/// A started server: its session and the agent-facing ends of its stdio.
pub struct McpProcess {
    pub running: Running,
    pub stdin: std::io::PipeWriter,
    pub stdout: std::io::PipeReader,
    /// The server's working directory; remove it after teardown.
    pub workdir: std::path::PathBuf,
    /// The command's pin, taken right before the server started.
    pub command: serde_json::Value,
}

/// Why a pinned server was not started.
pub enum McpStartError {
    /// The command gate refused it before it ran (ADR-047).
    Refused(Refusal),
    Failed(StartFailure),
}

impl<E: std::fmt::Display> From<E> for McpStartError {
    fn from(e: E) -> Self {
        McpStartError::Failed(e.into())
    }
}

impl Daemon {
    /// Start `name` for the agent session `owner` names: the server's
    /// session carries that session's labels (ADR-038). There is no way to
    /// start one with labels of its own. `gate` is checked right before the
    /// command runs.
    ///
    /// Boxed: a server session is started from inside an agent session's
    /// pipeline, which a session launch itself starts (the future is
    /// otherwise recursive).
    pub fn start_mcp_server<'a>(
        self: &'a Arc<Self>,
        name: &'a str,
        cfg: &'a McpServerConfig,
        user: &'a PolicyFile,
        owner: LabelOwner,
        gate: Gate,
    ) -> Pin<Box<dyn Future<Output = Result<McpProcess, McpStartError>> + Send + 'a>> {
        Box::pin(async move {
            let id = SessionId::new();
            let r = self.start_mcp_inner(&id, name, cfg, user, &owner, gate).await;
            let argv0 = cfg.command.first().map(String::as_str).unwrap_or("");
            match &r {
                Err(McpStartError::Failed(f)) => self.refuse(&id, argv0, &f.message, &f.layers),
                Err(McpStartError::Refused(why)) => self.refuse(&id, argv0, &why.message(), &[]),
                Ok(_) => {}
            }
            r
        })
    }

    async fn start_mcp_inner(
        self: &Arc<Self>,
        id: &SessionId,
        name: &str,
        cfg: &McpServerConfig,
        user: &PolicyFile,
        owner: &LabelOwner,
        gate: Gate,
    ) -> Result<McpProcess, McpStartError> {
        let u = passwd_user()?;
        let dir = std::env::temp_dir().join(format!("broker-mcp-{name}-{id}"));
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        }
        let dir = dir.canonicalize()?;
        let cleanup = scopeguard(dir.clone());
        let (in_r, in_w) = std::io::pipe()?;
        let (out_r, out_w) = std::io::pipe()?;
        let err: OwnedFd = std::fs::OpenOptions::new().write(true).open("/dev/null")?.into();
        let params = StartParams {
            argv: cfg.command.clone(),
            cwd: dir.display().to_string(),
            profile: None,
            env: BTreeMap::from([("PATH".to_string(), "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin".to_string())]),
            mode: None,
            identity_token: None,
        };
        let profile = ProfileFile { version: 1, name: format!("mcp:{name}"), ..Default::default() };
        let layer = PolicyFile {
            version: 1,
            egress: cfg.egress.clone(),
            issuers: user.issuers.clone(),
            tls: user.tls.clone(),
            ..Default::default()
        };
        let assembled = self
            .assemble_layers(id, &params, &dir, &u.name, profile, layer, SessionKind::McpServer(owner), None)
            .map_err(McpStartError::Failed)?;
        // Last step before the exec: the command by content, against the
        // approval and the agent session's writable mounts (ADR-047).
        let (argv, cwd) = (params.argv.clone(), dir.clone());
        let command = tokio::task::spawn_blocking(move || gate.check(&argv, &cwd))
            .await
            .map_err(|e| McpStartError::Failed(format!("command check: {e}").into()))?
            .map_err(McpStartError::Refused)?;
        let running = self
            .start_assembled(id, params, dir.clone(), &u.dir, &u.name, assembled, [in_r.into(), out_w.into(), err])
            .await
            .map_err(McpStartError::Failed)?;
        std::mem::forget(cleanup);
        Ok(McpProcess { running, stdin: in_w, stdout: out_r, workdir: dir, command })
    }
}

/// Removes the working directory unless the launch succeeded.
struct RemoveOnDrop(std::path::PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scopeguard(p: std::path::PathBuf) -> RemoveOnDrop {
    RemoveOnDrop(p)
}
