//! A pinned MCP server as its own sandboxed session (MCP Guard): the pinned
//! command from user or org policy, the server's own egress grants (its
//! credentials reach it as sentinels), a fresh working directory per
//! session (never inside broker state, which no sandbox may write: I5).
//! Never the agent's policy, a shadow candidate or another MCP server.

use super::{Daemon, Running, StartFailure};
use crate::dirs::passwd_user;
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
}

impl Daemon {
    /// Boxed: a server session is started from inside an agent session's
    /// pipeline, which a session launch itself starts (the future is
    /// otherwise recursive).
    pub fn start_mcp_server<'a>(
        self: &'a Arc<Self>,
        name: &'a str,
        cfg: &'a McpServerConfig,
        user: &'a PolicyFile,
    ) -> Pin<Box<dyn Future<Output = Result<McpProcess, StartFailure>> + Send + 'a>> {
        Box::pin(async move {
            let id = SessionId::new();
            let r = self.start_mcp_inner(&id, name, cfg, user).await;
            if let Err(f) = &r {
                let argv0 = cfg.command.first().map(String::as_str).unwrap_or("");
                self.refuse(&id, argv0, &f.message, &f.layers);
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
    ) -> Result<McpProcess, StartFailure> {
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
        let assembled = self.assemble_layers(id, &params, &dir, &u.name, profile, layer, false, None)?;
        let running = self
            .start_assembled(id, params, dir.clone(), &u.dir, &u.name, assembled, [in_r.into(), out_w.into(), err])
            .await?;
        std::mem::forget(cleanup);
        Ok(McpProcess { running, stdin: in_w, stdout: out_r, workdir: dir })
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
