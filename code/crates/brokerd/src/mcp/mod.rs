//! MCP Guard in the daemon. The agent's MCP configuration names only the
//! stub `broker mcp connect <name>`, which reaches the daemon through the
//! session's own proxy as `<name>.mcp.broker.internal:1`. The daemon starts
//! the command pinned for that name in user or org policy, in its own
//! sandbox with its own egress grants, pins its manifest and relays
//! JSON-RPC with every `tools/call` authorized. The agent can name a
//! server; it cannot choose its command (I5).

pub mod pin;
mod relay;

use crate::dirs::BrokerDirs;
use crate::pipeline::{Outcome, PipelineCtx};
use crate::proto::Exited;
use crate::session::Daemon;
use audit::{Dest, Reason, RequestId};
use netguard::CanonicalHost;
use netguard::ingress::IngressKind;
use policy::PolicyFile;
use relay::{FrameReader, Pin, Relay, send};
use std::collections::HashSet;
use std::sync::{Arc, Weak};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};

/// Reserved names: `<server>.mcp.broker.internal`, port 1. They never reach
/// DNS or the network.
pub const RESERVED_SUFFIX: &str = ".mcp.broker.internal";
pub const PORT: u16 = 1;

/// Per agent session: the daemon (to start servers) and the user policy
/// that defines them.
pub struct McpCtx {
    pub daemon: Weak<Daemon>,
    pub user: PolicyFile,
    pub dirs: BrokerDirs,
}

/// The server a reserved host names, if it is one and it is defined.
pub fn server_for<'a>(ctx: &'a PipelineCtx, host: &CanonicalHost, port: u16) -> Option<&'a str> {
    let name = host.as_str().strip_suffix(RESERVED_SUFFIX)?;
    let m = ctx.mcp.as_ref()?;
    (port == PORT && policy::mcp::valid_name(name))
        .then(|| m.user.mcp.get_key_value(name).map(|(k, _)| k.as_str()))
        .flatten()
}

/// Serve an accepted connection (the CONNECT was answered) until either
/// side closes; returns the number of agent frames handled.
pub async fn serve<S>(ctx: Arc<PipelineCtx>, name: String, client: S, kind: IngressKind) -> Outcome
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let rid = RequestId::new();
    let dest = Dest {
        ingress: Some(kind.as_str().to_string()),
        host: Some(format!("{name}{RESERVED_SUFFIX}")),
        port: Some(PORT),
        ..Default::default()
    };
    let Some(m) = ctx.mcp.clone() else { return Outcome::Denied { request_id: rid, reason: Reason::McpServerUnknown } };
    let Some(cfg) = m.user.mcp.get(&name).cloned() else {
        return Outcome::Denied { request_id: rid, reason: Reason::McpServerUnknown };
    };
    let (agent_r, mut agent_w) = tokio::io::split(client);
    let mut agent_r = FrameReader::new(BufReader::new(agent_r));

    // Start and pin the server before anything from the agent is relayed.
    let started = match m.daemon.upgrade() {
        Some(d) => d.start_mcp_server(&name, &cfg, &m.user).await.map_err(|f| f.message).map(|p| (d, p)),
        None => Err("the daemon is shutting down".into()),
    };
    let mut server = None;
    let mut refused_early: Vec<String> = Vec::new();
    let (pin, init, server_session) = match started {
        Err(e) => (Pin::Failed(e), serde_json::Value::Null, String::new()),
        Ok((d, mut p)) => {
            let sid = p.running.id.to_string();
            let io = (
                tokio::net::unix::pipe::Sender::from_owned_fd(p.stdin.into()),
                tokio::net::unix::pipe::Receiver::from_owned_fd(p.stdout.into()),
            );
            match io {
                (Ok(mut w), Ok(r)) => {
                    let mut r = FrameReader::new(BufReader::new(r));
                    let pinned = tokio::time::timeout(relay::pin_timeout(), relay::handshake(&mut r, &mut w)).await;
                    let (pin, init) = match pinned {
                        Ok(Ok((init, man, refused))) => {
                            refused_early = refused;
                            let _ = pin::record_seen(&m.dirs, &name, &man);
                            let pin = match pin::approved(&m.dirs, &name) {
                                None => Pin::Unapproved(man),
                                Some(sha) if sha == man.sha256 => Pin::Pinned(man),
                                Some(expected) => {
                                    let old =
                                        pin::approved_manifest(&m.dirs, &name).map(|a| a.tools).unwrap_or_default();
                                    Pin::Changed { diff: pin::diff(&old, &man.tools), expected, got: man }
                                }
                            };
                            (pin, init)
                        }
                        Ok(Err(e)) => (Pin::Failed(e), serde_json::Value::Null),
                        Err(_) => (
                            Pin::Failed("the server did not answer initialize/tools/list in time".into()),
                            serde_json::Value::Null,
                        ),
                    };
                    let child = p.running.take_child();
                    server = Some((w, r, d, p.running, child, p.workdir));
                    (pin, init, sid)
                }
                _ => {
                    p.running.teardown(&d, &Exited { code: None, signal: None });
                    let _ = std::fs::remove_dir_all(&p.workdir);
                    (Pin::Failed("the server's stdio could not be attached".into()), serde_json::Value::Null, sid)
                }
            }
        }
    };
    let mut relay = Relay {
        ctx: &ctx,
        name: &name,
        cfg: &cfg,
        dest,
        server_session,
        pin,
        init,
        pending: HashSet::new(),
        relist: None,
        relists: 0,
    };
    relay.record_connect();
    for m in refused_early {
        let _ = relay.deny(None, Reason::McpMethodNotAllowed, format!("mcp.server.{m} {name}"), vec![]);
    }

    let mut frames = 0u64;
    let mut agent_open = true;
    let mut drain_until = None;
    loop {
        if !agent_open && relay.pending.is_empty() {
            break;
        }
        let sleep =
            tokio::time::sleep_until(drain_until.unwrap_or_else(|| tokio::time::Instant::now() + relay::drain()));
        tokio::select! {
            line = agent_r.next(), if agent_open => match line {
                Ok(Some(Some(b))) => {
                    frames += 1;
                    let (reply, fwd) = relay.on_agent(&b);
                    if let Some(r) = reply && send(&mut agent_w, &r).await.is_err() { break; }
                    if let Some(f) = fwd {
                        let sent = match server.as_mut() {
                            Some((w, ..)) => send(w, &f).await.is_ok(),
                            None => false,
                        };
                        if !sent {
                            break;
                        }
                    }
                }
                Ok(Some(None)) => {
                    frames += 1;
                    let _ = relay.deny(None, Reason::McpMalformed, "mcp.frame".into(), vec![]);
                }
                Ok(None) | Err(_) => {
                    agent_open = false;
                    drain_until = Some(tokio::time::Instant::now() + relay::drain());
                }
            },
            line = async {
                match server.as_mut() {
                    Some((_, r, ..)) => r.next().await,
                    None => std::future::pending().await,
                }
            } => match line {
                Ok(Some(Some(b))) => {
                    let (to_agent, to_server) = relay.on_server(&b);
                    if let Some(a) = to_agent && send(&mut agent_w, &a).await.is_err() { break; }
                    if let (Some(s), Some((w, ..))) = (to_server, server.as_mut()) && send(w, &s).await.is_err() { break; }
                }
                Ok(Some(None)) => {}
                Ok(None) | Err(_) => break,
            },
            _ = sleep, if !agent_open => break,
        }
    }
    use tokio::io::AsyncWriteExt;
    let _ = agent_w.shutdown().await;
    if let Some((w, r, d, running, child, workdir)) = server {
        drop((w, r));
        running.teardown(&d, &Exited { code: None, signal: Some(9) });
        if let Some(mut c) = child {
            let _ = tokio::task::spawn_blocking(move || c.wait()).await;
        }
        let _ = std::fs::remove_dir_all(workdir);
    }
    Outcome::Terminated { request_id: rid, requests: frames }
}
