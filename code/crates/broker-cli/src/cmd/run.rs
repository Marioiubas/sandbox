//! `broker run -- <command>`.

use super::{EXIT_BROKER, ctl};
use brokerd::proto::{self, Exited, Incoming, Request, StartParams, StartResult, codes};
use std::collections::BTreeMap;
use std::ffi::OsString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn start_params(profile: Option<String>, command: Vec<OsString>) -> anyhow::Result<StartParams> {
    let argv = command
        .into_iter()
        .map(|a| a.into_string().map_err(|a| anyhow::anyhow!("argument is not valid UTF-8: {a:?}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let cwd = std::env::current_dir()?.display().to_string();
    // Never send anything that looks like a credential, even to brokerd.
    let env: BTreeMap<String, String> =
        std::env::vars().filter(|(k, _)| !policy::config::env_name_is_secretish(k)).collect();
    Ok(StartParams { argv, cwd, profile, env })
}

pub fn run(profile: Option<String>, command: Vec<OsString>) -> i32 {
    match run_inner(profile, command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

fn print_refusal(err: &proto::RpcError) {
    eprintln!("broker: launch refused: {}", err.message);
    if let Some(layers) = err.data.as_ref().and_then(|d| d.get("layers")).and_then(|l| l.as_array()) {
        for l in layers {
            let ok = l.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            let req = l.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
            if !ok {
                eprintln!(
                    "  - {} ({}): {}",
                    l.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                    if req { "required" } else { "optional" },
                    l.get("detail").and_then(|v| v.as_str()).unwrap_or("")
                );
            }
        }
    }
    eprintln!("broker: the agent was not started. Run `broker doctor` for details.");
}

fn run_inner(profile: Option<String>, command: Vec<OsString>) -> anyhow::Result<i32> {
    let dirs = ctl::dirs()?;
    let params = start_params(profile, command)?;
    let sock = ctl::connect_or_start(&dirs)?;
    let line = proto::to_line(&Request::new(Some(1), "session.start", serde_json::to_value(&params)?));
    proto::send_with_fds(&sock, &line, &[0, 1, 2])?;
    sock.set_nonblocking(true)?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async move {
        let stream = tokio::net::UnixStream::from_std(sock)?;
        let (rd, mut wr) = stream.into_split();
        let mut lines = BufReader::new(rd).lines();
        let first = lines.next_line().await?.ok_or_else(|| anyhow::anyhow!("brokerd closed the connection"))?;
        let resp: Incoming = serde_json::from_str(&first)?;
        if let Some(err) = resp.error {
            if err.code == codes::LAUNCH_REFUSED {
                print_refusal(&err);
            } else {
                eprintln!("broker: {}", err.message);
            }
            return Ok(EXIT_BROKER);
        }
        let started: StartResult = serde_json::from_value(resp.result.unwrap_or_default())?;
        eprintln!(
            "broker: session {} · {} · profile {} · {} egress grant(s) · denies explained by `broker why <request-id>`",
            started.session_id,
            started.backend,
            started.profile,
            started.grants.len()
        );
        for w in &started.warnings {
            eprintln!("broker: warning: {w}");
        }
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigs = [
            ("INT", signal(SignalKind::interrupt())?),
            ("TERM", signal(SignalKind::terminate())?),
            ("HUP", signal(SignalKind::hangup())?),
            ("WINCH", signal(SignalKind::window_change())?),
            ("QUIT", signal(SignalKind::quit())?),
        ];
        loop {
            let [(_, s_int), (_, s_term), (_, s_hup), (_, s_winch), (_, s_quit)] = &mut sigs;
            let forward = tokio::select! {
                line = lines.next_line() => {
                    match line? {
                        Some(l) => {
                            let msg: Incoming = serde_json::from_str(&l)?;
                            if msg.method.as_deref() == Some("session.exited") {
                                let ex: Exited = serde_json::from_value(msg.params.unwrap_or_default())?;
                                return Ok(match (ex.code, ex.signal) {
                                    (Some(c), _) => c,
                                    (None, Some(s)) => 128 + s,
                                    _ => EXIT_BROKER,
                                });
                            }
                            continue;
                        }
                        None => {
                            eprintln!("broker: lost the connection to brokerd; the session was stopped");
                            return Ok(EXIT_BROKER);
                        }
                    }
                }
                _ = s_int.recv() => "INT",
                _ = s_term.recv() => "TERM",
                _ = s_hup.recv() => "HUP",
                _ = s_winch.recv() => "WINCH",
                _ = s_quit.recv() => "QUIT",
            };
            let req = Request::new(None, "session.signal", serde_json::json!({"signal": forward}));
            wr.write_all(&proto::to_line(&req)).await?;
        }
    })
}
