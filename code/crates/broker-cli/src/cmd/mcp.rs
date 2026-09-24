//! `broker mcp connect|approve|list` (MCP Guard). `connect` is the stub an
//! agent's MCP configuration runs inside the sandbox: it reaches the daemon
//! only through the session's own proxy and can name a pinned server, not
//! choose its command. `approve` and `list` run on the host.

use super::{EXIT_BROKER, ctl};
use base64::Engine;
use brokerd::mcp::pin;
use std::io::{Read, Write};
use std::net::TcpStream;

/// The session proxy from the sandbox environment.
fn proxy() -> Result<(String, u16, Option<String>), String> {
    let url = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .ok_or("no session proxy in the environment: run the agent under `broker run`")?;
    let rest = url.strip_prefix("http://").ok_or("the session proxy must be http://")?.trim_end_matches('/');
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(base64::engine::general_purpose::STANDARD.encode(a)), h),
        None => (None, rest),
    };
    let (h, p) = hostport.rsplit_once(':').ok_or("the session proxy has no port")?;
    Ok((h.to_string(), p.parse().map_err(|_| "bad proxy port")?, auth))
}

pub fn connect(name: &str) -> i32 {
    match run_connect(name) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("broker: mcp {name}: {e}");
            EXIT_BROKER
        }
    }
}

fn run_connect(name: &str) -> Result<i32, String> {
    if !policy::mcp::valid_name(name) {
        return Err("server names are 1-32 of a-z, 0-9 and -".into());
    }
    let (h, p, auth) = proxy()?;
    let mut s = TcpStream::connect((h.as_str(), p)).map_err(|e| format!("connecting to the session proxy: {e}"))?;
    let target = format!("{name}{}:{}", brokerd::mcp::RESERVED_SUFFIX, brokerd::mcp::PORT);
    let mut head = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(a) = auth {
        head.push_str(&format!("Proxy-Authorization: Basic {a}\r\n"));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    // The proxy's answer, byte by byte, so nothing after it is consumed.
    let mut resp = Vec::new();
    let mut b = [0u8; 1];
    while !resp.ends_with(b"\r\n\r\n") {
        if resp.len() > 16 << 10 || s.read(&mut b).map_err(|e| e.to_string())? == 0 {
            return Err("the session proxy closed the connection".into());
        }
        resp.push(b[0]);
    }
    let text = String::from_utf8_lossy(&resp).to_string();
    let status = text.lines().next().unwrap_or("").to_string();
    if status.split_whitespace().nth(1) != Some("200") {
        let mut body = Vec::new();
        let _ = s.take(64 << 10).read_to_end(&mut body);
        eprintln!("broker: mcp {name} refused: {status} {}", String::from_utf8_lossy(&body).trim());
        return Ok(1);
    }
    let mut up = s.try_clone().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut up);
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    let mut out = std::io::stdout().lock();
    let _ = std::io::copy(&mut s, &mut out);
    let _ = out.flush();
    Ok(0)
}

pub fn approve(name: &str, sha: Option<String>) -> i32 {
    let run = || -> anyhow::Result<()> {
        let dirs = ctl::dirs()?;
        let seen = pin::seen(&dirs, name).ok_or_else(|| {
            anyhow::anyhow!(
                "no manifest seen for {name:?} yet: connect to it once from a session (it is refused until approved)"
            )
        })?;
        if let Some(s) = sha
            && s != seen.sha256
        {
            anyhow::bail!("the server's manifest is now {}, not {s}; review it again", seen.sha256);
        }
        let user = brokerd::session_util::load_user_policy(&dirs)?;
        if !user.mcp.contains_key(name) {
            eprintln!("broker: warning: {name:?} is not defined in your broker.toml");
        }
        println!("mcp server {name}: approving manifest {} ({} tools)", seen.sha256, seen.tools.len());
        match pin::approved_manifest(&dirs, name) {
            Some(old) => {
                for d in pin::diff(&old.tools, &seen.tools) {
                    println!("  {d}");
                }
            }
            None => println!("  (first approval)"),
        }
        for t in &seen.tools {
            let n = t.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let d: String = t.get("description").and_then(|v| v.as_str()).unwrap_or("").chars().take(300).collect();
            println!("  tool {n}: {d}");
        }
        pin::approve(&dirs, name, &seen)?;
        println!("approved; any change to these tools revokes {name} until approved again");
        Ok(())
    };
    match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

pub fn list() -> i32 {
    let run = || -> anyhow::Result<()> {
        let dirs = ctl::dirs()?;
        let user = brokerd::session_util::load_user_policy(&dirs)?;
        if user.mcp.is_empty() {
            println!("no MCP servers defined in your broker.toml ([mcp.<name>])");
        }
        for (name, cfg) in &user.mcp {
            let state = match (pin::approved(&dirs, name), pin::seen(&dirs, name)) {
                (None, _) => "not approved".to_string(),
                (Some(a), Some(s)) if a != s.sha256 => format!("CHANGED since approval ({a} → {})", s.sha256),
                (Some(a), _) => format!("approved {a}"),
            };
            println!("{name}: {} [{state}]", cfg.command.join(" "));
        }
        Ok(())
    };
    match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}
