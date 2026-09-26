//! `broker approvals` / `broker approve`: step-up approvals (ADR-037). A
//! request denied only for want of a human approval leaves a pending
//! approval in the daemon; these commands show its authority diff (exactly
//! what would be allowed) and the provenance behind it (which requests
//! raised the session's labels), from the broker's own records, never from
//! the agent's account, and grant it. They run on the host: the control
//! socket is not reachable from any sandbox.

use super::{EXIT_BROKER, ctl};
use serde_json::{Value, json};
use std::io::{BufRead, IsTerminal, Write};

fn render(p: &Value) -> String {
    let mut out = format!(
        "approval {}  (session {}, {} s left)\n  held back: request {} was denied ({}): {}\n  it would allow, exactly:\n",
        p["id"].as_str().unwrap_or("?"),
        p["session"].as_str().unwrap_or("?"),
        p["expires_in_secs"].as_i64().unwrap_or(0),
        p["request_id"].as_str().unwrap_or("?"),
        p["reason"].as_str().unwrap_or("?"),
        p["why"].as_str().unwrap_or(""),
    );
    for d in p["authority_diff"].as_array().into_iter().flatten() {
        out.push_str(&format!("    {}\n", d.as_str().unwrap_or("?")));
    }
    let prov: Vec<&Value> = p["provenance"].as_array().into_iter().flatten().collect();
    if !prov.is_empty() {
        out.push_str("  the session's labels were raised by:\n");
        for e in prov {
            out.push_str(&format!(
                "    {:<16} {}  ({})\n",
                e["label"].as_str().unwrap_or("?"),
                e["cause"].as_str().unwrap_or("?"),
                e["request_id"].as_str().unwrap_or("?"),
            ));
        }
    }
    out
}

fn pending(dirs: &brokerd::dirs::BrokerDirs) -> anyhow::Result<Vec<Value>> {
    let r = ctl::call(dirs, "approval.list", Value::Null)?;
    if let Some(e) = r.error {
        anyhow::bail!("{}", e.message);
    }
    Ok(r.result.and_then(|v| v.as_array().cloned()).unwrap_or_default())
}

pub fn list(as_json: bool) -> i32 {
    let run = || -> anyhow::Result<i32> {
        let dirs = ctl::dirs()?;
        drop(ctl::connect_or_start(&dirs)?);
        let items = pending(&dirs)?;
        if as_json {
            println!("{}", serde_json::to_string_pretty(&items)?);
        } else if items.is_empty() {
            println!("no pending approvals");
        } else {
            for p in &items {
                println!("{}", render(p));
            }
            println!("approve one with `broker approve <id>` (add --for-session to keep it for the session)");
        }
        Ok(0)
    };
    run().unwrap_or_else(|e| {
        eprintln!("broker: {e:#}");
        EXIT_BROKER
    })
}

pub fn approve(id: &str, for_session: bool, yes: bool) -> i32 {
    let run = || -> anyhow::Result<i32> {
        let dirs = ctl::dirs()?;
        drop(ctl::connect_or_start(&dirs)?);
        let Some(p) = pending(&dirs)?.into_iter().find(|p| p["id"].as_str() == Some(id)) else {
            eprintln!("broker: no pending approval {id} (expired, granted, or its session ended)");
            return Ok(1);
        };
        print!("{}", render(&p));
        let scope = if for_session { "session" } else { "once" };
        println!(
            "  scope: {}",
            if for_session {
                "every matching request for the rest of this session"
            } else {
                "the next matching request only"
            }
        );
        if !yes {
            if !std::io::stdin().is_terminal() {
                eprintln!("broker: not approved: stdin is not a terminal (review the diff above, then pass --yes)");
                return Ok(1);
            }
            print!("Approve? [y/N] ");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            if !matches!(line.trim(), "y" | "Y" | "yes") {
                println!("not approved");
                return Ok(1);
            }
        }
        let r = ctl::call(&dirs, "approval.grant", json!({ "approval": id, "scope": scope }))?;
        match (r.result, r.error) {
            (Some(_), _) => {
                println!("approved ({scope}); the agent can retry the request");
                Ok(0)
            }
            (None, e) => {
                eprintln!("broker: {}", e.map(|e| e.message).unwrap_or_default());
                Ok(1)
            }
        }
    };
    run().unwrap_or_else(|e| {
        eprintln!("broker: {e:#}");
        EXIT_BROKER
    })
}
