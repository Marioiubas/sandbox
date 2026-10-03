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

/// Bytes of tool arguments the `approvals` list shows (all of them with
/// `--json`); `broker approve` always shows every argument it asks about.
const SHOW_ARGS: usize = 4096;

/// What reaches the terminal: the agent's bytes (tool arguments, paths,
/// causes) with every control the terminal could act on escaped: C0/DEL
/// (serde_json escapes these inside strings only), C1 (e.g. U+009B, CSI),
/// bidi embeddings, overrides and isolates, zero-width and line separators.
fn terminal_safe(s: &str) -> String {
    s.chars()
        .map(|c| match c as u32 {
            0x0a => c.to_string(),
            0x00..=0x1f | 0x7f..=0x9f | 0x061c | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x2069 | 0xfeff => {
                format!("\\u{{{:04x}}}", c as u32)
            }
            _ => c.to_string(),
        })
        .collect()
}

/// The approve view: everything the approval would allow, every argument.
fn render(p: &Value) -> String {
    render_with(p, None)
}

fn render_with(p: &Value, show_args: Option<usize>) -> String {
    terminal_safe(&render_raw(p, show_args))
}

fn render_raw(p: &Value, show_args: Option<usize>) -> String {
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
    // An MCP tool call's key names a digest; the arguments are what runs.
    if let Some(args) = p["subject"].get("tool_arguments") {
        let text = serde_json::to_string_pretty(args).unwrap_or_default();
        out.push_str("  with these tool arguments (as the agent sent them):\n");
        let mut shown = 0;
        for line in text.lines() {
            if show_args.is_some_and(|max| shown + line.len() > max) {
                out.push_str(&format!(
                    "    … {} more bytes: `broker approvals --json` shows all\n",
                    text.len() - shown
                ));
                break;
            }
            shown += line.len() + 1;
            out.push_str(&format!("    {line}\n"));
        }
    }
    let prov: Vec<&Value> = p["provenance"].as_array().into_iter().flatten().collect();
    if !prov.is_empty() {
        // A pinned MCP server's session is judged with its agent session's
        // labels (ADR-038).
        match p["labels_session"].as_str().filter(|l| Some(*l) != p["session"].as_str()) {
            Some(l) => out.push_str(&format!("  it was judged with the labels of agent session {l}, raised by:\n")),
            None => out.push_str("  the session's labels were raised by:\n"),
        }
        for e in prov {
            let via = e["raised_in_session"].as_str().map(|s| format!(" in session {s}")).unwrap_or_default();
            out.push_str(&format!(
                "    {:<16} {}  ({}{via})\n",
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
                println!("{}", render_with(p, Some(SHOW_ARGS)));
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

#[cfg(test)]
mod review_tests {
    use super::*;

    fn pending_with_args(args: Value) -> Value {
        json!({
            "id": "apr-test", "session": "S1", "labels_session": "S1", "request_id": "req-1",
            "reason": "rule_of_two", "why": "held for a human", "expires_in_secs": 600,
            "authority_diff": ["+ mcp.call_tool gh post args=sha256:00"],
            "subject": { "tool_arguments": args },
            "provenance": [],
        })
    }

    /// ADR-037: a call too large to show is denied without an approval,
    /// "since the user would approve bytes they cannot see". The view that
    /// ends in the "Approve?" prompt must therefore show every argument (or
    /// the command must refuse); here an agent pads an early key so the one
    /// that matters sorts after the cut.
    #[test]
    fn review_approve_view_never_hides_arguments_it_asks_to_approve() {
        let args = json!({ "a_padding": "x".repeat(SHOW_ARGS + 100), "repo": "attacker/evil" });
        let shown = render(&pending_with_args(args));
        assert!(
            shown.contains("attacker/evil"),
            "the approve view hides the `repo` argument it asks the user to approve:\n{}",
            shown.lines().filter(|l| !l.contains("xxxx")).collect::<Vec<_>>().join("\n")
        );
    }

    /// Tool arguments are the agent's bytes. C1 controls (U+0080..U+009F,
    /// e.g. U+009B CSI) and bidi overrides/isolates (U+202A..U+202E,
    /// U+2066..U+2069) can rewrite or reorder what the user's terminal
    /// shows, so the approvals view must never print them raw (in keys or
    /// values).
    #[test]
    fn review_approvals_view_does_not_print_c1_or_bidi_controls_raw() {
        let mut v = serde_json::Map::new();
        let mut k = serde_json::Map::new();
        for c in (0x80u32..=0x9f).chain(0x202a..=0x202e).chain(0x2066..=0x2069) {
            let ch = char::from_u32(c).unwrap();
            v.insert(format!("v{c:04x}"), json!(format!("ok{ch}31mevil")));
            k.insert(format!("k{ch}{c:04x}"), json!("x"));
        }
        let shown = render(&pending_with_args(json!({ "values": v, "keys": k })));
        let raw: Vec<String> = shown
            .chars()
            .filter(|c| matches!(*c as u32, 0x80..=0x9f | 0x202a..=0x202e | 0x2066..=0x2069))
            .map(|c| format!("U+{:04X}", c as u32))
            .collect();
        assert!(raw.is_empty(), "printed raw to the terminal: {}", raw.join(" "));
    }
}
