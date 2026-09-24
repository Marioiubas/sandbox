//! `broker policy shadow`: activate a candidate policy in shadow mode (it is
//! evaluated beside your policy on every request and logged, never applied),
//! turn it off, or report what it would have changed.

use super::{EXIT_BROKER, ctl};
use audit::{DecisionResult, EventKind, SqliteRecorder};
use std::collections::{BTreeMap, BTreeSet};

pub enum Action {
    Activate(std::path::PathBuf),
    Off,
    Report,
}

pub fn shadow(a: Action) -> i32 {
    match run(a) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

fn run(a: Action) -> anyhow::Result<()> {
    let dirs = ctl::dirs()?;
    dirs.ensure()?;
    match a {
        Action::Activate(p) => {
            let text = std::fs::read_to_string(&p).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
            let sha = brokerd::shadow::activate(&dirs, &text)?;
            println!(
                "shadow candidate {sha} is active: new `broker run` sessions evaluate and log it; it decides nothing"
            );
            println!("see what it would change with `broker policy shadow --report`");
        }
        Action::Off => {
            if brokerd::shadow::deactivate(&dirs)? {
                println!("shadow mode off");
            } else {
                println!("no shadow candidate was active");
            }
        }
        Action::Report => report(&dirs)?,
    }
    Ok(())
}

fn report(dirs: &brokerd::dirs::BrokerDirs) -> anyhow::Result<()> {
    let Some((sha, _)) = brokerd::shadow::load(dirs)? else {
        anyhow::bail!("no shadow candidate is active (`broker policy shadow <file>`)");
    };
    let db = dirs.audit_db();
    let n = SqliteRecorder::verify_path(&db).map_err(|e| anyhow::anyhow!("audit chain does not verify: {e}"))?;
    let rec = SqliteRecorder::open_read_only(&db)?;
    let rows = rec.range(0, i64::try_from(n).unwrap_or(i64::MAX))?;
    // Sessions that evaluated this exact candidate.
    let sessions: BTreeSet<String> = rows
        .iter()
        .filter(|s| s.event.kind == EventKind::SessionStart)
        .filter(|s| {
            s.event.detail.get("shadow").and_then(|v| v.get("candidate")).and_then(|c| c.as_str()) == Some(&sha)
        })
        .filter_map(|s| s.event.session.as_ref().map(|x| x.to_string()))
        .collect();
    let (mut total, mut same) = (0usize, 0usize);
    let mut tighter: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut wider: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for s in &rows {
        let e = &s.event;
        if e.kind != EventKind::RequestDecision || !e.session.as_ref().is_some_and(|x| sessions.contains(x.as_str())) {
            continue;
        }
        let (Some(sh), Some(d)) = (e.detail.get("shadow"), &e.decision) else { continue };
        total += 1;
        if sh.get("differs").and_then(|v| v.as_bool()) != Some(true) {
            same += 1;
            continue;
        }
        let dest = e.dest.as_ref().and_then(|d| d.host.clone()).unwrap_or_default();
        let verb = e.detail.get("verb").and_then(|v| v.as_str()).unwrap_or("connect");
        let rid = e.request_id.as_ref().map(|r| r.to_string()).unwrap_or_default();
        let line = format!("{verb} {dest} ({rid})");
        if d.result == DecisionResult::Allow {
            let r = sh.get("reason").and_then(|v| v.as_str()).unwrap_or("denied");
            tighter.entry(r.to_string()).or_default().push(line);
        } else {
            wider.entry(e.reason.map(|r| r.as_str().to_string()).unwrap_or_default()).or_default().push(line);
        }
    }
    println!("shadow candidate {sha}: {} session(s), {total} decision(s), {same} unchanged", sessions.len());
    let count = |m: &BTreeMap<String, Vec<String>>| m.values().map(Vec::len).sum::<usize>();
    println!("the candidate would deny {} request(s) your policy allowed:", count(&tighter));
    for (r, v) in &tighter {
        println!("  {r}: {} (e.g. {})", v.len(), v[0]);
    }
    println!("the candidate would allow {} request(s) your policy denied:", count(&wider));
    for (r, v) in &wider {
        println!("  was {r}: {} (e.g. {})", v.len(), v[0]);
    }
    if total == 0 {
        println!("no evidence yet: run sessions with `broker run` while the candidate is active");
    } else if tighter.is_empty() {
        println!("no candidate-only denies: ready for review; to enforce it, make it your broker.toml");
    } else {
        println!("the candidate would break the requests above; revise it before enforcing");
    }
    Ok(())
}
