//! `broker suggest`: mine record-mode sessions (`broker learn`) from the
//! verified audit chain into a proposed broker.toml diff, with evidence,
//! the safeguards applied, and a replay under the current and the candidate
//! policy. Nothing is applied: a human merges it (I3).

use super::{EXIT_BROKER, ctl};
use audit::SqliteRecorder;
use learn::generalise::Options;
use std::collections::BTreeMap;

pub fn suggest(min_runs: usize, out: Option<std::path::PathBuf>) -> i32 {
    match run(min_runs, out) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

fn run(min_runs: usize, out: Option<std::path::PathBuf>) -> anyhow::Result<()> {
    let dirs = ctl::dirs()?;
    let db = dirs.audit_db();
    // The miner reads only committed, verified rows.
    let n = SqliteRecorder::verify_path(&db).map_err(|e| anyhow::anyhow!("audit chain does not verify: {e}"))?;
    let rec = SqliteRecorder::open_read_only(&db)?;
    let events: Vec<audit::AuditEvent> =
        rec.tail(u32::try_from(n).unwrap_or(u32::MAX))?.into_iter().map(|s| s.event).collect();
    let s = learn::suggest(&events, Options { min_runs, ..Options::default() });
    if !s.corpus.sessions.values().any(|x| x.record) {
        anyhow::bail!("no record-mode sessions yet: run `broker learn -- <agent> ...` first");
    }
    print!("{}", s.render_report());
    // Replay per profile: the current policy (profile + user) vs + learned.
    let user = brokerd::session_util::load_user_policy(&dirs)?;
    let learned = s.active_entries();
    let mut by_profile: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for x in s.corpus.sessions.values().filter(|x| x.record) {
        by_profile.entry(x.profile.clone()).or_default().push(x.id.clone());
    }
    let issuers: std::collections::BTreeSet<String> = user.issuers.github_app.keys().cloned().collect();
    for (profile, sessions) in by_profile {
        let prof = brokerd::profiles::by_name(&profile)?;
        let mut sub = s.corpus.clone();
        sub.observations.retain(|o| sessions.contains(&o.session));
        let env = policy::CompileEnv { github_app_issuers: issuers.clone(), ..Default::default() };
        let scope = format!("profile:{profile}");
        let before =
            learn::replay(&sub, [(scope.as_str(), prof.egress.as_slice()), ("user", user.egress.as_slice())], &env)
                .map_err(|e| anyhow::anyhow!(e))?;
        let after = learn::replay(
            &sub,
            [
                (scope.as_str(), prof.egress.as_slice()),
                ("user", user.egress.as_slice()),
                ("learned", learned.as_slice()),
            ],
            &env,
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        println!(
            "replay ({profile}): current policy would deny {} of {} recorded requests; with the proposals {}; \
             ceiling/blocked still denied {} of {}",
            before.denied, before.total, after.denied, after.blocked_still_denied, after.blocked_total
        );
        let layers = |with_learned: bool| {
            let mut l = vec![(scope.as_str(), prof.egress.as_slice()), ("user", user.egress.as_slice())];
            if with_learned {
                l.push(("learned", learned.as_slice()));
            }
            policy::EgressPolicy::compile_with(l, &env).map_err(|e| anyhow::anyhow!("{e}"))
        };
        match policy::gates::solver_version() {
            Ok(_) => {
                let old = policy::gates::Bundle::from_egress(&layers(false)?);
                let new = policy::gates::Bundle::from_egress(&layers(true)?);
                let r = policy::gates::check(&policy::gates::Inputs { new: &new, old: Some(&old), repo: None })?;
                println!("gates ({profile}; {}):\n{}", r.solver, r.render());
                if !r.hard_failures().is_empty() {
                    println!("the proposal fails a hard gate: do not merge it");
                }
            }
            Err(why) => println!(
                "gates: not run ({why}); replay says the ceiling still denies {} of {} blocked requests",
                after.blocked_still_denied, after.blocked_total
            ),
        }
    }
    let toml = s.render_toml();
    match out {
        Some(p) => {
            std::fs::write(&p, &toml)?;
            println!("wrote {} (review, then merge into your broker.toml)", p.display());
        }
        None => print!("\n{toml}"),
    }
    Ok(())
}
