//! `broker policy status|approve|check`: repository policy in `.broker/`
//! is used only after its exact content is approved here, outside any
//! sandbox (I5); `check` runs the formal gates (SymCC CI Gates).

use super::{EXIT_BROKER, ctl};
use brokerd::repo_policy::{self, Status};
use policy::gates::{self, Bundle, Inputs};
use policy::{CompileEnv, EgressPolicy, PolicyFile, ProfileFile};
use std::path::PathBuf;

/// A hard gate failed (no override exists).
pub const EXIT_GATE_FAILED: i32 = 1;
/// Only the narrowing gate failed: the change widens and needs approval.
pub const EXIT_WIDENS: i32 = 2;

fn repo_root() -> anyhow::Result<std::path::PathBuf> {
    Ok(brokerd::session_util::repo_root(&std::env::current_dir()?.canonicalize()?))
}

pub fn status() -> i32 {
    match (|| -> anyhow::Result<()> {
        let dirs = ctl::dirs()?;
        let root = repo_root()?;
        let st = repo_policy::status(&dirs, &root)?;
        println!("repository {}: {}", root.display(), st.describe());
        if let Status::Approved { toml: Some(p), .. } = &st {
            for e in &p.egress {
                println!(
                    "  narrows to: {}{}",
                    e.host,
                    e.methods.as_ref().map(|m| format!(" {m:?}")).unwrap_or_default()
                );
            }
        }
        Ok(())
    })() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

pub fn approve() -> i32 {
    match (|| -> anyhow::Result<()> {
        let dirs = ctl::dirs()?;
        dirs.ensure()?;
        let root = repo_root()?;
        // Compile it now, so an approval never covers a policy that cannot load.
        let files = repo_policy::read(&root)?;
        if let Some(t) = files.toml.as_deref() {
            let p = repo_policy::parse_toml(t)?;
            policy::EgressPolicy::compile([])
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .with_repo_layer(&p.egress, files.cedar.as_deref(), &policy::CompileEnv::default())
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        } else if let Some(c) = files.cedar.as_deref() {
            policy::EgressPolicy::compile([])
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .with_repo_layer(&[], Some(c), &policy::CompileEnv::default())
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        match repo_policy::approve(&dirs, &root)? {
            Some(h) => {
                println!("approved repository policy of {} ({h}); it can only narrow your policy", root.display())
            }
            None => println!("no repository policy in {}", root.display()),
        }
        Ok(())
    })() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

pub struct CheckArgs {
    pub profile: Option<String>,
    pub policy: Option<PathBuf>,
    pub baseline: Option<PathBuf>,
    pub repo: bool,
    pub json: bool,
}

fn load(path: &std::path::Path) -> anyhow::Result<PolicyFile> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    policy::config::parse_policy_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
}

fn compile(
    profile: Option<&(String, ProfileFile)>,
    user: &PolicyFile,
    env: &CompileEnv,
) -> anyhow::Result<EgressPolicy> {
    let mut layers: Vec<(&str, &[policy::config::EgressEntry])> = Vec::new();
    if let Some((scope, p)) = profile {
        layers.push((scope.as_str(), p.egress.as_slice()));
    }
    layers.push(("user", user.egress.as_slice()));
    EgressPolicy::compile_with(layers, env).map_err(|e| anyhow::anyhow!("{e}"))
}

/// `broker policy check`: prove the gates for the user policy (or
/// `--policy`), optionally against `--baseline` and with this repository's
/// `.broker/` layer. Exit 0: every gate proved; 2: the change widens (human
/// approval, counterexamples shown); 1: a hard gate failed.
pub fn check(a: CheckArgs) -> i32 {
    match run_check(a) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

fn run_check(a: CheckArgs) -> anyhow::Result<i32> {
    let dirs = ctl::dirs()?;
    let user = match &a.policy {
        Some(p) => load(p)?,
        None => brokerd::session_util::load_user_policy(&dirs)?,
    };
    let profile = match &a.profile {
        Some(n) => Some((format!("profile:{n}"), brokerd::profiles::by_name(n)?)),
        None => None,
    };
    let root = repo_root()?;
    let env = CompileEnv {
        repo_remote: brokerd::session_util::origin_remote(&root),
        github_app_issuers: user.issuers.github_app.keys().cloned().collect(),
        ..Default::default()
    };
    let mut new = compile(profile.as_ref(), &user, &env)?;
    if a.repo {
        let files = repo_policy::read(&root)?;
        let toml = files.toml.as_deref().map(repo_policy::parse_toml).transpose()?;
        let entries = toml.map(|p| p.egress).unwrap_or_default();
        new = new.with_repo_layer(&entries, files.cedar.as_deref(), &env).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    let old = match &a.baseline {
        Some(p) => Some(Bundle::from_egress(&compile(profile.as_ref(), &load(p)?, &env)?)),
        None => None,
    };
    let bundle = Bundle::from_egress(&new);
    let r = gates::check(&Inputs { new: &bundle, old: old.as_ref(), repo: new.engine().repo() })?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        println!("{}", r.render());
        println!("({}; {} environments, {} queries, {} ms)", r.solver, r.envs, r.queries, r.millis);
    }
    Ok(if !r.hard_failures().is_empty() {
        EXIT_GATE_FAILED
    } else if !r.widenings().is_empty() {
        EXIT_WIDENS
    } else {
        0
    })
}
