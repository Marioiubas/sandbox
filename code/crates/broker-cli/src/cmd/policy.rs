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
        aws_sts_issuers: user.issuers.aws_sts.keys().cloned().collect(),
        deny_public_sinks_after_untrusted_input: user.trifecta.deny_public_sinks_after_untrusted_input,
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

pub struct ExportArgs {
    pub target: String,
    pub profile: String,
    pub policy: Option<PathBuf>,
    pub out: Option<PathBuf>,
}

/// `broker policy export`: the profile's policy as a vendor-native file
/// (defence in depth; the broker stays the boundary). The file goes to
/// stdout or `--out`, the export report to stderr. Nothing is installed.
pub fn export(a: ExportArgs) -> i32 {
    match run_export(a) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

fn run_export(a: ExportArgs) -> anyhow::Result<()> {
    use launcher::fs_compile::{DEFAULT_DENY_READ, HOME_DENY_WRITE, ROOT_DENY_WRITE};
    use policy::exporters::{Normalized, claude, codex};
    let dirs = ctl::dirs()?;
    let user = match &a.policy {
        Some(p) => load(p)?,
        None => brokerd::session_util::load_user_policy(&dirs)?,
    };
    let profile = (format!("profile:{}", a.profile), brokerd::profiles::by_name(&a.profile)?);
    let env = CompileEnv {
        github_app_issuers: user.issuers.github_app.keys().cloned().collect(),
        aws_sts_issuers: user.issuers.aws_sts.keys().cloned().collect(),
        deny_public_sinks_after_untrusted_input: user.trifecta.deny_public_sinks_after_untrusted_input,
        ..Default::default()
    };
    let egress = compile(Some(&profile), &user, &env)?;
    let mut report = Vec::new();
    let mut paths = |list: &[String]| -> Vec<String> {
        list.iter()
            .filter(|p| {
                let ok = p.starts_with("~/") || p.starts_with('/');
                if !ok {
                    report.push(format!("{p}: not exported (only `~/` and absolute paths resolve the same way)"));
                }
                ok
            })
            .cloned()
            .collect()
    };
    let mut deny_read: Vec<String> = DEFAULT_DENY_READ.iter().map(|p| format!("~/{p}")).collect();
    deny_read.extend(paths(&profile.1.filesystem.deny_read));
    deny_read.extend(paths(&user.filesystem.deny_read));
    let deny_write: Vec<String> = HOME_DENY_WRITE.iter().map(|p| format!("~/{p}")).collect();
    let n = Normalized::from_policy(&egress, &deny_read, &deny_write);
    let e = match a.target.as_str() {
        "claude-code" => claude::export(&n),
        "codex" => codex::export(&n, &a.profile),
        t => anyhow::bail!("unknown target {t:?} (claude-code, codex)"),
    };
    report.extend(e.report);
    report.push(format!(
        "project-relative deny-write names ({}) are enforced by the broker only",
        ROOT_DENY_WRITE.join(", ")
    ));
    match &a.out {
        Some(p) => std::fs::write(p, &e.file)?,
        None => print!("{}", e.file),
    }
    for r in report {
        eprintln!("export: {r}");
    }
    Ok(())
}
