//! `broker policy status|approve`: repository policy in `.broker/` is used
//! only after its exact content is approved here, outside any sandbox (I5).

use super::{EXIT_BROKER, ctl};
use brokerd::repo_policy::{self, Status};

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
