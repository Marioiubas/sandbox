//! `broker doctor`: per-layer status, directories and the active grants.

use super::{EXIT_BROKER, ctl};

pub fn doctor() -> i32 {
    match doctor_inner() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

fn doctor_inner() -> anyhow::Result<i32> {
    let backend = launcher::host_backend();
    let report = backend.probe()?;
    println!("backend: {}", report.backend);
    for l in &report.layers {
        println!(
            "  [{}] {:<16} {:<9} {}",
            if l.ok {
                "ok"
            } else if l.required {
                "!!"
            } else {
                "--"
            },
            l.name,
            if l.required { "required" } else { "optional" },
            l.detail
        );
    }
    if let Some(abi) = report.landlock_abi {
        println!("  landlock ABI: {abi}");
    }
    let dirs = ctl::dirs()?;
    println!("config:  {}", dirs.config_file().display());
    println!("state:   {}", dirs.state_dir.display());
    println!("runtime: {}", dirs.run_dir.display());
    match launcher::default_shim_path() {
        Ok(p) => println!("shim:    {}", p.display()),
        Err(e) => println!("shim:    MISSING ({e})"),
    }
    let user = if dirs.config_file().exists() { Some(policy::load_policy_file(&dirs.config_file())) } else { None };
    match user {
        None => println!("user policy: none (built-in agent profiles only; the default profile grants no egress)"),
        Some(Err(e)) => println!("user policy: INVALID, sessions will be refused: {e:#}"),
        Some(Ok(p)) => match policy::EgressPolicy::compile([("user", p.egress.as_slice())]) {
            Ok(c) => {
                println!("user policy: {} egress grant(s)", c.grants().len());
                for g in c.grants() {
                    println!("  {} {} ports {:?}", g.id, g.pattern, g.ports);
                }
            }
            Err(e) => println!("user policy: INVALID, sessions will be refused: {e}"),
        },
    }
    match ctl::call(&dirs, "daemon.status", serde_json::Value::Null) {
        Ok(r) => println!("brokerd: running {}", r.result.unwrap_or_default()),
        Err(_) => println!("brokerd: not running (started on demand by `broker run`)"),
    }
    if report.ok() {
        println!("result: all required layers available");
        Ok(0)
    } else {
        println!("result: REQUIRED LAYER MISSING; `broker run` will refuse to start agents");
        Ok(1)
    }
}
