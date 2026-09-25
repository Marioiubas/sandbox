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
    match &user {
        None => println!("user policy: none (built-in agent profiles only; the default profile grants no egress)"),
        Some(Err(e)) => println!("user policy: INVALID, sessions will be refused: {e:#}"),
        Some(Ok(p)) => {
            let env = policy::CompileEnv {
                github_app_issuers: p.issuers.github_app.keys().cloned().collect(),
                aws_sts_issuers: p.issuers.aws_sts.keys().cloned().collect(),
                deny_public_sinks_after_untrusted_input: p.trifecta.deny_public_sinks_after_untrusted_input,
                ..Default::default()
            };
            match policy::EgressPolicy::compile_with([("user", p.egress.as_slice())], &env) {
                Ok(c) => {
                    println!("user policy: {} egress grant(s)", c.grants().len());
                    for g in c.grants() {
                        println!("  {} {} ports {:?}: {}", g.id, g.pattern, g.ports, tls_mode(g));
                    }
                }
                Err(e) => println!("user policy: INVALID, sessions will be refused: {e}"),
            }
            describe_identity(p);
            if !p.mcp.is_empty() {
                println!(
                    "mcp servers: {} pinned ({})",
                    p.mcp.len(),
                    p.mcp.keys().cloned().collect::<Vec<_>>().join(", ")
                );
            }
            if p.trifecta.deny_public_sinks_after_untrusted_input {
                println!("session labels: public writes are denied after untrusted input (opt-in rule on)");
            }
        }
    }
    println!("protocols:");
    for (what, how) in PROTOCOLS {
        println!("  {what:<38} {how}");
    }
    match ctl::call(&dirs, "daemon.status", serde_json::Value::Null) {
        Ok(r) => {
            println!("brokerd: running {}", r.result.unwrap_or_default());
            if let Ok(l) = ctl::call(&dirs, "login.status", serde_json::Value::Null)
                && let Some(v) = l.result.filter(|v| !v.is_null())
            {
                println!(
                    "login: signed in as {} ({})",
                    v["subject"].as_str().unwrap_or("?"),
                    v["issuer"].as_str().unwrap_or("?")
                );
            }
        }
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

/// How the broker handles TLS for a grant (the compatibility matrix).
fn tls_mode(g: &policy::Grant) -> String {
    if g.passthrough {
        return "TLS passthrough for pinning clients (nothing decrypted, no credential)".into();
    }
    match &g.l7 {
        None => "TLS spliced after the SNI check (no L7 rules)".into(),
        Some(r) => format!(
            "TLS terminated, {} rules{}",
            r.protocol.as_str(),
            r.credential.as_ref().map(|c| format!(", credential {} ({})", c.id, c.kind.as_str())).unwrap_or_default()
        ),
    }
}

fn describe_identity(p: &policy::PolicyFile) {
    if !p.identity.oidc.is_empty() {
        let issuers: Vec<&str> = p.identity.oidc.iter().map(|o| o.issuer.as_str()).collect();
        println!("identity: CI tokens accepted from {}", issuers.join(", "));
    }
    match &p.identity.login {
        Some(l) => println!(
            "identity: `broker login` to {}{}",
            l.issuer,
            if l.required { " (required: sessions are refused without a login)" } else { "" }
        ),
        None if p.identity.oidc.is_empty() => println!("identity: the local user (no [identity] configured)"),
        None => {}
    }
}

/// What reaches the network from a session, by protocol.
const PROTOCOLS: &[(&str, &str)] = &[
    ("HTTPS (proxy CONNECT, SOCKS5 CONNECT)", "through the broker, per grant"),
    ("plain HTTP", "refused"),
    ("QUIC / HTTP/3, other UDP", "blocked (no UDP route out of the sandbox)"),
    ("DNS", "only the broker resolves, admitted names only"),
    ("HTTP/2 on terminated hosts", "not offered (clients use HTTP/1.1)"),
    ("WebSocket on terminated hosts", "refused"),
    ("SOCKS4, SOCKS5 BIND/UDP", "refused"),
];
