//! `broker login` / `broker logout`: OIDC device login (RFC 8628) to the
//! identity provider in `[identity.login]`. The daemon runs the flow and
//! keeps the result; this command only shows the code and waits. Nothing
//! here sees a token.

use super::{EXIT_BROKER, ctl};
use serde_json::{Value, json};

fn until(v: &Value) -> String {
    let secs = v["until"].as_u64().unwrap_or(0) as i64;
    time::OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_default()
}

fn describe(v: &Value) -> String {
    let groups: Vec<&str> = v["groups"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    format!(
        "{} (issuer {}){} until {}",
        v["subject"].as_str().unwrap_or("?"),
        v["issuer"].as_str().unwrap_or("?"),
        if groups.is_empty() { String::new() } else { format!(", groups {}", groups.join(", ")) },
        until(v)
    )
}

pub fn login(status: bool) -> i32 {
    let run = || -> anyhow::Result<i32> {
        let dirs = ctl::dirs()?;
        drop(ctl::connect_or_start(&dirs)?);
        if status {
            let r = ctl::call(&dirs, "login.status", Value::Null)?;
            match r.result.filter(|v| !v.is_null()) {
                Some(v) => println!("signed in as {}", describe(&v)),
                None => println!("not signed in"),
            }
            return Ok(0);
        }
        let r = ctl::call(&dirs, "login.start", Value::Null)?;
        let Some(start) = r.result else {
            eprintln!("broker: login: {}", r.error.map(|e| e.message).unwrap_or_default());
            return Ok(1);
        };
        println!(
            "To sign in to {}, open {} and enter the code {}",
            start["issuer"].as_str().unwrap_or("?"),
            start["verification_uri"].as_str().unwrap_or("?"),
            start["user_code"].as_str().unwrap_or("?"),
        );
        if let Some(u) = start["verification_uri_complete"].as_str() {
            println!("(or open {u}, and check the page shows the same code)");
        }
        println!("Waiting (the code expires in {} s)…", start["expires_in"].as_u64().unwrap_or(0));
        let r = ctl::call(&dirs, "login.wait", json!({ "login_id": start["login_id"] }))?;
        match r.result {
            Some(v) => {
                println!("signed in as {}", describe(&v));
                Ok(0)
            }
            None => {
                eprintln!("broker: login: {}", r.error.map(|e| e.message).unwrap_or_default());
                Ok(1)
            }
        }
    };
    run().unwrap_or_else(|e| {
        eprintln!("broker: {e:#}");
        EXIT_BROKER
    })
}

pub fn logout() -> i32 {
    let Ok(dirs) = ctl::dirs() else { return EXIT_BROKER };
    match ctl::call(&dirs, "login.logout", Value::Null) {
        Ok(r) if r.result.as_ref().and_then(|v| v["signed_out"].as_bool()) == Some(true) => {
            println!("signed out");
            0
        }
        _ => {
            println!("not signed in");
            0
        }
    }
}
