//! `broker daemon status|stop`.

use super::ctl;

pub fn status() -> i32 {
    let Ok(dirs) = ctl::dirs() else { return 1 };
    match ctl::call(&dirs, "daemon.status", serde_json::Value::Null) {
        Ok(r) => {
            println!("{}", r.result.unwrap_or_default());
            0
        }
        Err(_) => {
            println!("brokerd is not running");
            1
        }
    }
}

pub fn stop() -> i32 {
    let Ok(dirs) = ctl::dirs() else { return 1 };
    match ctl::call(&dirs, "daemon.shutdown", serde_json::Value::Null) {
        Ok(r) if r.error.is_none() => 0,
        Ok(r) => {
            eprintln!("broker: {}", r.error.map(|e| e.message).unwrap_or_default());
            1
        }
        Err(_) => 0,
    }
}
