//! Filesystem probes: reads, listings, writes, renames and links against
//! the sandbox's filesystem policy.

use super::*;

pub fn run(cmd: &str, rest: &[String]) -> ! {
    match cmd {
        "read" => {
            let p = rest.first().unwrap_or_else(|| usage());
            match std::fs::read(p) {
                Ok(b) => allowed(format!("read {} bytes from {p}", b.len())),
                Err(e) => denied(format!("read {p}: {}", errno_str(&e))),
            }
        }
        "list" => {
            let p = rest.first().unwrap_or_else(|| usage());
            match std::fs::read_dir(p) {
                Ok(rd) => allowed(format!("listed {} entries in {p}", rd.count())),
                Err(e) => denied(format!("list {p}: {}", errno_str(&e))),
            }
        }
        "write" | "write-new" => {
            let p = rest.first().unwrap_or_else(|| usage());
            let mut o = std::fs::OpenOptions::new();
            o.write(true);
            if cmd == "write-new" {
                o.create_new(true)
            } else {
                o.create(true).append(true)
            };
            match o.open(p).and_then(|mut f| f.write_all(b"broker-probe\n")) {
                Ok(()) => allowed(format!("wrote {p}")),
                Err(e) => denied(format!("write {p}: {}", errno_str(&e))),
            }
        }
        "mkdir" => {
            let p = rest.first().unwrap_or_else(|| usage());
            match std::fs::create_dir_all(p) {
                Ok(()) => allowed(format!("created {p}")),
                Err(e) => denied(format!("mkdir {p}: {}", errno_str(&e))),
            }
        }
        "rename" => {
            let (a, b) = (rest.first().unwrap_or_else(|| usage()), rest.get(1).unwrap_or_else(|| usage()));
            match std::fs::rename(a, b) {
                Ok(()) => allowed(format!("renamed {a} -> {b}")),
                Err(e) => denied(format!("rename: {}", errno_str(&e))),
            }
        }
        "symlink" => {
            let (t, l) = (rest.first().unwrap_or_else(|| usage()), rest.get(1).unwrap_or_else(|| usage()));
            match std::os::unix::fs::symlink(t, l) {
                Ok(()) => allowed(format!("symlink {l} -> {t}")),
                Err(e) => denied(format!("symlink: {}", errno_str(&e))),
            }
        }
        "hardlink" => {
            let (s, d) = (rest.first().unwrap_or_else(|| usage()), rest.get(1).unwrap_or_else(|| usage()));
            match std::fs::hard_link(s, d) {
                Ok(()) => allowed(format!("hardlink {d} -> {s}")),
                Err(e) => denied(format!("hardlink: {}", errno_str(&e))),
            }
        }
        "read-when-exists" => {
            let p = rest.first().unwrap_or_else(|| usage());
            let secs: u64 = rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
            let deadline = std::time::Instant::now() + Duration::from_secs(secs);
            while std::time::Instant::now() < deadline {
                if std::fs::symlink_metadata(p).is_ok() {
                    match std::fs::read(p) {
                        Ok(_) => allowed(format!("read {p} created after start")),
                        Err(e) => denied(format!("exists but unreadable: {}", errno_str(&e))),
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            inconclusive(format!("{p} never became visible"))
        }
        _ => usage(),
    }
}
