//! Secret probes: environment checks and the scan for canary secrets across
//! the environment, `/proc` and files.

use super::*;

pub fn run(cmd: &str, rest: &[String]) -> ! {
    match cmd {
        "env-has" => {
            let needle = rest.first().unwrap_or_else(|| usage());
            match std::env::vars().find(|(k, v)| k.contains(needle.as_str()) || v.contains(needle.as_str())) {
                Some((k, _)) => allowed(format!("found in {k}")),
                None => denied("not in environment"),
            }
        }
        "env-scan" => {
            // Canary scan over env, argv and (Linux) every visible /proc/*/environ and cmdline.
            // The canary arrives hex-encoded so this probe's own argv does not contain it.
            let needle = hex::decode(rest.first().unwrap_or_else(|| usage())).unwrap_or_else(|_| usage());
            let hit = |b: &[u8]| b.windows(needle.len()).any(|w| w == needle.as_slice());
            for (k, v) in std::env::vars() {
                if hit(k.as_bytes()) || hit(v.as_bytes()) {
                    allowed(format!("canary in env var {k}"));
                }
            }
            if let Ok(rd) = std::fs::read_dir("/proc") {
                for e in rd.flatten() {
                    for f in ["environ", "cmdline"] {
                        if let Ok(b) = std::fs::read(e.path().join(f))
                            && hit(&b)
                        {
                            allowed(format!("canary in {}", e.path().join(f).display()));
                        }
                    }
                }
            }
            denied("canary not visible")
        }
        "secret-scan" => {
            // secret-scan <hex canary> <path[:depth]>...: env, /proc (Linux) and
            // bounded file walks. Prints CLEAN (exit 0) or FOUND (exit 1).
            let needle = hex::decode(rest.first().unwrap_or_else(|| usage())).unwrap_or_else(|_| usage());
            let hit = |b: &[u8]| b.windows(needle.len()).any(|w| w == needle.as_slice());
            let found = |w: String| -> ! {
                println!("FOUND canary in {w}");
                exit(1)
            };
            for (k, v) in std::env::vars_os() {
                if hit(k.as_encoded_bytes()) || hit(v.as_encoded_bytes()) {
                    found(format!("env var {}", k.to_string_lossy()));
                }
            }
            let mut procs = 0;
            if let Ok(rd) = std::fs::read_dir("/proc") {
                for e in rd.flatten() {
                    for f in ["environ", "cmdline"] {
                        if let Ok(b) = std::fs::read(e.path().join(f)) {
                            procs += 1;
                            if hit(&b) {
                                found(format!("{}", e.path().join(f).display()));
                            }
                        }
                    }
                }
            }
            let (mut files, mut unreadable, mut bytes) = (0u64, 0u64, 0u64);
            let mut stack: Vec<(std::path::PathBuf, u32)> = rest[1..]
                .iter()
                .map(|a| match a.rsplit_once(':') {
                    Some((p, d)) if d.parse::<u32>().is_ok() => (p.into(), d.parse().unwrap_or(6)),
                    _ => (a.into(), 6),
                })
                .collect();
            while let Some((p, depth)) = stack.pop() {
                if files > 50_000 || bytes > (512 << 20) {
                    break;
                }
                let Ok(m) = std::fs::symlink_metadata(&p) else {
                    unreadable += 1;
                    continue;
                };
                if m.is_dir() {
                    match std::fs::read_dir(&p) {
                        Ok(rd) if depth > 0 => stack.extend(rd.flatten().map(|e| (e.path(), depth - 1))),
                        Ok(_) => {}
                        Err(_) => unreadable += 1,
                    }
                } else if m.is_file() && m.len() <= 8 << 20 {
                    match std::fs::read(&p) {
                        Ok(b) => {
                            files += 1;
                            bytes += b.len() as u64;
                            if hit(&b) {
                                found(format!("file {}", p.display()));
                            }
                        }
                        Err(_) => unreadable += 1,
                    }
                }
            }
            println!("CLEAN env, {procs} /proc entries, {files} files ({bytes} bytes); {unreadable} unreadable");
            exit(0)
        }
        _ => usage(),
    }
}
