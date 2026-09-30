//! Filesystem probes: reads, listings, writes, renames, unlinks and links
//! against the sandbox's filesystem policy.
//!
//! A failure is DENIED only when the kernel refused the operation: EACCES or
//! EPERM (Seatbelt, Landlock) or EROFS (read-only binds and masks). Any
//! other error is INCONCLUSIVE, above all ENOENT and ENOTDIR: a probe of a
//! path that does not exist proves nothing about the sandbox. The errno
//! name is printed (`errno=ENOENT`), so a test can accept one platform's own
//! mechanism by name where it must (for example EXDEV, Landlock's and the
//! mount table's answer to a rename or link across a read-only bind).

use super::*;

fn fail(what: String, e: &std::io::Error) -> ! {
    let msg = format!("{what}: {} errno={}", errno_str(e), errno_name(e));
    match e.raw_os_error() {
        Some(libc::EACCES | libc::EPERM | libc::EROFS) => denied(msg),
        _ => inconclusive(msg),
    }
}

fn arg(rest: &[String], i: usize) -> &str {
    rest.get(i).map(String::as_str).unwrap_or_else(|| usage())
}

pub fn run(cmd: &str, rest: &[String]) -> ! {
    let p = arg(rest, 0);
    match cmd {
        "read" => match std::fs::read(p) {
            Ok(b) => allowed(format!("read {} bytes from {p}", b.len())),
            Err(e) => fail(format!("read {p}"), &e),
        },
        "list" => match std::fs::read_dir(p) {
            Ok(rd) => allowed(format!("listed {} entries in {p}", rd.count())),
            Err(e) => fail(format!("list {p}"), &e),
        },
        "write" | "write-new" => {
            let mut o = std::fs::OpenOptions::new();
            o.write(true);
            if cmd == "write-new" {
                o.create_new(true)
            } else {
                o.create(true).append(true)
            };
            match o.open(p).and_then(|mut f| f.write_all(b"broker-probe\n")) {
                Ok(()) => allowed(format!("wrote {p}")),
                Err(e) => fail(format!("write {p}"), &e),
            }
        }
        "mkdir" => match std::fs::create_dir_all(p) {
            Ok(()) => allowed(format!("created {p}")),
            Err(e) => fail(format!("mkdir {p}"), &e),
        },
        "rename" => {
            let to = arg(rest, 1);
            match std::fs::rename(p, to) {
                Ok(()) => allowed(format!("renamed {p} -> {to}")),
                Err(e) => fail(format!("rename {p} -> {to}"), &e),
            }
        }
        // Files only: unlink(2) of a directory is EPERM on macOS by design.
        "unlink" => match std::fs::remove_file(p) {
            Ok(()) => allowed(format!("unlinked {p}")),
            Err(e) => fail(format!("unlink {p}"), &e),
        },
        "symlink" => {
            let link = arg(rest, 1);
            match std::os::unix::fs::symlink(p, link) {
                Ok(()) => allowed(format!("symlink {link} -> {p}")),
                Err(e) => fail(format!("symlink {link} -> {p}"), &e),
            }
        }
        "hardlink" => {
            let link = arg(rest, 1);
            match std::fs::hard_link(p, link) {
                Ok(()) => allowed(format!("hardlink {link} -> {p}")),
                Err(e) => fail(format!("hardlink {link} -> {p}"), &e),
            }
        }
        // A path created after the session started: ENOENT means "not yet";
        // the first other answer decides.
        "read-when-exists" => {
            let secs: u64 = rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
            let deadline = std::time::Instant::now() + Duration::from_secs(secs);
            while std::time::Instant::now() < deadline {
                match std::fs::read(p) {
                    Ok(_) => allowed(format!("read {p} created after start")),
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
                    Err(e) => fail(format!("read {p} created after start"), &e),
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            inconclusive(format!("{p} never became visible errno=ENOENT"))
        }
        _ => usage(),
    }
}
