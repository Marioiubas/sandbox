//! Git smart-HTTP adapter (Git Smart-HTTP Adapter note): turns the three
//! smart-HTTP routes into `git.fetch`, `git.push-advertise` and one
//! `git.push` per ref update, with `force` derived from the pushed pack.
//!
//! Wire formats follow `gitprotocol-http` and `gitprotocol-pack`.

pub mod pack;
pub mod pktline;
pub mod receive_pack;

use audit::Reason;
use netguard::CanonicalHost;
use policy::{Action, RepoId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// `GET /owner/repo(.git)/info/refs?service=...`
    InfoRefs { repo: RepoId, service: Service },
    /// `POST /owner/repo(.git)/git-upload-pack|git-receive-pack`
    Rpc { repo: RepoId, service: Service },
}

/// Recognise a smart-HTTP route on a canonical path. Anything else is not
/// git (and a git-only grant then denies it).
pub fn route(host: &CanonicalHost, port: u16, method: &str, path: &str, query: Option<&str>) -> Option<Route> {
    let rest = path.strip_prefix('/')?;
    let mut segs = rest.split('/');
    let (owner, name) = (segs.next()?, segs.next()?);
    let tail: Vec<&str> = segs.collect();
    let repo = RepoId::new(host, port, owner, name)?;
    match (method, tail.as_slice(), query) {
        ("GET", ["info", "refs"], Some("service=git-upload-pack")) => {
            Some(Route::InfoRefs { repo, service: Service::UploadPack })
        }
        ("GET", ["info", "refs"], Some("service=git-receive-pack")) => {
            Some(Route::InfoRefs { repo, service: Service::ReceivePack })
        }
        ("POST", ["git-upload-pack"], None) => Some(Route::Rpc { repo, service: Service::UploadPack }),
        ("POST", ["git-receive-pack"], None) => Some(Route::Rpc { repo, service: Service::ReceivePack }),
        _ => None,
    }
}

impl Route {
    /// Receive-pack bodies carry the pushed refs and pack; upload-pack
    /// bodies say which refs a fetch asks for (`refs/pull/*`).
    pub fn needs_body(&self) -> bool {
        matches!(self, Route::Rpc { .. })
    }
}

/// Whether an upload-pack request may read a pull request's head. Protocol
/// v2 names refs: `ref-prefix` (ls-refs) and `want-ref` (fetch) under
/// `refs/pull/`. A v0 request wants bare object IDs the broker cannot
/// place, so it counts as possibly reading one (fail closed). Unreadable
/// bodies count too.
pub fn upload_pack_reads_pull_refs(body: &[u8]) -> bool {
    let mut rest = body;
    let mut first = true;
    loop {
        match pktline::read(rest) {
            Ok((pktline::Pkt::Data(d), n)) => {
                let line = d.strip_suffix(b"\n").unwrap_or(d);
                if first && !line.starts_with(b"command=") {
                    return true;
                }
                first = false;
                if line.starts_with(b"ref-prefix refs/pull/") || line.starts_with(b"want-ref refs/pull/") {
                    return true;
                }
                rest = &rest[n..];
            }
            Ok((_, n)) if n > 0 && n <= rest.len() => {
                first = false;
                rest = &rest[n..];
            }
            _ => return first || !rest.is_empty(),
        }
    }
}

/// What a push carried, for the audit row and a git-native rejection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PushInfo {
    pub capabilities: Vec<String>,
    pub refs: Vec<String>,
    /// Why the pack could not be read (every update then counts as force).
    pub pack_note: Option<String>,
}

/// Classify a smart-HTTP request. `body` is the decoded request body and is
/// required for receive-pack.
pub fn actions(route: &Route, body: Option<&[u8]>) -> Result<(Vec<Action>, Option<PushInfo>), Reason> {
    match route {
        Route::InfoRefs { repo, service: Service::UploadPack } => {
            Ok((vec![Action::GitFetch { repo: repo.clone(), pull_refs: false }], None))
        }
        Route::Rpc { repo, service: Service::UploadPack } => {
            let pull_refs = body.is_none_or(upload_pack_reads_pull_refs);
            Ok((vec![Action::GitFetch { repo: repo.clone(), pull_refs }], None))
        }
        Route::InfoRefs { repo, service: Service::ReceivePack } => {
            Ok((vec![Action::GitPushAdvertise { repo: repo.clone() }], None))
        }
        Route::Rpc { repo, service: Service::ReceivePack } => {
            let body = body.ok_or(Reason::GitParseError)?;
            let rp = receive_pack::parse(body).map_err(|_| Reason::GitParseError)?;
            let needs_graph = rp.commands.iter().any(|c| !c.is_create() && !c.is_delete());
            let (graph, pack_note) = if !needs_graph {
                (None, None)
            } else if rp.oid_len() != 40 {
                (None, Some("sha256 object format: ancestry not checked".to_string()))
            } else {
                match pack::commit_graph(rp.pack, &pack::Limits::default()) {
                    Ok(g) => (Some(g), None),
                    Err(e) => (None, Some(format!("pack not readable: {e:?}"))),
                }
            };
            let mut acts = Vec::new();
            for c in &rp.commands {
                let kind = pack::classify(&c.old, &c.new, graph.as_ref());
                acts.push(Action::GitPush {
                    repo: repo.clone(),
                    refname: c.refname.clone(),
                    force: kind.is_force(),
                    update: kind.as_str(),
                });
            }
            let info = PushInfo {
                capabilities: rp.capabilities.clone(),
                refs: rp.commands.iter().map(|c| c.refname.clone()).collect(),
                pack_note,
            };
            Ok((acts, Some(info)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netguard::canon_host;

    fn h() -> CanonicalHost {
        canon_host(b"github.com").unwrap()
    }

    #[test]
    fn routes() {
        let r = route(&h(), 443, "GET", "/Acme/Web.git/info/refs", Some("service=git-receive-pack")).unwrap();
        assert_eq!(
            r,
            Route::InfoRefs { repo: RepoId::parse("github.com/acme/web").unwrap(), service: Service::ReceivePack }
        );
        assert!(route(&h(), 443, "POST", "/acme/web/git-upload-pack", None).is_some());
        assert!(route(&h(), 443, "POST", "/acme/web.git/git-receive-pack", None).unwrap().needs_body());
        for (m, p, q) in [
            ("GET", "/acme/web/info/refs", None),
            ("GET", "/acme/web/info/refs", Some("service=git-upload-pack&x=1")),
            ("POST", "/acme/web/info/refs", Some("service=git-upload-pack")),
            ("GET", "/acme/web/git-receive-pack", None),
            ("POST", "/acme/web/git-receive-pack", Some("x")),
            ("POST", "/acme/git-receive-pack", None),
            ("POST", "/a/b/c/git-receive-pack", None),
            ("GET", "/acme/web/info/lfs/objects", None),
        ] {
            assert!(route(&h(), 443, m, p, q).is_none(), "{m} {p} {q:?}");
        }
        let r = route(&canon_host(b"git.test").unwrap(), 8443, "POST", "/a/b/git-upload-pack", None).unwrap();
        assert_eq!(r, Route::Rpc { repo: RepoId::parse("git.test:8443/a/b").unwrap(), service: Service::UploadPack });
    }

    #[test]
    fn push_actions() {
        let repo = RepoId::parse("github.com/acme/web").unwrap();
        let r = Route::Rpc { repo: repo.clone(), service: Service::ReceivePack };
        let a = "1".repeat(40);
        let z = "0".repeat(40);
        let mut body = Vec::new();
        pktline::write(&mut body, format!("{z} {a} refs/heads/agent/x\0report-status").as_bytes());
        pktline::write(&mut body, format!("{a} {z} refs/heads/old").as_bytes());
        pktline::flush(&mut body);
        let (acts, info) = actions(&r, Some(&body)).unwrap();
        assert_eq!(
            acts,
            vec![
                Action::GitPush {
                    repo: repo.clone(),
                    refname: "refs/heads/agent/x".into(),
                    force: false,
                    update: "create"
                },
                Action::GitPush { repo: repo.clone(), refname: "refs/heads/old".into(), force: true, update: "delete" },
            ]
        );
        assert_eq!(info.unwrap().refs.len(), 2);
        // An update with an unreadable pack is a force push.
        let b = "2".repeat(40);
        let mut body = Vec::new();
        pktline::write(&mut body, format!("{a} {b} refs/heads/agent/x\0report-status").as_bytes());
        pktline::flush(&mut body);
        body.extend_from_slice(b"garbage");
        let (acts, info) = actions(&r, Some(&body)).unwrap();
        assert!(matches!(&acts[0], Action::GitPush { force: true, .. }));
        assert!(info.unwrap().pack_note.is_some());
        assert_eq!(actions(&r, Some(b"0000")).unwrap_err(), Reason::GitParseError);
        assert_eq!(actions(&r, None).unwrap_err(), Reason::GitParseError);
    }

    fn pkts(lines: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in lines {
            match *l {
                "0000" => pktline::flush(&mut out),
                "0001" => out.extend_from_slice(b"0001"),
                l => pktline::write(&mut out, format!("{l}\n").as_bytes()),
            }
        }
        out
    }

    #[test]
    fn pull_request_refs_are_recognised_in_upload_pack_requests() {
        // Protocol v2 (git's HTTP default): refs are named.
        let heads =
            pkts(&["command=ls-refs", "0001", "peel", "ref-prefix refs/heads/", "ref-prefix refs/tags/", "0000"]);
        assert!(!upload_pack_reads_pull_refs(&heads));
        let pr = pkts(&["command=ls-refs", "0001", "ref-prefix refs/pull/1/head", "0000"]);
        assert!(upload_pack_reads_pull_refs(&pr), "gh pr checkout lists refs/pull/N/head");
        let want_ref = pkts(&["command=fetch", "0001", "want-ref refs/pull/7/merge", "done", "0000"]);
        assert!(upload_pack_reads_pull_refs(&want_ref));
        let fetch = pkts(&["command=fetch", "0001", "want 4f2c1a9e4f2c1a9e4f2c1a9e4f2c1a9e4f2c1a9e", "done", "0000"]);
        assert!(!upload_pack_reads_pull_refs(&fetch));
        // Protocol v0 wants bare object IDs: not placeable, so possibly a PR head.
        let v0 = pkts(&["want 4f2c1a9e4f2c1a9e4f2c1a9e4f2c1a9e4f2c1a9e multi_ack side-band-64k", "0000", "done"]);
        assert!(upload_pack_reads_pull_refs(&v0));
        // Unreadable or empty: fail closed.
        assert!(upload_pack_reads_pull_refs(b""));
        assert!(upload_pack_reads_pull_refs(b"zzzz"));
        let mut trailing = heads.clone();
        trailing.extend_from_slice(b"00");
        assert!(upload_pack_reads_pull_refs(&trailing));
        let r = Route::Rpc { repo: RepoId::parse("github.com/acme/web").unwrap(), service: Service::UploadPack };
        assert!(matches!(actions(&r, Some(&pr)).unwrap().0[..], [Action::GitFetch { pull_refs: true, .. }]));
        assert!(matches!(actions(&r, Some(&heads)).unwrap().0[..], [Action::GitFetch { pull_refs: false, .. }]));
    }

    proptest::proptest! {
        /// Any body: no panic.
        #[test]
        fn upload_pack_reader_is_total(b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200)) {
            let _ = upload_pack_reads_pull_refs(&b);
        }
    }
}
