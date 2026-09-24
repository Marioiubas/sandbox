//! receive-pack request parsing (pkt-line framing, command list, push
//! options): never panics, and every accepted ref name is valid.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(rp) = l7::git::receive_pack::parse(data) {
        for c in &rp.commands {
            assert!(policy::repo::valid_refname(&c.refname));
            assert_eq!(c.old.len(), c.new.len());
        }
        // Whatever parses must classify without panicking; an unreadable
        // pack makes every non-create update a force push.
        let repo = policy::RepoId::parse("github.com/a/b").unwrap();
        let route = l7::git::Route::Rpc { repo, service: l7::git::Service::ReceivePack };
        if let Ok((acts, _)) = l7::git::actions(&route, Some(data)) {
            for a in acts {
                if let policy::Action::GitPush { force, update, .. } = a {
                    assert!(force || update == "create" || update == "fast_forward");
                }
            }
        }
    }
});
