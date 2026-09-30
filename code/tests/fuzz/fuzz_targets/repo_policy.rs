//! Repository-supplied policy text (parsed on the host from the agent's
//! workspace): the parser and the repository-layer compile never panic.
//! Whether an accepted layer only narrows is proved by the SymCC gates
//! (I4); this target covers the parsing surface.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn base() -> &'static policy::EgressPolicy {
    static B: OnceLock<policy::EgressPolicy> = OnceLock::new();
    B.get_or_init(|| {
        let p = policy::config::parse_policy_str(
            "version = 1\n[[egress]]\nhost = \"api.example.com\"\nmethods = [\"GET\"]\n",
        )
        .unwrap();
        policy::EgressPolicy::compile([("user", p.egress.as_slice())]).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Ok(p) = policy::config::parse_policy_str(text) else { return };
    let _ = base().clone().with_repo_layer(&p.egress, None, &policy::CompileEnv::default());
});
