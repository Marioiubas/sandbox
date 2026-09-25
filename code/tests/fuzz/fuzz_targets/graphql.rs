//! GitHub GraphQL (ADR-035): the document parser and the adapter never
//! panic; a query never maps to a write verb; every write names a node the
//! broker must resolve; public reads carry no bodies.
#![no_main]
use libfuzzer_sys::fuzz_target;

fn check(m: &[l7::github::graphql::Mapped], query_only: bool) {
    for x in m {
        assert!(policy::github::is_verb(x.verb));
        let write = !policy::github::is_read_verb(x.verb);
        assert!(!(query_only && write), "a query mapped to {}", x.verb);
        assert_eq!(write, x.node.is_some());
        assert!(!write || !l7::github::graphql::node_types(x.verb).is_empty());
        assert!(!x.public || (x.verb == "github.read" && !x.bodies));
        assert_eq!(x.verb == "repo.read", x.repo.is_some());
    }
}

fuzz_target!(|data: &[u8]| {
    let host = netguard::canon_host(b"github.com").unwrap();
    // Raw request bodies.
    if let Ok(m) = l7::github::graphql::map(&host, data) {
        check(&m, false);
    }
    // The input as a document.
    let Ok(src) = std::str::from_utf8(data) else { return };
    let Ok(doc) = l7::graphql::parse(src) else { return };
    let body = serde_json::to_vec(&serde_json::json!({ "query": src })).unwrap();
    if let Ok(m) = l7::github::graphql::map(&host, &body) {
        let query_only = doc.operations.iter().all(|o| o.ty == l7::graphql::OpType::Query);
        check(&m, query_only);
    }
});
