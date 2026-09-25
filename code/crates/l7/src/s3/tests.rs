use super::*;
use proptest::prelude::*;

const VH: &str = "acme-data.s3.us-east-1.amazonaws.com";
const PS: &str = "s3.eu-west-1.amazonaws.com";

fn r(host: &str, method: &str, target: &str) -> Result<Route, Reason> {
    let h = netguard::canon_host(host.as_bytes()).unwrap();
    let p = netguard::canon_path(target.as_bytes()).map_err(|_| Reason::NonCanonicalPath)?;
    route(&h, method, p.path(), p.query())
}

fn op(host: &str, method: &str, target: &str) -> Option<(&'static str, String, String)> {
    r(host, method, target).ok().map(|x| (x.op, x.bucket, x.key))
}

#[test]
fn operations() {
    let o = |m: &str, t: &str| op(VH, m, t);
    let k = |op: &'static str, key: &str| Some((op, "acme-data".to_string(), key.to_string()));
    assert_eq!(o("GET", "/tasks/123/in.txt"), k("s3.get", "tasks/123/in.txt"));
    assert_eq!(o("HEAD", "/tasks/123/in.txt?x-id=HeadObject"), k("s3.get", "tasks/123/in.txt"));
    assert_eq!(o("GET", "/a?response-content-type=text%2Fplain&partNumber=1"), k("s3.get", "a"));
    assert_eq!(o("GET", "/?list-type=2&prefix=tasks%2F123%2F&delimiter=%2F"), k("s3.list", "tasks/123/"));
    assert_eq!(o("GET", "/?prefix=tasks/1&marker=x"), k("s3.list", "tasks/1"));
    assert_eq!(o("GET", "/"), k("s3.list", ""));
    assert_eq!(o("PUT", "/tasks/123/out/r.txt"), k("s3.put", "tasks/123/out/r.txt"));
    assert_eq!(o("PUT", "/a?partNumber=2&uploadId=u"), k("s3.put", "a"));
    assert_eq!(o("POST", "/a?uploads"), k("s3.put", "a"));
    assert_eq!(o("POST", "/a?uploadId=u"), k("s3.put", "a"));
    assert_eq!(o("GET", "/a?uploadId=u&max-parts=5"), k("s3.put", "a"));
    assert_eq!(o("DELETE", "/a?uploadId=u"), k("s3.put", "a"));
    assert_eq!(o("DELETE", "/a"), k("s3.delete", "a"));
    // Path-style: the bucket is the first segment.
    assert_eq!(op(PS, "GET", "/acme-data/k/1"), Some(("s3.get", "acme-data".into(), "k/1".into())));
    assert_eq!(op(PS, "GET", "/acme-data?list-type=2&prefix=k/"), Some(("s3.list", "acme-data".into(), "k/".into())));
    assert_eq!(op(PS, "GET", "/acme-data/"), Some(("s3.list", "acme-data".into(), String::new())));
}

#[test]
fn everything_else_is_denied() {
    for (m, t) in [
        ("GET", "/a?acl"),
        ("PUT", "/a?acl"),
        ("GET", "/a?tagging"),
        ("GET", "/a?versionId=3"),
        ("DELETE", "/a?versionId=3"),
        ("GET", "/?policy"),
        ("PUT", "/"),
        ("DELETE", "/"),
        ("HEAD", "/"),
        ("POST", "/?delete"),
        ("GET", "/?list-type=1"),
        ("GET", "/?list-type=2&marker=x"),
        ("GET", "/?encoding-type=xml"),
        ("POST", "/a?restore"),
        ("POST", "/a?select&select-type=2"),
        ("PATCH", "/a"),
        ("GET", "/a?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=x"),
        ("GET", "/a?prefix=1&prefix=2"),
        ("GET", "/a?x=%zz"),
        ("GET", "/a?&x"),
        ("PUT", "/a?uploadId=u"),
        ("POST", "/a?uploads=1"),
    ] {
        assert_eq!(r(VH, m, t), Err(Reason::S3RouteUnknown), "{m} {t}");
    }
    assert_eq!(op(PS, "GET", "/Bad_Bucket/k"), None);
    assert_eq!(op("api.example.com", "GET", "/a"), None, "not an S3 endpoint");
}

#[test]
fn canonical_forms() {
    let x = r(VH, "GET", "/tasks/a%20b/c+d!e?prefix=a+b&list-type=2").unwrap_err();
    assert_eq!(x, Reason::S3RouteUnknown, "a key GET does not take list parameters");
    let x = r(VH, "GET", "/tasks/a%20b/c+d!e(f)").unwrap();
    assert_eq!(x.key, "tasks/a b/c+d!e(f)", "path `+` is literal");
    assert_eq!(x.canonical_uri, "/tasks/a%20b/c%2Bd%21e%28f%29");
    let x = r(VH, "GET", "/?prefix=a+b%2Fc&list-type=2&delimiter=%2F").unwrap();
    assert_eq!(x.key, "a b/c", "query `+` is a space");
    assert_eq!(x.canonical_query, "delimiter=%2F&list-type=2&prefix=a%20b%2Fc");
    let x = r(VH, "POST", "/k?uploads").unwrap();
    assert_eq!(x.canonical_query, "uploads=");
    assert_eq!(uri_encode("ሴ".as_bytes(), true), "%E1%88%B4");
}

#[test]
fn headers() {
    let mk = |pairs: &[(&str, &str)]| {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(http::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    };
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for ok in [vec![], vec![("x-amz-content-sha256", empty)], vec![("x-amz-content-sha256", "UNSIGNED-PAYLOAD")]] {
        assert_eq!(check_headers(&mk(&ok)), Ok(()), "{ok:?}");
    }
    for bad in [
        vec![("x-amz-copy-source", "/other/key")],
        vec![("x-amz-copy-source-range", "bytes=0-9")],
        vec![("x-amz-acl", "public-read")],
        vec![("x-amz-grant-read", "uri=http://acs.amazonaws.com/groups/global/AllUsers")],
        vec![("x-amz-object-lock-mode", "GOVERNANCE")],
        vec![("x-amz-tagging", "a=b")],
        vec![("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")],
        vec![("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")],
        vec![("x-amz-content-sha256", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")],
        vec![("x-amz-content-sha256", empty), ("x-amz-content-sha256", "UNSIGNED-PAYLOAD")],
    ] {
        assert_eq!(check_headers(&mk(&bad)), Err(Reason::S3RouteUnknown), "{bad:?}");
    }
}

proptest! {
    /// Never panics; a mapped request's canonical forms decode back to the
    /// same path and parameters (what is signed is what was classified).
    #[test]
    fn route_is_total_and_canonical(method in "(GET|HEAD|PUT|POST|DELETE)", path in "/[a-z0-9/%+!() ._~-]{0,30}",
                                    query in proptest::option::of("[a-zA-Z0-9=&%+/_-]{0,30}")) {
        let h = netguard::canon_host(VH.as_bytes()).unwrap();
        if let Ok(x) = route(&h, &method, &path, query.as_deref()) {
            prop_assert!(OPS_SEEN.contains(&x.op));
            prop_assert_eq!(decode(&x.canonical_uri, false), decode(&path, false));
            let mut back = query_pairs(Some(&x.canonical_query).filter(|q| !q.is_empty()).map(|q| q.as_str())).unwrap();
            let mut orig = query_pairs(query.as_deref()).unwrap();
            back.sort();
            orig.sort();
            prop_assert_eq!(back, orig);
        }
    }
}

const OPS_SEEN: &[&str] = &["s3.get", "s3.list", "s3.put", "s3.delete"];
