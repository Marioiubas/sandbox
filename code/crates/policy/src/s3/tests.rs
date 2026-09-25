use super::*;
use proptest::prelude::*;
use serde_json::Value;

fn host(s: &str) -> CanonicalHost {
    netguard::canon_host(s.as_bytes()).unwrap()
}

#[test]
fn endpoint_grammar() {
    let ep = |h: &str| endpoint(&host(h));
    let vh = |b: &str, r: &str| Some(Endpoint { bucket: Some(b.into()), region: r.into() });
    let ps = |r: &str| Some(Endpoint { bucket: None, region: r.into() });
    assert_eq!(ep("acme-data.s3.us-east-1.amazonaws.com"), vh("acme-data", "us-east-1"));
    assert_eq!(ep("acme-data.s3.amazonaws.com"), vh("acme-data", "us-east-1"));
    assert_eq!(ep("my.bucket.s3.eu-west-2.amazonaws.com"), vh("my.bucket", "eu-west-2"));
    assert_eq!(ep("acme-data.s3-eu-west-1.amazonaws.com"), vh("acme-data", "eu-west-1"));
    assert_eq!(ep("acme-data.s3.dualstack.us-west-2.amazonaws.com"), vh("acme-data", "us-west-2"));
    assert_eq!(ep("s3.us-east-2.amazonaws.com"), ps("us-east-2"));
    assert_eq!(ep("s3.amazonaws.com"), ps("us-east-1"));
    assert_eq!(ep("s3-external-1.amazonaws.com"), ps("us-east-1"));
    for bad in [
        "s3.example.com",
        "acme.s3.evil.com",
        "sts.us-east-1.amazonaws.com",
        "acme.s3.us-east-1.amazonaws.com.evil.com",
        "acme.s3.us-east-1.extra.amazonaws.com",
        "acme.s3.dualstack.amazonaws.com",
        "ab.s3.us-east-1.amazonaws.com",
        "a..b.s3.us-east-1.amazonaws.com",
        "acme.s3-control.amazonaws.com",
        "acme.s3.useast1.amazonaws.com",
    ] {
        assert_eq!(netguard::canon_host(bad.as_bytes()).ok().and_then(|h| endpoint(&h)), None, "{bad}");
    }
}

#[test]
fn prefixes() {
    for ok in ["", "tasks/123/", "a-b_c.d=e+f!g'(h)", "x"] {
        assert!(prefix_ok(ok), "{ok}");
    }
    for bad in ["/tasks", "a*", "a?", "${aws:username}/", "a\"b", "a\\b", "a b", "é", &"x".repeat(513)] {
        assert!(!prefix_ok(bad), "{bad}");
    }
}

fn rules(read: &[&str], write: &[&str], delete: &[&str]) -> S3Rules {
    let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect();
    S3Rules { bucket: "acme-data".into(), read: v(read), write: v(write), delete: v(delete) }
}

#[test]
fn session_policy_is_exactly_the_grant() {
    let p = session_policy(&rules(&["tasks/123/"], &["tasks/123/out/"], &[])).unwrap();
    let v: Value = serde_json::from_str(&p).unwrap();
    assert_eq!(v["Version"], "2012-10-17");
    let st = v["Statement"].as_array().unwrap();
    assert_eq!(st.len(), 3);
    assert_eq!(st[0]["Resource"][0], "arn:aws:s3:::acme-data/tasks/123/*");
    assert_eq!(st[1]["Condition"]["StringLike"]["s3:prefix"][0], "tasks/123/*");
    assert_eq!(st[2]["Resource"][0], "arn:aws:s3:::acme-data/tasks/123/out/*");
    assert!(!p.contains("s3:DeleteObject"), "no delete prefixes, no delete action");
    assert!(!p.contains(' '), "minified");
    // The whole bucket lists without a prefix condition.
    let all = session_policy(&rules(&[""], &[], &[])).unwrap();
    assert!(!all.contains("Condition"));
    assert!(session_policy(&rules(&[], &[], &[])).is_err(), "empty lists grant nothing");
    let many: Vec<String> = (0..40).map(|i| format!("tasks/{i:04}/some/deep/prefix/")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let e = session_policy(&rules(&many, &[], &[])).unwrap_err();
    assert!(e.contains("2048"), "{e}");
}

/// IAM wildcard matching (`*` any run, `?` one character).
fn glob(p: &[u8], s: &[u8]) -> bool {
    match (p.first(), s.first()) {
        (None, None) => true,
        (Some(b'*'), _) => glob(&p[1..], s) || (!s.is_empty() && glob(p, &s[1..])),
        (Some(b'?'), Some(_)) => glob(&p[1..], &s[1..]),
        (Some(a), Some(b)) if a == b => glob(&p[1..], &s[1..]),
        _ => false,
    }
}

/// A reference evaluator for the Allow-only session policies this module
/// emits: what AWS would allow the minted credentials to do.
fn iam_allows(policy: &str, op: &str, bucket: &str, key: &str) -> bool {
    let (action, resource, prefix) = match op {
        "s3.get" => ("s3:GetObject", format!("arn:aws:s3:::{bucket}/{key}"), None),
        "s3.list" => ("s3:ListBucket", format!("arn:aws:s3:::{bucket}"), Some(key)),
        "s3.put" => ("s3:PutObject", format!("arn:aws:s3:::{bucket}/{key}"), None),
        _ => ("s3:DeleteObject", format!("arn:aws:s3:::{bucket}/{key}"), None),
    };
    let v: Value = serde_json::from_str(policy).unwrap();
    v["Statement"].as_array().unwrap().iter().any(|s| {
        let has = |k: &str, want: &str| {
            s[k].as_array().unwrap().iter().any(|x| glob(x.as_str().unwrap().as_bytes(), want.as_bytes()))
        };
        let cond = match s.get("Condition") {
            None => true,
            Some(c) => {
                let pats = c["StringLike"]["s3:prefix"].as_array().unwrap();
                prefix.is_some_and(|p| pats.iter().any(|x| glob(x.as_str().unwrap().as_bytes(), p.as_bytes())))
            }
        };
        s["Effect"] == "Allow" && has("Action", action) && has("Resource", &resource) && cond
    })
}

fn prefix_strategy() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec("[ab/]{0,4}", 0..3)
}

proptest! {
    /// The broker's decision (the reference Cedar mirrors) and AWS's
    /// decision on the minted credentials agree for every operation, key
    /// and bucket: neither layer is wider than the other.
    #[test]
    fn broker_and_aws_agree(read in prefix_strategy(), write in prefix_strategy(), delete in prefix_strategy(),
                            key in "[ab/]{0,6}", other in any::<bool>()) {
        let r = S3Rules { bucket: "acme-data".into(), read, write, delete };
        let Ok(policy) = session_policy(&r) else { return Ok(()) };
        let bucket = if other { "acme-other" } else { "acme-data" };
        for op in OPS {
            prop_assert_eq!(rule_allows(&r, op, bucket, &key).is_ok(), iam_allows(&policy, op, bucket, &key),
                            "{} {}/{} under {}", op, bucket, key, policy);
        }
    }
}
