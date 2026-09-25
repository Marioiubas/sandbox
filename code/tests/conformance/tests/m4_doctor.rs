//! M4: `broker doctor` reports every layer, how TLS is handled for each
//! grant (terminated, spliced or passthrough) and the protocol matrix, and
//! accepts a policy whose credentials name configured issuers.

use conformance::*;

#[test]
fn doctor_reports_layers_the_tls_matrix_and_identity() {
    let h = Harness::new(
        r#"version = 1
[[egress]]
host = "github.com"
id = "git"
protocol = "git"
allow = { fetch = ["${repo_remote}"], push = { repo = "${repo_remote}", refs = ["agent/*"] } }
credential = { kind = "github_app", issuer = "acme", permissions = { contents = "write" }, repos = ["${repo_remote}"] }
[[egress]]
host = "acme-data.s3.us-east-1.amazonaws.com"
id = "data"
protocol = "s3"
s3 = { bucket = "acme-data", read = ["tasks/"] }
credential = { kind = "aws_sts", issuer = "dev" }
[[egress]]
host = "pinned.example.com"
passthrough = true
[[egress]]
host = "registry.npmjs.org"
[issuers.github_app.acme]
app_id = "1"
installation_id = "2"
private_key = "keychain:x"
[issuers.aws_sts.dev]
role_arn = "arn:aws:iam::123456789012:role/r"
region = "us-east-1"
access_key_id = "env:A"
secret_access_key = "env:B"
[identity.login]
issuer = "https://idp.example.com"
client_id = "0oa1"
required = true
"#,
    );
    let r = h.broker(&["doctor"]);
    assert_eq!(r.code, 0, "{r:?}");
    for want in [
        "4 egress grant(s)",
        "github.com ports [443]: TLS terminated, git rules, credential user:git (github_app)",
        "TLS terminated, s3 rules, credential user:data (aws_sts)",
        "pinned.example.com ports [443]: TLS passthrough",
        "registry.npmjs.org ports [443]: TLS spliced after the SNI check",
        "`broker login` to https://idp.example.com (required",
        "QUIC / HTTP/3, other UDP",
        "result: all required layers available",
    ] {
        assert!(r.stdout.contains(want), "missing {want:?} in:\n{}", r.stdout);
    }
    assert!(!r.stdout.contains("INVALID"), "{}", r.stdout);
}
