//! S3 grants through Cedar: compile rules fail closed, Cedar agrees with
//! the reference check on every key, the `aws_sts` credential binds only
//! to allowed requests, and S3 writes are subject to the Rule of Two.

use super::*;
use crate::config::parse_policy_str;
use crate::egress::EgressPolicy;
use crate::github::Label;
use crate::l7::{Action, CompileEnv, CredKind};
use audit::Reason;
use netguard::canon_host;
use proptest::prelude::*;

const HOST: &str = "acme-data.s3.us-east-1.amazonaws.com";

fn env() -> CompileEnv {
    CompileEnv {
        aws_sts_issuers: ["dev".to_string()].into_iter().collect(),
        session: SessionInfo { expires_at: entities::now_epoch() + 3600, ..Default::default() },
        ..Default::default()
    }
}

fn compile(toml: &str) -> Result<EgressPolicy, String> {
    let p = parse_policy_str(toml).map_err(|e| e.to_string())?;
    EgressPolicy::compile_with([("user", p.egress.as_slice())], &env()).map_err(|e| e.to_string())
}

fn grant(host: &str, extra: &str) -> String {
    format!("version = 1\n[[egress]]\nid = \"data\"\nhost = \"{host}\"\n{extra}\n")
}

const S3: &str = "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"tasks/123/\"], write = [\"tasks/123/out/\"] }\n\
                  credential = { kind = \"aws_sts\", issuer = \"dev\" }";

fn decide(p: &EgressPolicy, op: &str, bucket: &str, key: &str) -> policy_decision::D {
    let mut adm = p.admit_host(&canon_host(HOST.as_bytes()).unwrap(), 443).unwrap();
    p.admit_addrs(&mut adm, &["52.216.1.1".parse().unwrap()]).unwrap();
    let method = if op == "s3.put" { "PUT" } else { "GET" };
    let d = p.authorize_l7(
        &adm,
        &[
            Action::Http { method: method.into(), path: "/x".into() },
            Action::S3 { op: op.into(), bucket: bucket.into(), key: key.into() },
        ],
    );
    policy_decision::D { result: d.result, credential: d.binding.map(|b| b.credential().id.clone()) }
}

mod policy_decision {
    pub struct D {
        pub result: Result<(), audit::Reason>,
        pub credential: Option<String>,
    }
}

#[test]
fn s3_grants_compile_fail_closed() {
    let s3 = "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"a/\"] }";
    assert!(compile(&grant(HOST, s3)).is_ok());
    assert!(compile(&grant("s3.us-east-1.amazonaws.com", s3)).is_ok(), "path-style endpoint");
    for (host, extra, why) in [
        (HOST, "protocol = \"s3\"", "no s3 key"),
        (HOST, "s3 = { bucket = \"acme-data\" }", "s3 without protocol"),
        (HOST, "protocol = \"s3\"\nmethods = [\"GET\"]\ns3 = { bucket = \"acme-data\" }", "methods on s3"),
        ("storage.example.com", s3, "not an S3 endpoint"),
        ("*.s3.us-east-1.amazonaws.com", s3, "wildcard host"),
        ("other.s3.us-east-1.amazonaws.com", s3, "host names another bucket"),
        (HOST, "protocol = \"s3\"\ns3 = { bucket = \"Acme_Data\" }", "bad bucket"),
        (HOST, "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"a*\"] }", "wildcard prefix"),
        (HOST, "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"/a\"] }", "leading slash"),
        (HOST, "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"${aws:username}\"] }", "policy variable"),
        (
            HOST,
            "protocol = \"s3\"\ns3 = { bucket = \"acme-data\" }\ncredential = { kind = \"aws_sts\", issuer = \"dev\" }",
            "empty lists",
        ),
        (
            HOST,
            "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"a/\"] }\ncredential = { kind = \"aws_sts\", issuer = \"prod\" }",
            "unknown issuer",
        ),
        (
            HOST,
            "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"a/\"] }\ncredential = { kind = \"aws_sts\" }",
            "no issuer",
        ),
        (
            HOST,
            "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"a/\"] }\ncredential = { kind = \"aws_sts\", issuer = \"dev\", header = \"x-api-key\" }",
            "header",
        ),
        (
            HOST,
            "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"a/\"] }\ncredential = { kind = \"aws_sts\", issuer = \"dev\", ref = \"env:K\" }",
            "ref",
        ),
        ("api.example.com", "credential = { kind = \"aws_sts\", issuer = \"dev\" }", "aws_sts on http"),
    ] {
        assert!(compile(&grant(host, extra)).is_err(), "{why}");
    }
}

#[test]
fn the_credential_carries_the_compiled_session_policy() {
    let p = compile(&grant(HOST, S3)).unwrap();
    let creds = p.credentials();
    assert_eq!(creds.len(), 1);
    let c = &creds[0];
    assert_eq!(c.env.as_deref(), Some("AWS_ACCESS_KEY_ID"));
    assert_eq!(c.attach, crate::l7::AttachSpec::SigV4);
    let CredKind::AwsSts { issuer, session_policy } = &c.kind else { panic!("{:?}", c.kind) };
    assert_eq!(issuer, "dev");
    assert!(session_policy.contains("arn:aws:s3:::acme-data/tasks/123/*"));
    assert!(session_policy.contains("arn:aws:s3:::acme-data/tasks/123/out/*"));
}

#[test]
fn allowed_operations_bind_the_credential_and_nothing_else_does() {
    let p = compile(&grant(HOST, S3)).unwrap();
    let ok = decide(&p, "s3.get", "acme-data", "tasks/123/in.txt");
    assert_eq!((ok.result, ok.credential.as_deref()), (Ok(()), Some("user:data")));
    assert_eq!(decide(&p, "s3.list", "acme-data", "tasks/123/").result, Ok(()));
    assert_eq!(decide(&p, "s3.put", "acme-data", "tasks/123/out/r.txt").result, Ok(()));
    for (op, bucket, key) in [
        ("s3.put", "acme-data", "tasks/123/in.txt"),
        ("s3.put", "acme-data", "tasks/999/out/x"),
        ("s3.get", "acme-data", "tasks/1234/in.txt"),
        ("s3.list", "acme-data", ""),
        ("s3.list", "acme-data", "tasks/"),
        ("s3.delete", "acme-data", "tasks/123/out/r.txt"),
        ("s3.get", "acme-other", "tasks/123/in.txt"),
    ] {
        let d = decide(&p, op, bucket, key);
        assert_eq!(d.result, Err(Reason::S3PrefixNotAllowed), "{op} {bucket}/{key}");
        assert_eq!(d.credential, None, "no credential for a denied request");
    }
}

#[test]
fn s3_writes_are_subject_to_the_rule_of_two() {
    let p = compile(&grant(HOST, S3)).unwrap();
    assert_eq!(decide(&p, "s3.put", "acme-data", "tasks/123/out/a").result, Ok(()));
    p.labels().raise(Label::UntrustedInput);
    p.labels().raise(Label::SensitiveRead);
    assert_eq!(decide(&p, "s3.get", "acme-data", "tasks/123/a").result, Ok(()), "reads stay allowed");
    assert_eq!(decide(&p, "s3.put", "acme-data", "tasks/123/out/a").result, Err(Reason::RuleOfTwo));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    /// Cedar and the reference check (the explainer, and the session
    /// policy's mirror) agree on every operation, bucket and key.
    #[test]
    fn cedar_agrees_with_the_reference(key in "[ab/]{0,6}", other in any::<bool>()) {
        use std::sync::OnceLock;
        static P: OnceLock<EgressPolicy> = OnceLock::new();
        let p = P.get_or_init(|| compile(&grant(HOST,
            "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"a/\", \"b\"], write = [\"a/b/\"], delete = [\"\"] }")).unwrap());
        let r = crate::s3::S3Rules { bucket: "acme-data".into(), read: vec!["a/".into(), "b".into()],
                                     write: vec!["a/b/".into()], delete: vec!["".into()] };
        let bucket = if other { "acme-other" } else { "acme-data" };
        for op in crate::s3::OPS {
            let want = crate::s3::rule_allows(&r, op, bucket, &key);
            prop_assert_eq!(decide(p, op, bucket, &key).result, want, "{} {}/{}", op, bucket, key);
        }
    }
}
