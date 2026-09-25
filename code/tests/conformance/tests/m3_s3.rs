//! M3 acceptance D6: S3 reads work through credentials the broker mints
//! with STS; writes outside the granted prefix are denied, by Cedar at the
//! broker and, independently, by the session policy AWS enforces on the
//! minted credentials. Against a fake STS and a fake S3 that verify every
//! SigV4 signature. The agent (curl) holds only a sentinel access key ID.

use audit::{DecisionResult, EventKind, Reason};
use conformance::m1::*;
use conformance::*;
use creds::issuers::sigv4;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const BUCKET_HOST: &str = "acme-data.s3.us-east-1.amazonaws.com";
const STS_HOST: &str = "sts.us-east-1.amazonaws.com";
const BASE_AKID: &str = "AKIDBASETESTNOTREAL0";

/// What the fake AWS saw and issued.
#[derive(Default)]
struct Aws {
    base_secret: String,
    /// Minted sessions: access key ID → (secret, token, session policy).
    sessions: HashMap<String, (String, String, String)>,
    assume_calls: Vec<HashMap<String, String>>,
    objects: HashMap<String, Vec<u8>>,
    /// Requests whose signature or token did not verify.
    bad_signatures: Vec<String>,
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).unwrap();
    hex::encode(b)
}

fn form(body: &[u8]) -> HashMap<String, String> {
    let dec = |s: &str| {
        let pairs = l7::s3::query_pairs(Some(&format!("k={s}"))).unwrap();
        pairs[0].1.clone()
    };
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_string(), dec(v)))
        .collect()
}

/// Verify a SigV4 request the way AWS does: recompute over the signed
/// headers as received, the path as received and the canonical query.
fn verify(s: &Seen, secret: &str, service: &str, payload: &str) -> Result<String, String> {
    let auth = s.header("authorization").ok_or("no authorization")?;
    let rest = auth.strip_prefix("AWS4-HMAC-SHA256 ").ok_or("not SigV4")?;
    let field = |k: &str| rest.split(", ").find_map(|p| p.strip_prefix(k)).map(str::to_string);
    let cred = field("Credential=").ok_or("no Credential")?;
    let signed = field("SignedHeaders=").ok_or("no SignedHeaders")?;
    let sig = field("Signature=").ok_or("no Signature")?;
    let akid = cred.split('/').next().unwrap().to_string();
    let date = s.header("x-amz-date").ok_or("no x-amz-date")?;
    let headers: Vec<(String, String)> = signed
        .split(';')
        .map(|n| (n.to_string(), sigv4::canonical_value(s.header(n).unwrap_or("").as_bytes()).unwrap()))
        .collect();
    let query = l7::s3::canonical_query(&l7::s3::query_pairs(s.query.as_deref()).map_err(|_| "bad query")?);
    let scope =
        sigv4::Scope { access_key_id: &akid, secret: secret.as_bytes(), region: "us-east-1", service, amz_date: date };
    let (_, want) = sigv4::sign(&scope, &s.method, &s.path, &query, &headers, payload);
    if want != sig { Err(format!("signature mismatch for {} {}", s.method, s.path)) } else { Ok(akid) }
}

/// The session policy's decision (Allow statements with `*` wildcards and
/// the `s3:prefix` condition), as AWS would evaluate it.
fn iam_allows(policy: &str, action: &str, resource: &str, prefix: Option<&str>) -> bool {
    fn glob(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => glob(&p[1..], s) || (!s.is_empty() && glob(p, &s[1..])),
            (Some(a), Some(b)) if a == b => glob(&p[1..], &s[1..]),
            _ => false,
        }
    }
    let v: Value = serde_json::from_str(policy).unwrap();
    v["Statement"].as_array().unwrap().iter().any(|st| {
        let any = |k: &str, want: &str| {
            st[k].as_array().unwrap().iter().any(|x| glob(x.as_str().unwrap().as_bytes(), want.as_bytes()))
        };
        let cond = match st.get("Condition") {
            None => true,
            Some(c) => prefix.is_some_and(|p| {
                c["StringLike"]["s3:prefix"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|x| glob(x.as_str().unwrap().as_bytes(), p.as_bytes()))
            }),
        };
        any("Action", action) && any("Resource", resource) && cond
    })
}

fn sts_handler(aws: Arc<Mutex<Aws>>) -> Handler {
    Arc::new(move |s: &Seen| {
        let mut a = aws.lock().unwrap();
        let payload = sigv4::hex_sha256(&s.body);
        match verify(s, &a.base_secret.clone(), "sts", &payload) {
            Ok(akid) if akid == BASE_AKID => {}
            other => {
                a.bad_signatures.push(format!("sts: {other:?}"));
                return Reply::new(
                    403,
                    "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>",
                );
            }
        }
        let f = form(&s.body);
        let (akid, secret, token) = (format!("ASIA{}", random_hex(8).to_uppercase()), random_hex(20), random_hex(40));
        a.sessions.insert(akid.clone(), (secret.clone(), token.clone(), f.get("Policy").cloned().unwrap_or_default()));
        a.assume_calls.push(f);
        let exp = time::OffsetDateTime::now_utc() + time::Duration::minutes(15);
        let exp = exp.format(&time::format_description::well_known::Rfc3339).unwrap();
        Reply::new(
            200,
            format!(
                "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>{akid}</AccessKeyId>\
                 <SecretAccessKey>{secret}</SecretAccessKey><SessionToken>{token}</SessionToken>\
                 <Expiration>{exp}</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"
            ),
        )
    })
}

fn s3_handler(aws: Arc<Mutex<Aws>>) -> Handler {
    Arc::new(move |s: &Seen| {
        let mut a = aws.lock().unwrap();
        let deny = |code: u16, c: &str| Reply::new(code, format!("<Error><Code>{c}</Code></Error>"));
        let payload = s.header("x-amz-content-sha256").unwrap_or("").to_string();
        if payload.len() == 64 && payload != sigv4::hex_sha256(&s.body) {
            return deny(400, "XAmzContentSHA256Mismatch");
        }
        let akid =
            s.header("authorization").and_then(|h| h.split("Credential=").nth(1)).and_then(|c| c.split('/').next());
        let Some((secret, token, policy)) = akid.and_then(|k| a.sessions.get(k)).cloned() else {
            a.bad_signatures.push(format!("s3: unknown access key in {:?}", s.header("authorization")));
            return deny(403, "InvalidAccessKeyId");
        };
        if s.header("x-amz-security-token") != Some(token.as_str()) || verify(s, &secret, "s3", &payload).is_err() {
            a.bad_signatures.push(format!("s3: {} {}", s.method, s.path));
            return deny(403, "SignatureDoesNotMatch");
        }
        let key = s.path.trim_start_matches('/').to_string();
        let key = l7::s3::query_pairs(Some(&format!("k={key}"))).unwrap()[0].1.clone();
        let object = format!("arn:aws:s3:::acme-data/{key}");
        match (s.method.as_str(), key.is_empty()) {
            ("GET", true) => {
                let q = l7::s3::query_pairs(s.query.as_deref()).unwrap();
                let prefix = q.iter().find(|(k, _)| k == "prefix").map(|(_, v)| v.clone()).unwrap_or_default();
                if !iam_allows(&policy, "s3:ListBucket", "arn:aws:s3:::acme-data", Some(&prefix)) {
                    return deny(403, "AccessDenied");
                }
                let keys: String = a
                    .objects
                    .keys()
                    .filter(|k| k.starts_with(&prefix))
                    .map(|k| format!("<Contents><Key>{k}</Key></Contents>"))
                    .collect();
                Reply::new(200, format!("<ListBucketResult>{keys}</ListBucketResult>"))
            }
            ("GET", false) if iam_allows(&policy, "s3:GetObject", &object, None) => match a.objects.get(&key) {
                Some(b) => Reply::new(200, b.clone()),
                None => deny(404, "NoSuchKey"),
            },
            ("PUT", false) if iam_allows(&policy, "s3:PutObject", &object, None) => {
                a.objects.insert(key, s.body.clone());
                Reply::new(200, "")
            }
            _ => deny(403, "AccessDenied"),
        }
    })
}

struct Fx {
    h: Harness,
    aws: Arc<Mutex<Aws>>,
    s3: HttpsServer,
    sts: HttpsServer,
    base_secret: String,
    _ca_dir: tempfile::TempDir,
}

fn setup() -> Fx {
    let ca_dir = tempfile::Builder::new().prefix("bkca.").tempdir_in("/tmp").unwrap();
    let ca = TestCa::new(ca_dir.path());
    let base_secret = canary("aws-base-secret");
    let aws = Arc::new(Mutex::new(Aws { base_secret: base_secret.clone(), ..Default::default() }));
    aws.lock().unwrap().objects.insert("tasks/123/in.txt".into(), b"input-data".to_vec());
    aws.lock().unwrap().objects.insert("tasks/secret.txt".into(), b"not-for-this-task".to_vec());
    let sts = HttpsServer::start(&ca, STS_HOST, sts_handler(aws.clone()));
    let s3 = HttpsServer::start(&ca, BUCKET_HOST, s3_handler(aws.clone()));
    let h = Harness::new("version = 1\n");
    h.write_secret("aws-base-akid", BASE_AKID.as_bytes());
    h.write_secret("aws-base-secret", base_secret.as_bytes());
    h.set_config(&format!(
        "version = 1\n[tls]\nextra_roots = [\"{}\"]\n\n[issuers.aws_sts.dev]\n\
         role_arn = \"arn:aws:iam::123456789012:role/agent-s3\"\nregion = \"us-east-1\"\n\
         access_key_id = \"file:aws-base-akid\"\nsecret_access_key = \"file:aws-base-secret\"\n\
         sts_endpoint = \"https://{STS_HOST}:{}\"\nsts_addrs = [\"127.0.0.1\"]\n\n{}",
        ca.pem_path.display(),
        sts.port,
        loopback_grant(
            "data",
            BUCKET_HOST,
            s3.port,
            "protocol = \"s3\"\ns3 = { bucket = \"acme-data\", read = [\"tasks/123/\"], write = [\"tasks/123/out/\"] }\n\
             credential = { kind = \"aws_sts\", issuer = \"dev\" }"
        )
    ));
    Fx { h, aws, s3, sts, base_secret, _ca_dir: ca_dir }
}

impl Fx {
    /// One curl call signing with whatever the sandbox's AWS variables hold.
    fn curl(&self, method: &str, target: &str, extra: &str) -> String {
        format!(
            "curl -sS -o /dev/null -w '%{{http_code}} ' -X {method} --aws-sigv4 aws:amz:us-east-1:s3 \
             --user \"$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY\" {extra} 'https://{BUCKET_HOST}:{}{target}'; ",
            self.s3.port
        )
    }
}

fn denies(evs: &[audit::AuditEvent]) -> Vec<Reason> {
    evs.iter()
        .filter(|e| e.kind == EventKind::RequestDecision)
        .filter(|e| matches!(&e.decision, Some(d) if d.result == DecisionResult::Deny))
        .filter_map(|e| e.reason)
        .collect()
}

#[test]
fn d6_s3_reads_through_minted_credentials_and_out_of_prefix_writes_are_denied() {
    let f = setup();
    let put = "--data-binary result-data -H 'content-type: text/plain'";
    let steps = [
        f.curl("GET", "/tasks/123/in.txt", ""),
        f.curl("PUT", "/tasks/123/out/result.txt", put),
        f.curl("GET", "/?list-type=2&prefix=tasks%2F123%2F", ""),
        f.curl("PUT", "/tasks/999/evil.txt", put),
        f.curl("GET", "/tasks/secret.txt", ""),
        f.curl("PUT", "/tasks/123/out/public.txt", &format!("{put} -H 'x-amz-acl: public-read'")),
        f.curl("GET", "/tasks/123/in.txt?acl", ""),
    ]
    .concat();
    let script = format!(
        "{steps} echo; case \"$AWS_ACCESS_KEY_ID\" in brk_s_*) echo sentinel-akid;; esac; \
         env | grep -c '{}'; true",
        &f.base_secret
    );
    let n0 = f.h.events().len();
    let r = f.h.sh(&script);
    assert_eq!(r.code, 0, "{r:?}");
    let mut lines = r.stdout.lines();
    let codes: Vec<&str> = lines.next().unwrap().split_whitespace().collect();
    assert_eq!(codes, ["200", "200", "200", "403", "403", "403", "403"], "{r:?}");
    assert_eq!(lines.next(), Some("sentinel-akid"), "the agent's access key ID is a sentinel");
    assert_eq!(lines.next().map(str::trim), Some("0"), "the base secret is not in the agent's environment");
    let evs: Vec<_> = f.h.events().into_iter().skip(n0).collect();
    assert_eq!(
        denies(&evs),
        [Reason::S3PrefixNotAllowed, Reason::S3PrefixNotAllowed, Reason::S3RouteUnknown, Reason::S3RouteUnknown]
    );

    let aws = f.aws.lock().unwrap();
    assert!(aws.bad_signatures.is_empty(), "{:?}", aws.bad_signatures);
    assert_eq!(aws.objects.get("tasks/123/out/result.txt").map(Vec::as_slice), Some(b"result-data".as_slice()));
    assert!(!aws.objects.contains_key("tasks/999/evil.txt") && !aws.objects.contains_key("tasks/123/out/public.txt"));
    // One AssumeRole for the session's scope, narrowed to the grant.
    assert_eq!(aws.assume_calls.len(), 1, "minted once, then reused");
    let call = &aws.assume_calls[0];
    assert_eq!(call["Action"], "AssumeRole");
    assert_eq!(call["RoleArn"], "arn:aws:iam::123456789012:role/agent-s3");
    assert_eq!(call["DurationSeconds"], "900");
    assert!(call["RoleSessionName"].starts_with("broker-"));
    assert!(call["SourceIdentity"].starts_with("local-"), "{call:?}");
    let policy = &call["Policy"];
    assert!(policy.len() <= 2048 && policy.contains("arn:aws:s3:::acme-data/tasks/123/*"), "{policy}");
    // Nothing the agent held reached AWS; nothing AWS issued reached the agent.
    let seen = f.s3.seen.lock().unwrap();
    assert_eq!(seen.len(), 3, "denied requests never reached S3");
    for s in seen.iter() {
        let all = format!("{:?}", s.headers);
        assert!(!all.contains("brk_s_") && !all.contains("brk_aws"), "no sentinel upstream: {all}");
    }
    let (secret, token, _) = aws.sessions.values().next().unwrap();
    for leaked in [secret, token, &f.base_secret] {
        assert!(!r.stdout.contains(leaked.as_str()) && !r.stderr.contains(leaked.as_str()));
        assert!(!String::from_utf8_lossy(&f.h.audit_bytes()).contains(leaked.as_str()), "never in the audit log");
    }
    assert_eq!(f.sts.seen.lock().unwrap().len(), 1);
    // Allow rows name the minted credential, then its reuse.
    let origins: Vec<String> = evs
        .iter()
        .filter(|e| e.kind == EventKind::RequestDecision)
        .filter_map(|e| e.detail.get("credential_origin").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    assert_eq!(origins, ["mint", "reuse", "reuse"]);
}

#[test]
fn d6_the_session_policy_denies_on_its_own() {
    // AWS-side, independently of Cedar: the minted credentials themselves
    // cannot write outside the prefix, even if a request got past the broker.
    let f = setup();
    let r = f.h.sh(&f.curl("GET", "/tasks/123/in.txt", ""));
    assert_eq!(r.stdout.trim(), "200", "{r:?}");
    let (akid, (secret, token, _)) = {
        let aws = f.aws.lock().unwrap();
        aws.sessions.iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap()
    };
    let handler = s3_handler(f.aws.clone());
    let signed = |method: &str, path: &str| {
        let (_, date) = sigv4::amz_dates(std::time::SystemTime::now());
        let host = format!("{BUCKET_HOST}:{}", f.s3.port);
        let headers = vec![
            ("host".to_string(), host.clone()),
            ("x-amz-content-sha256".to_string(), "UNSIGNED-PAYLOAD".to_string()),
            ("x-amz-date".to_string(), date.clone()),
            ("x-amz-security-token".to_string(), token.clone()),
        ];
        let scope = sigv4::Scope {
            access_key_id: &akid,
            secret: secret.as_bytes(),
            region: "us-east-1",
            service: "s3",
            amz_date: &date,
        };
        let (names, sig) = sigv4::sign(&scope, method, path, "", &headers, "UNSIGNED-PAYLOAD");
        let mut h = headers;
        h.push(("authorization".into(), sigv4::authorization(&scope, &names, &sig)));
        Seen { method: method.into(), path: path.into(), query: None, headers: h, body: b"x".to_vec() }
    };
    assert_eq!(handler(&signed("PUT", "/tasks/123/out/ok.txt")).status, 200);
    assert_eq!(handler(&signed("PUT", "/tasks/999/evil.txt")).status, 403);
    assert_eq!(handler(&signed("GET", "/tasks/secret.txt")).status, 403);
    assert!(f.aws.lock().unwrap().bad_signatures.is_empty());
}

#[test]
fn d6_a_planted_aws_key_is_rejected() {
    // I7: an access key the broker did not issue is refused before any
    // credential is minted or anything is forwarded.
    let f = setup();
    let n0 = f.h.events().len();
    let script = format!(
        "curl -sS -o /dev/null -w '%{{http_code}}' --aws-sigv4 aws:amz:us-east-1:s3 --user AKIDATTACKERPLANTED0:x \
         'https://{BUCKET_HOST}:{}/tasks/123/in.txt'",
        f.s3.port
    );
    let r = f.h.sh(&script);
    assert_eq!(r.stdout.trim(), "403", "{r:?}");
    let evs: Vec<_> = f.h.events().into_iter().skip(n0).collect();
    assert_eq!(denies(&evs), [Reason::ForeignCredential]);
    assert!(f.s3.seen.lock().unwrap().is_empty());
    assert!(f.sts.seen.lock().unwrap().is_empty(), "nothing minted for a rejected request");
}
