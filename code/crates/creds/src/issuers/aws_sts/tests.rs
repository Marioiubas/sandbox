use super::*;
use crate::issuers::sigv4;
use std::sync::Mutex;

fn spec() -> AwsStsIssuerSpec {
    AwsStsIssuerSpec {
        role_arn: "arn:aws:iam::123456789012:role/agent-s3".into(),
        region: "us-east-1".into(),
        access_key_id: "env:AWS_BASE_AKID".into(),
        secret_access_key: "env:AWS_BASE_SECRET".into(),
        ..Default::default()
    }
}

#[test]
fn issuer_config_is_validated() {
    let s = AwsSts::from_spec("dev", &spec()).unwrap();
    assert_eq!(s.duration, Duration::from_secs(900));
    assert_eq!(s.api.authority(), "sts.us-east-1.amazonaws.com");
    assert!(s.source_identity);
    for (f, why) in [
        (
            &(|x: &mut AwsStsIssuerSpec| x.role_arn = "arn:aws:iam::1:user/x".into()) as &dyn Fn(&mut AwsStsIssuerSpec),
            "user ARN",
        ),
        (&|x| x.role_arn = "role/agent".into(), "not an ARN"),
        (&|x| x.region = "US-EAST-1".into(), "region"),
        (&|x| x.duration = Some("5m".into()), "too short"),
        (&|x| x.duration = Some("13h".into()), "too long"),
        (&|x| x.sts_endpoint = Some("http://sts.example".into()), "plain http"),
        (&|x| x.access_key_id = "plain-text-key".into(), "not a secret reference"),
    ] {
        let mut x = spec();
        f(&mut x);
        assert!(AwsSts::from_spec("dev", &x).is_err(), "{why}");
    }
}

#[test]
fn names_and_request_body() {
    assert_eq!(sts_name("repo:acme/web:ref:refs/heads/main"), "repo-acme-web-ref-refs-heads-main");
    assert_eq!(sts_name("x"), "x-");
    assert_eq!(sts_name(&"a".repeat(80)).len(), 64);
    let body = String::from_utf8(request_body(
        "arn:aws:iam::123456789012:role/agent-s3",
        "broker-s1",
        Duration::from_secs(900),
        r#"{"Version":"2012-10-17"}"#,
        Some("local-alice"),
    ))
    .unwrap();
    assert_eq!(
        body,
        "Action=AssumeRole&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fagent-s3\
         &RoleSessionName=broker-s1&DurationSeconds=900&Policy=%7B%22Version%22%3A%222012-10-17%22%7D\
         &SourceIdentity=local-alice"
    );
}

/// The sample response from the STS API reference (API_AssumeRole).
const SAMPLE: &str = r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
  <SourceIdentity>Alice</SourceIdentity>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/TestAR</Arn>
      <AssumedRoleId>ARO123EXAMPLE123:TestAR</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <SessionToken>
       AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd
      </SessionToken>
      <Expiration>2019-11-09T13:34:41Z</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>"#;

#[test]
fn responses() {
    let s = parse_response(200, SAMPLE.as_bytes()).unwrap();
    assert_eq!(s.access_key_id, "ASIAIOSFODNN7EXAMPLE");
    assert_eq!(s.secret_access_key.expose(), b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY");
    assert!(s.session_token.expose().starts_with(b"AQoDYXdzEPT//////////wEXAMPLE"));
    assert!(!s.session_token.expose().iter().any(|b| b.is_ascii_whitespace()));
    assert_eq!(s.expires_at, UNIX_EPOCH + Duration::from_secs(1_573_306_481));
    let denied = "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>\
                  <Message>User arn:aws:iam::1:user/x is not authorized</Message></Error></ErrorResponse>";
    let e = format!("{:#}", parse_response(403, denied.as_bytes()).err().unwrap());
    assert_eq!(e, "STS answered 403 AccessDenied");
    for bad in [
        SAMPLE.replace("<AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>", ""),
        SAMPLE.replace("</Credentials>", "</Credentials><Credentials></Credentials>"),
        SAMPLE.replace("ASIAIOSFODNN7EXAMPLE", "asia&amp;x"),
        SAMPLE.replace("2019-11-09T13:34:41Z", "tomorrow"),
        SAMPLE.replace("wJalrXUtnFEMI", "<b>wJalrXUtnFEMI</b>"),
    ] {
        let e = format!("{:#}", parse_response(200, bad.as_bytes()).err().unwrap());
        assert!(!e.contains("wJalr") && !e.contains("AQoD"), "errors never carry values: {e}");
    }
}

/// Path, headers and body of each call.
type Calls = Vec<(String, Vec<(String, String)>, Vec<u8>)>;

/// An STS stand-in that verifies the SigV4 signature it receives.
struct FakeSts {
    seen: Mutex<Calls>,
}

#[async_trait::async_trait]
impl Transport for FakeSts {
    async fn post_json(&self, _: &ApiEndpoint, _: &str, _: &Secret, _: Vec<u8>) -> anyhow::Result<(u16, Vec<u8>)> {
        anyhow::bail!("unused")
    }
    async fn post(
        &self,
        api: &ApiEndpoint,
        path: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> anyhow::Result<(u16, Vec<u8>)> {
        let get = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
        let auth = get("authorization");
        let signed = auth.split("SignedHeaders=").nth(1).unwrap().split(',').next().unwrap().to_string();
        let mut to_sign: Vec<(String, String)> =
            headers.iter().filter(|(k, _)| signed.split(';').any(|s| s == k)).cloned().collect();
        to_sign.push(("host".into(), api.authority()));
        let date = get("x-amz-date");
        let scope = sigv4::Scope {
            access_key_id: "AKIDBASE",
            secret: b"base-secret",
            region: "us-east-1",
            service: "sts",
            amz_date: &date,
        };
        let (_, want) = sigv4::sign(&scope, "POST", path, "", &to_sign, &sigv4::hex_sha256(&body));
        assert!(auth.ends_with(&format!("Signature={want}")), "{auth}");
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDBASE/"), "{auth}");
        self.seen.lock().unwrap().push((path.to_string(), headers, body));
        Ok((200, SAMPLE.replace("2019-11-09", "2099-11-09").into_bytes()))
    }
}

#[tokio::test]
async fn mint_signs_the_call_with_the_base_credentials() {
    let sts = AwsSts::from_spec("dev", &spec()).unwrap();
    let base = BaseCreds {
        access_key_id: Secret::new(b"AKIDBASE".to_vec()),
        secret_access_key: Secret::new(b"base-secret".to_vec()),
        session_token: None,
    };
    let t = FakeSts { seen: Mutex::new(vec![]) };
    let s = mint(&sts, &base, &t, r#"{"Version":"2012-10-17","Statement":[]}"#, "broker-s1", Some("local-alice"))
        .await
        .unwrap();
    assert_eq!(s.access_key_id, "ASIAIOSFODNN7EXAMPLE");
    let seen = t.seen.lock().unwrap();
    let (path, headers, body) = &seen[0];
    assert_eq!(path, "/");
    let body = String::from_utf8(body.clone()).unwrap();
    assert!(body.contains("RoleSessionName=broker-s1") && body.contains("SourceIdentity=local-alice"));
    assert!(body.contains("DurationSeconds=900"));
    assert!(!headers.iter().any(|(_, v)| v.contains("base-secret")), "the secret key is never sent");
}

#[test]
fn s3_requests_are_resigned_with_the_session() {
    let issued =
        Issued::new("data", "aws_sts", Secret::new(b"session-secret".to_vec()), None, None, [0; 32], "mint").with_aws(
            crate::AwsKeys { access_key_id: "ASIASESSION".into(), session_token: Secret::new(b"tok/en+1=".to_vec()) },
        );
    let mut h = HeaderMap::new();
    h.insert("host", HeaderValue::from_static("acme-data.s3.us-east-1.amazonaws.com"));
    h.insert("x-amz-date", HeaderValue::from_static("19990101T000000Z"));
    h.insert("x-amz-meta-note", HeaderValue::from_static("  two   words "));
    h.insert("content-type", HeaderValue::from_static("text/plain"));
    h.insert("user-agent", HeaderValue::from_static("curl/8"));
    let now = UNIX_EPOCH + Duration::from_secs(1_790_000_000);
    sign_s3(&issued, "us-east-1", "PUT", "/tasks/123/out/r.txt", "", &mut h, now).unwrap();
    let (_, date) = sigv4::amz_dates(now);
    assert_eq!(h["x-amz-date"], date.as_str(), "the client's date is replaced");
    assert_eq!(h["x-amz-security-token"], "tok/en+1=");
    assert!(h["x-amz-security-token"].is_sensitive() && h["authorization"].is_sensitive());
    assert_eq!(h["x-amz-content-sha256"], "UNSIGNED-PAYLOAD");
    let auth = h["authorization"].to_str().unwrap();
    let signed = "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-note;x-amz-security-token";
    assert!(auth.contains(&format!("SignedHeaders={signed},")), "{auth}");
    let scope = sigv4::Scope {
        access_key_id: "ASIASESSION",
        secret: b"session-secret",
        region: "us-east-1",
        service: "s3",
        amz_date: &date,
    };
    let headers: Vec<(String, String)> = [
        ("content-type", "text/plain"),
        ("host", "acme-data.s3.us-east-1.amazonaws.com"),
        ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ("x-amz-date", date.as_str()),
        ("x-amz-meta-note", "two words"),
        ("x-amz-security-token", "tok/en+1="),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let (_, want) = sigv4::sign(&scope, "PUT", "/tasks/123/out/r.txt", "", &headers, "UNSIGNED-PAYLOAD");
    assert!(auth.ends_with(&format!("Signature={want}")));
    // Not an AWS session: nothing is signed.
    let plain = Issued::new("x", "static", Secret::new(b"k".to_vec()), None, None, [0; 32], "load");
    assert!(sign_s3(&plain, "us-east-1", "GET", "/", "", &mut HeaderMap::new(), now).is_err());
}

/// Cross-check the canonicalisation against an independent signer: curl's
/// `--aws-sigv4`, from curl 8 on. The AWS test-suite vectors in `sigv4`
/// are the authority; curl 7.81 (Ubuntu 22.04) signs this request
/// differently from both curl 8.x and those rules, so older curls are
/// skipped rather than trusted.
#[test]
fn signatures_match_curl() {
    use std::io::{Read, Write};
    let version = std::process::Command::new("curl").arg("--version").output();
    let major = version
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().nth(1).map(str::to_string))
        .and_then(|v| v.split('.').next().and_then(|m| m.parse::<u32>().ok()));
    if major.is_none_or(|m| m < 8) {
        eprintln!("curl older than 8 (or missing): skipped");
        return;
    }
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut c, _) = l.accept().unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = c.read(&mut chunk).unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let _ = c.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        String::from_utf8(buf).unwrap()
    });
    let out = std::process::Command::new("curl")
        .args(["-sS", "-o", "/dev/null", "--aws-sigv4", "aws:amz:us-east-1:s3", "--user", "AKIDCURL:curl-secret"])
        .args(["-H", "x-amz-meta-a: b", "-H", "content-type: text/plain"])
        .arg(format!("http://127.0.0.1:{port}/acme-data/k%20ey/1?a=1&b=x%2Fy"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let req = server.join().unwrap();
    let mut lines = req.split("\r\n");
    let target = lines.next().unwrap().split(' ').nth(1).unwrap().to_string();
    let headers: Vec<(String, String)> = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let get = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
    let auth = get("authorization");
    let signed = auth.split("SignedHeaders=").nth(1).unwrap().split(',').next().unwrap();
    let to_sign: Vec<(String, String)> =
        headers.iter().filter(|(k, _)| signed.split(';').any(|s| s == k)).cloned().collect();
    let (path, query) = target.split_once('?').unwrap();
    let date = get("x-amz-date");
    let payload = headers
        .iter()
        .find(|(k, _)| k == "x-amz-content-sha256")
        .map(|(_, v)| v.clone())
        .unwrap_or(sigv4::hex_sha256(b""));
    let scope = sigv4::Scope {
        access_key_id: "AKIDCURL",
        secret: b"curl-secret",
        region: "us-east-1",
        service: "s3",
        amz_date: &date,
    };
    let (names, sig) = sigv4::sign(&scope, "GET", path, query, &to_sign, &payload);
    assert_eq!(names, signed);
    assert!(auth.ends_with(&format!("Signature={sig}")), "ours {sig}, curl's {auth}");
}
