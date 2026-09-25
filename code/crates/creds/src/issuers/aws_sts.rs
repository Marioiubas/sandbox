//! The `aws_sts` issuer (AWS STS Session Policies). The broker calls
//! `AssumeRole` with the base credentials the user configured, passing an
//! inline session policy compiled from the grant, a 15-minute default
//! duration and the session's end user as `SourceIdentity`; the minted
//! session lives only in broker memory and signs authorized S3 requests
//! at egress. Request parameters and the response shape follow the STS API
//! reference (API_AssumeRole, checked 2026-09-25).

use super::sigv4::{self, Scope};
use super::{ApiEndpoint, Transport};
use crate::{Issued, Secret};
use http::{HeaderMap, HeaderName, HeaderValue};
use policy::SecretRef;
use policy::config::AwsStsIssuerSpec;
use policy::s3::{region_ok, uri_encode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// STS accepts 900 s to 43,200 s (and at most the role's maximum).
pub const MIN_DURATION: Duration = Duration::from_secs(900);
pub const MAX_DURATION: Duration = Duration::from_secs(43_200);

pub struct AwsSts {
    pub name: String,
    pub role_arn: String,
    pub region: String,
    pub api: ApiEndpoint,
    pub duration: Duration,
    pub access_key_id: SecretRef,
    pub secret_access_key: SecretRef,
    pub session_token: Option<SecretRef>,
    pub source_identity: bool,
}

impl std::fmt::Debug for AwsSts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsSts")
            .field("name", &self.name)
            .field("role_arn", &self.role_arn)
            .field("api", &self.api.authority())
            .field("duration", &self.duration)
            .finish()
    }
}

fn role_arn_ok(a: &str) -> bool {
    (20..=2048).contains(&a.len())
        && ["arn:aws:iam::", "arn:aws-cn:iam::", "arn:aws-us-gov:iam::"].iter().any(|p| a.starts_with(p))
        && a.contains(":role/")
        && a.bytes().all(|b| b.is_ascii_graphic())
}

impl AwsSts {
    pub fn from_spec(name: &str, s: &AwsStsIssuerSpec) -> Result<AwsSts, String> {
        let ctx = |m: String| format!("[issuers.aws_sts.{name}]: {m}");
        if !role_arn_ok(&s.role_arn) {
            return Err(ctx("role_arn must be an IAM role ARN (arn:aws:iam::<account>:role/<name>)".into()));
        }
        if !region_ok(&s.region) {
            return Err(ctx(format!("{:?} is not a region name", s.region)));
        }
        let duration = match &s.duration {
            None => MIN_DURATION,
            Some(d) => policy::l7::parse_ttl(d).map_err(ctx)?,
        };
        if !(MIN_DURATION..=MAX_DURATION).contains(&duration) {
            return Err(ctx("duration must be 15m to 12h".into()));
        }
        let url = s.sts_endpoint.clone().unwrap_or_else(|| format!("https://sts.{}.amazonaws.com", s.region));
        Ok(AwsSts {
            name: name.to_string(),
            role_arn: s.role_arn.clone(),
            region: s.region.clone(),
            api: ApiEndpoint::parse(&url, &s.sts_addrs).map_err(ctx)?,
            duration,
            access_key_id: SecretRef::parse(&s.access_key_id).map_err(ctx)?,
            secret_access_key: SecretRef::parse(&s.secret_access_key).map_err(ctx)?,
            session_token: s.session_token.as_deref().map(SecretRef::parse).transpose().map_err(ctx)?,
            source_identity: s.source_identity.unwrap_or(true),
        })
    }
}

/// The base credentials, read from their secret sources for each mint.
pub struct BaseCreds {
    pub access_key_id: Secret,
    pub secret_access_key: Secret,
    pub session_token: Option<Secret>,
}

/// A minted session: only in broker memory, zeroized on drop.
pub struct AwsSession {
    pub access_key_id: String,
    pub secret_access_key: Secret,
    pub session_token: Secret,
    pub expires_at: SystemTime,
}

/// `RoleSessionName` and `SourceIdentity` allow `[\w+=,.@-]`, 2-64
/// characters; anything else becomes `-`.
pub fn sts_name(s: &str) -> String {
    let mut o: String =
        s.chars().map(|c| if c.is_ascii_alphanumeric() || "_+=,.@-".contains(c) { c } else { '-' }).take(64).collect();
    while o.len() < 2 {
        o.push('-');
    }
    o
}

/// The form body of an `AssumeRole` call.
pub fn request_body(
    role_arn: &str,
    session_name: &str,
    duration: Duration,
    policy: &str,
    source_identity: Option<&str>,
) -> Vec<u8> {
    let mut p = vec![
        ("Action", "AssumeRole".to_string()),
        ("Version", "2011-06-15".to_string()),
        ("RoleArn", role_arn.to_string()),
        ("RoleSessionName", session_name.to_string()),
        ("DurationSeconds", duration.as_secs().to_string()),
        ("Policy", policy.to_string()),
    ];
    if let Some(si) = source_identity {
        p.push(("SourceIdentity", si.to_string()));
    }
    p.iter().map(|(k, v)| format!("{k}={}", uri_encode(v.as_bytes(), false))).collect::<Vec<_>>().join("&").into_bytes()
}

/// The raw inside of the single `<tag>` element of `hay`.
fn section<'a>(hay: &'a str, tag: &str) -> anyhow::Result<&'a str> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    if hay.matches(&open).count() != 1 || hay.matches(&close).count() != 1 {
        anyhow::bail!("STS response does not have exactly one {tag}");
    }
    let start = hay.find(&open).expect("counted") + open.len();
    let end = hay.find(&close).expect("counted");
    if end < start {
        anyhow::bail!("STS response {tag} is malformed");
    }
    Ok(&hay[start..end])
}

/// The text of the single `<tag>` element, ASCII whitespace removed
/// (credentials contain none); entities and markup are refused.
fn element(hay: &str, tag: &str) -> anyhow::Result<String> {
    let v: String = section(hay, tag)?.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_graphic() && b != b'<' && b != b'&') {
        anyhow::bail!("STS response {tag} has unexpected characters");
    }
    Ok(v)
}

/// Parse an `AssumeRole` response. Errors name the STS error code, never a value.
pub fn parse_response(status: u16, body: &[u8]) -> anyhow::Result<AwsSession> {
    let text = std::str::from_utf8(body).map_err(|_| anyhow::anyhow!("STS response is not UTF-8"))?;
    if status != 200 {
        let code = element(text, "Code").ok().filter(|c| c.len() <= 64).unwrap_or_default();
        anyhow::bail!("STS answered {status} {code}");
    }
    let creds = section(text, "Credentials")?;
    let akid = element(creds, "AccessKeyId")?;
    if !(16..=128).contains(&akid.len()) || !akid.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()) {
        anyhow::bail!("STS response AccessKeyId is not an access key ID");
    }
    let exp = element(creds, "Expiration")?;
    let exp = time::OffsetDateTime::parse(&exp, &time::format_description::well_known::Rfc3339)
        .map_err(|_| anyhow::anyhow!("STS response Expiration is not RFC 3339"))?;
    Ok(AwsSession {
        access_key_id: akid,
        secret_access_key: Secret::new(element(creds, "SecretAccessKey")?.into_bytes()),
        session_token: Secret::new(element(creds, "SessionToken")?.into_bytes()),
        expires_at: UNIX_EPOCH + Duration::from_secs(u64::try_from(exp.unix_timestamp()).unwrap_or(0)),
    })
}

fn text(s: &Secret, what: &str) -> anyhow::Result<String> {
    let v = std::str::from_utf8(s.expose()).map_err(|_| anyhow::anyhow!("the base {what} is not text"))?.trim();
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_graphic()) {
        anyhow::bail!("the base {what} has unexpected characters");
    }
    Ok(v.to_string())
}

/// Call `AssumeRole` once.
pub async fn mint(
    sts: &AwsSts,
    base: &BaseCreds,
    transport: &dyn Transport,
    policy: &str,
    session_name: &str,
    source_identity: Option<&str>,
) -> anyhow::Result<AwsSession> {
    let body = request_body(&sts.role_arn, session_name, sts.duration, policy, source_identity);
    let (_, amz_date) = sigv4::amz_dates(SystemTime::now());
    let path = format!("{}/", sts.api.base_path);
    let mut headers = vec![
        ("content-type".to_string(), "application/x-www-form-urlencoded; charset=utf-8".to_string()),
        ("host".to_string(), sts.api.authority()),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    let token = base.session_token.as_ref().map(|t| text(t, "session token")).transpose()?;
    if let Some(t) = &token {
        headers.push(("x-amz-security-token".to_string(), t.clone()));
    }
    let akid = text(&base.access_key_id, "access key ID")?;
    let secret = zeroize::Zeroizing::new(text(&base.secret_access_key, "secret access key")?);
    let scope = Scope {
        access_key_id: &akid,
        secret: secret.as_bytes(),
        region: &sts.region,
        service: "sts",
        amz_date: &amz_date,
    };
    let (signed, sig) =
        sigv4::sign(&scope, "POST", &uri_encode(path.as_bytes(), true), "", &headers, &sigv4::hex_sha256(&body));
    headers.push(("authorization".to_string(), sigv4::authorization(&scope, &signed, &sig)));
    headers.retain(|(k, _)| k != "host");
    let (status, resp) = tokio::time::timeout(Duration::from_secs(20), transport.post(&sts.api, &path, headers, body))
        .await
        .map_err(|_| anyhow::anyhow!("AssumeRole timed out"))??;
    parse_response(status, &resp)
}

fn header(v: &str) -> anyhow::Result<HeaderValue> {
    HeaderValue::from_str(v).map_err(|_| anyhow::anyhow!("not a header value"))
}

/// Re-sign an authorized S3 request with the minted session. Sets
/// `x-amz-date`, `x-amz-security-token`, `x-amz-content-sha256` (the
/// client's verified value, else `UNSIGNED-PAYLOAD`) and `authorization`;
/// signs `host`, `content-type`, `content-md5` and every `x-amz-*` header.
/// `canonical_uri` and `canonical_query` must be exactly what is forwarded.
pub fn sign_s3(
    issued: &Issued,
    region: &str,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &mut HeaderMap,
    now: SystemTime,
) -> anyhow::Result<()> {
    let keys =
        issued.aws().ok_or_else(|| anyhow::anyhow!("credential {} is not an AWS session", issued.credential_id))?;
    let (_, amz_date) = sigv4::amz_dates(now);
    for h in ["authorization", "x-amz-date", "x-amz-security-token", "date"] {
        headers.remove(h);
    }
    headers.insert(HeaderName::from_static("x-amz-date"), header(&amz_date)?);
    let token = std::str::from_utf8(keys.session_token.expose()).map_err(|_| anyhow::anyhow!("token is not text"))?;
    let mut tv = header(token)?;
    tv.set_sensitive(true);
    headers.insert(HeaderName::from_static("x-amz-security-token"), tv);
    if !headers.contains_key("x-amz-content-sha256") {
        headers.insert(HeaderName::from_static("x-amz-content-sha256"), HeaderValue::from_static("UNSIGNED-PAYLOAD"));
    }
    let payload = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("bad x-amz-content-sha256"))?
        .to_string();
    let mut signed = Vec::new();
    for (name, value) in headers.iter() {
        let n = name.as_str();
        if matches!(n, "host" | "content-type" | "content-md5") || n.starts_with("x-amz-") {
            let v = sigv4::canonical_value(value.as_bytes())
                .ok_or_else(|| anyhow::anyhow!("header {n} cannot be signed"))?;
            signed.push((n.to_string(), v));
        }
    }
    if !signed.iter().any(|(n, _)| n == "host") {
        anyhow::bail!("no host header to sign");
    }
    let scope = Scope {
        access_key_id: &keys.access_key_id,
        secret: issued.secret().expose(),
        region,
        service: "s3",
        amz_date: &amz_date,
    };
    let (names, sig) = sigv4::sign(&scope, method, canonical_uri, canonical_query, &signed, &payload);
    let mut auth = header(&sigv4::authorization(&scope, &names, &sig))?;
    auth.set_sensitive(true);
    headers.insert(http::header::AUTHORIZATION, auth);
    Ok(())
}

#[cfg(test)]
mod tests;
