//! Amazon S3 grants (AWS STS Session Policies): the endpoint grammar, the
//! operation classes a grant names, the reference check `broker why`
//! explains with, and the inline session policy the `aws_sts` issuer sends.
//!
//! Cedar decides at the broker. The session policy makes AWS enforce the
//! same bucket and prefixes on the minted credentials, so a broker bug in
//! either layer alone does not widen what the credentials can do.

use crate::config::EgressEntry;
use crate::github::Label;
use crate::l7::Protocol;
use audit::Reason;
use netguard::{CanonicalHost, HostPattern};
use serde_json::json;

/// Largest inline session policy STS accepts, in plaintext characters
/// (API_AssumeRole: "can't exceed 2,048 characters").
pub const MAX_SESSION_POLICY: usize = 2048;

/// Operation classes: object reads (GetObject, HeadObject), listings
/// (ListObjects, ListObjectsV2), writes (PutObject and the multipart
/// calls) and deletes (DeleteObject).
pub const OPS: &[&str] = &["s3.get", "s3.list", "s3.put", "s3.delete"];

pub fn is_op(v: &str) -> bool {
    OPS.contains(&v)
}

/// An S3 REST endpoint: virtual-hosted (`<bucket>.s3.<region>.amazonaws.com`)
/// or path-style (`s3.<region>.amazonaws.com/<bucket>/<key>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// The bucket a virtual-hosted name carries; `None` for path-style.
    pub bucket: Option<String>,
    /// The region requests to this endpoint are signed for.
    pub region: String,
}

/// SigV4 `UriEncode` (IAM User Guide, "Create a signed AWS API request"):
/// every byte except `A-Za-z0-9-._~` as `%XX` in upper case, and `/` too
/// unless `keep_slash` (object key paths). The S3 adapter forwards, and the
/// signer signs, strings made only by this function.
pub fn uri_encode(b: &[u8], keep_slash: bool) -> String {
    let mut o = String::with_capacity(b.len() * 3);
    for &c in b {
        if c.is_ascii_alphanumeric() || b"-._~".contains(&c) || (keep_slash && c == b'/') {
            o.push(c as char);
        } else {
            o.push_str(&format!("%{c:02X}"));
        }
    }
    o
}

/// A region name as AWS spells them (`us-east-1`).
pub fn region_ok(r: &str) -> bool {
    (4..=32).contains(&r.len())
        && r.as_bytes()[0].is_ascii_lowercase()
        && r.contains('-')
        && !r.ends_with('-')
        && r != "dualstack"
        && r.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// General-purpose bucket naming rules (3-63 of `a-z0-9.-`, alphanumeric at
/// both ends, no `..`).
pub fn bucket_ok(b: &str) -> bool {
    let bytes = b.as_bytes();
    (3..=63).contains(&b.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[b.len() - 1].is_ascii_alphanumeric()
        && !b.contains("..")
        && b.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
}

/// The endpoint a canonical host names, if it is one of the AWS S3 forms
/// (`s3`, `s3.<region>`, `s3.dualstack.<region>`, `s3-<region>`, each with
/// an optional bucket in front). Anything else is not an S3 endpoint.
pub fn endpoint(host: &CanonicalHost) -> Option<Endpoint> {
    let labels: Vec<&str> = host.as_str().split('.').collect();
    let n = labels.len();
    if n < 3 || labels[n - 2] != "amazonaws" || labels[n - 1] != "com" {
        return None;
    }
    let i = labels[..n - 2].iter().position(|l| *l == "s3" || l.starts_with("s3-"))?;
    let rest = &labels[i + 1..n - 2];
    let region = if labels[i] == "s3" {
        match rest {
            [] => "us-east-1".to_string(),
            [r] | ["dualstack", r] => r.to_string(),
            _ => return None,
        }
    } else {
        if !rest.is_empty() {
            return None;
        }
        match &labels[i][3..] {
            "external-1" => "us-east-1".to_string(),
            r => r.to_string(),
        }
    };
    if !region_ok(&region) {
        return None;
    }
    let bucket = labels[..i].join(".");
    match bucket.as_str() {
        "" => Some(Endpoint { bucket: None, region }),
        b if bucket_ok(b) => Some(Endpoint { bucket: Some(bucket), region }),
        _ => None,
    }
}

/// A key prefix a grant may name: printable ASCII without a leading `/`,
/// and without the characters that are wildcards or variables in Cedar
/// `like` patterns or IAM policies (`*`, `?`, `$`), quotes or backslashes.
pub fn prefix_ok(p: &str) -> bool {
    p.len() <= 512 && !p.starts_with('/') && p.bytes().all(|b| b.is_ascii_graphic() && !b"*?$\"\\".contains(&b))
}

/// The S3 part of one grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3Rules {
    pub bucket: String,
    pub read: Vec<String>,
    pub write: Vec<String>,
    pub delete: Vec<String>,
}

impl S3Rules {
    /// The prefixes an operation class may touch (none for unknown ones).
    pub fn prefixes(&self, op: &str) -> &[String] {
        match op {
            "s3.get" | "s3.list" => &self.read,
            "s3.put" => &self.write,
            "s3.delete" => &self.delete,
            _ => &[],
        }
    }
}

/// Validate the `s3` key: only on `protocol = "s3"`, on an exact S3
/// endpoint host of the named bucket, with well-formed prefixes.
pub(crate) fn compile(
    grant_id: &str,
    e: &EgressEntry,
    protocol: Protocol,
    pattern: &HostPattern,
) -> Result<Option<S3Rules>, String> {
    if protocol != Protocol::S3 {
        if e.s3.is_some() {
            return Err(format!("{grant_id}: s3 rules need protocol = \"s3\""));
        }
        return Ok(None);
    }
    if e.methods.is_some() || e.paths.is_some() || e.allow.is_some() || e.verbs.is_some() || e.repos.is_some() {
        return Err(format!("{grant_id}: protocol = \"s3\" takes s3 = {{ bucket, read, write, delete }} only"));
    }
    let Some(a) = &e.s3 else {
        return Err(format!("{grant_id}: protocol = \"s3\" needs s3 = {{ bucket, read, write, delete }}"));
    };
    if !bucket_ok(&a.bucket) {
        return Err(format!("{grant_id}: {:?} is not a valid bucket name", a.bucket));
    }
    let ep = match pattern {
        HostPattern::Exact(h) => endpoint(h),
        HostPattern::Subdomains(_) => None,
    }
    .ok_or_else(|| {
        format!("{grant_id}: an s3 grant's host must be an S3 endpoint (<bucket>.s3.<region>.amazonaws.com or s3.<region>.amazonaws.com)")
    })?;
    if let Some(b) = &ep.bucket
        && b != &a.bucket
    {
        return Err(format!("{grant_id}: the host names bucket {b}, not {}", a.bucket));
    }
    for p in a.read.iter().chain(&a.write).chain(&a.delete) {
        if !prefix_ok(p) {
            return Err(format!("{grant_id}: bad s3 prefix {p:?} (printable, no leading /, no * ? $ \" \\)"));
        }
    }
    Ok(Some(S3Rules {
        bucket: a.bucket.clone(),
        read: a.read.clone(),
        write: a.write.clone(),
        delete: a.delete.clone(),
    }))
}

/// The reference (explainer) check of one S3 action against one grant.
pub(crate) fn rule_allows(r: &S3Rules, op: &str, bucket: &str, key: &str) -> Result<(), Reason> {
    if bucket == r.bucket && r.prefixes(op).iter().any(|p| key.starts_with(p.as_str())) {
        Ok(())
    } else {
        Err(Reason::S3PrefixNotAllowed)
    }
}

/// The inline session policy for credentials minted for this grant:
/// exactly the grant's bucket and prefixes, minified, within the STS limit.
pub fn session_policy(r: &S3Rules) -> Result<String, String> {
    let objects =
        |ps: &[String]| -> Vec<String> { ps.iter().map(|p| format!("arn:aws:s3:::{}/{}*", r.bucket, p)).collect() };
    let mut st = Vec::new();
    if !r.read.is_empty() {
        st.push(json!({ "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": objects(&r.read) }));
        let bucket = format!("arn:aws:s3:::{}", r.bucket);
        st.push(if r.read.iter().any(|p| p.is_empty()) {
            // The whole bucket: also listings that name no prefix.
            json!({ "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": [bucket] })
        } else {
            let like: Vec<String> = r.read.iter().map(|p| format!("{p}*")).collect();
            json!({ "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": [bucket],
                    "Condition": { "StringLike": { "s3:prefix": like } } })
        });
    }
    if !r.write.is_empty() {
        st.push(json!({ "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
                        "Resource": objects(&r.write) }));
    }
    if !r.delete.is_empty() {
        st.push(json!({ "Effect": "Allow", "Action": ["s3:DeleteObject"], "Resource": objects(&r.delete) }));
    }
    if st.is_empty() {
        return Err("an aws_sts credential needs s3 read, write or delete prefixes (empty lists grant nothing)".into());
    }
    let s = json!({ "Version": "2012-10-17", "Statement": st }).to_string();
    if s.len() > MAX_SESSION_POLICY {
        return Err(format!(
            "the session policy would be {} characters; STS accepts {MAX_SESSION_POLICY} (use fewer or shorter prefixes)",
            s.len()
        ));
    }
    Ok(s)
}

/// The labels an S3 operation raises: reads of a bucket are sensitive
/// (buckets are private unless shown otherwise); writes and deletes are
/// external effects.
pub fn labels_for(op: &str) -> Vec<Label> {
    match op {
        "s3.get" | "s3.list" => vec![Label::SensitiveRead],
        _ => vec![Label::ExternalEffect],
    }
}

#[cfg(test)]
mod tests;
