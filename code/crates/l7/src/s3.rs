//! The Amazon S3 REST adapter (AWS STS Session Policies): a request on an
//! S3 endpoint host is an object read (`s3.get`), a listing (`s3.list`), a
//! write (`s3.put`, including the multipart calls) or a delete
//! (`s3.delete`) of one bucket and key, or it is denied. Operations follow
//! the S3 API reference:
//!
//! - `GET|HEAD /<key>` (GetObject, HeadObject), response overrides and
//!   `partNumber` allowed → `s3.get`;
//! - `GET /` (ListObjects) or `GET /?list-type=2` (ListObjectsV2) → `s3.list`
//!   on the requested `prefix`;
//! - `PUT /<key>` (PutObject), `PUT ?partNumber&uploadId` (UploadPart),
//!   `POST ?uploads` (CreateMultipartUpload), `POST ?uploadId`
//!   (CompleteMultipartUpload), `GET ?uploadId` (ListParts) and
//!   `DELETE ?uploadId` (AbortMultipartUpload) → `s3.put`;
//! - `DELETE /<key>` (DeleteObject) → `s3.delete`.
//!
//! Everything else is denied: bucket and object subresources (`?acl`,
//! `?policy`, `?tagging`, …), versioned access, batch `?delete`, presigned
//! query authentication, CopyObject (`x-amz-copy-source`), ACL, tagging and
//! object-lock headers, and signed-chunk uploads (their chunk signatures
//! are chained to the client's seed signature and cannot survive re-signing).
//!
//! A route also carries the canonical URI and query that SigV4 signs; the
//! broker forwards exactly those, so what it signs is what S3 verifies.

use audit::Reason;
use http::HeaderMap;
use netguard::CanonicalHost;
pub use policy::s3::uri_encode;
use policy::s3::{bucket_ok, endpoint};

/// A mapped request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub op: &'static str,
    pub bucket: String,
    /// The object key, or for a listing the requested prefix.
    pub key: String,
    /// The region the endpoint is signed for.
    pub region: String,
    /// The path, UriEncoded with `/` kept: forwarded and signed as is.
    pub canonical_uri: String,
    /// The query, each name and value UriEncoded, sorted: forwarded and signed.
    pub canonical_query: String,
}

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Percent-decode; `+` is a space in query components (as S3 reads them).
fn decode(s: &str, plus_is_space: bool) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                out.push((hex(*b.get(i + 1)?)? << 4) | hex(*b.get(i + 2)?)?);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// The decoded query parameters, in request order. Malformed escapes,
/// empty pieces and repeated names are refused (fail closed).
pub fn query_pairs(q: Option<&str>) -> Result<Vec<(String, String)>, Reason> {
    let mut out: Vec<(String, String)> = Vec::new();
    let Some(q) = q else { return Ok(out) };
    for piece in q.split('&') {
        let (k, v) = piece.split_once('=').unwrap_or((piece, ""));
        let k = decode(k, true).filter(|k| !k.is_empty()).ok_or(Reason::S3RouteUnknown)?;
        let v = decode(v, true).ok_or(Reason::S3RouteUnknown)?;
        if out.iter().any(|(x, _)| *x == k) {
            return Err(Reason::S3RouteUnknown);
        }
        out.push((k, v));
    }
    Ok(out)
}

/// SigV4's canonical query: names and values UriEncoded, sorted.
pub fn canonical_query(pairs: &[(String, String)]) -> String {
    let mut enc: Vec<(String, String)> =
        pairs.iter().map(|(k, v)| (uri_encode(k.as_bytes(), false), uri_encode(v.as_bytes(), false))).collect();
    enc.sort();
    enc.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

const GET_OBJECT: &[&str] = &[
    "partNumber",
    "response-cache-control",
    "response-content-disposition",
    "response-content-encoding",
    "response-content-language",
    "response-content-type",
    "response-expires",
    "x-id",
];
const LIST_V1: &[&str] = &["delimiter", "encoding-type", "marker", "max-keys", "prefix", "x-id"];
const LIST_V2: &[&str] = &[
    "continuation-token",
    "delimiter",
    "encoding-type",
    "fetch-owner",
    "list-type",
    "max-keys",
    "prefix",
    "start-after",
    "x-id",
];
const LIST_PARTS: &[&str] = &["encoding-type", "max-parts", "part-number-marker", "uploadId", "x-id"];

/// Map a request on an S3 endpoint host to its operation. `path` is
/// canonical (netguard), `query` its raw query.
pub fn route(host: &CanonicalHost, method: &str, path: &str, query: Option<&str>) -> Result<Route, Reason> {
    let unknown = Reason::S3RouteUnknown;
    let ep = endpoint(host).ok_or(unknown)?;
    let decoded = decode(path, false).ok_or(unknown)?;
    let rest = decoded.strip_prefix('/').ok_or(unknown)?;
    let (bucket, key) = match &ep.bucket {
        Some(b) => (b.clone(), rest.to_string()),
        None => match rest.split_once('/') {
            Some((b, k)) => (b.to_string(), k.to_string()),
            None => (rest.to_string(), String::new()),
        },
    };
    if !bucket_ok(&bucket) || key.len() > 1024 {
        return Err(unknown);
    }
    let pairs = query_pairs(query)?;
    let get = |k: &str| pairs.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str());
    let has = |k: &str| get(k).is_some();
    let only = |allowed: &[&str]| pairs.iter().all(|(k, _)| allowed.contains(&k.as_str()));
    if get("encoding-type").is_some_and(|v| v != "url") {
        return Err(unknown);
    }
    let upload = has("uploadId");
    let op = match (key.is_empty(), method) {
        (true, "GET") if get("list-type") == Some("2") && only(LIST_V2) => "s3.list",
        (true, "GET") if !has("list-type") && only(LIST_V1) => "s3.list",
        (false, "GET" | "HEAD") if !upload && only(GET_OBJECT) => "s3.get",
        (false, "GET") if upload && only(LIST_PARTS) => "s3.put",
        (false, "PUT") if !upload && only(&["x-id"]) => "s3.put",
        (false, "PUT") if upload && has("partNumber") && only(&["partNumber", "uploadId", "x-id"]) => "s3.put",
        (false, "POST") if get("uploads") == Some("") && only(&["uploads", "x-id"]) => "s3.put",
        (false, "POST") if upload && only(&["uploadId", "x-id"]) => "s3.put",
        (false, "DELETE") if upload && only(&["uploadId", "x-id"]) => "s3.put",
        (false, "DELETE") if !upload && only(&["x-id"]) => "s3.delete",
        _ => return Err(unknown),
    };
    let key = if op == "s3.list" { get("prefix").unwrap_or("").to_string() } else { key };
    Ok(Route {
        op,
        bucket,
        key,
        region: ep.region,
        canonical_uri: uri_encode(decoded.as_bytes(), true),
        canonical_query: canonical_query(&pairs),
    })
}

/// Request headers that would change what an allowed operation does beyond
/// its object: copies from another key, ACLs and grants, tags, object locks,
/// website redirects.
const DENIED_HEADERS: &[&str] =
    &["x-amz-acl", "x-amz-bypass-governance-retention", "x-amz-tagging", "x-amz-website-redirect-location"];
const DENIED_PREFIXES: &[&str] = &["x-amz-copy-source", "x-amz-grant-", "x-amz-object-lock-"];

/// `x-amz-content-sha256` values the broker can re-sign: a payload hash S3
/// verifies against the body, or an unsigned payload (with or without a
/// trailing checksum). Signed-chunk uploads are refused.
pub fn payload_hash_ok(v: &[u8]) -> bool {
    (v.len() == 64 && v.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)))
        || v == b"UNSIGNED-PAYLOAD"
        || v == b"STREAMING-UNSIGNED-PAYLOAD-TRAILER"
}

/// Check the request headers of a mapped S3 request.
pub fn check_headers(headers: &HeaderMap) -> Result<(), Reason> {
    for name in headers.keys() {
        let n = name.as_str();
        if DENIED_HEADERS.contains(&n) || DENIED_PREFIXES.iter().any(|p| n.starts_with(p)) {
            return Err(Reason::S3RouteUnknown);
        }
    }
    let mut hashes = headers.get_all("x-amz-content-sha256").iter();
    match (hashes.next(), hashes.next()) {
        (None, _) => Ok(()),
        (Some(v), None) if payload_hash_ok(v.as_bytes()) => Ok(()),
        _ => Err(Reason::S3RouteUnknown),
    }
}

#[cfg(test)]
mod tests;
