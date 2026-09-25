//! S3 requests in the L7 pipeline: headers the adapter refuses, the
//! canonical target that is forwarded, and SigV4 re-signing with the
//! minted session (AWS STS Session Policies). The client's own signature,
//! made with a sentinel, is stripped with every other client credential.

use creds::Issued;
use http::HeaderMap;
use l7::classify::Plan;
use policy::AttachSpec;
use std::time::SystemTime;

/// The adapter's header check for mapped S3 requests (others pass).
pub(super) fn check_headers(plan: &Plan, headers: &HeaderMap) -> Result<(), audit::Reason> {
    match plan {
        Plan::S3(_, Ok(_)) => l7::s3::check_headers(headers),
        _ => Ok(()),
    }
}

/// The forwarded request target: for S3 exactly the canonical URI and
/// query that are signed; otherwise the canonical path and stripped query.
pub(super) fn target(plan: &Plan, path: &str, query: Option<&str>) -> String {
    match (plan, query) {
        (Plan::S3(_, Ok(r)), _) if r.canonical_query.is_empty() => r.canonical_uri.clone(),
        (Plan::S3(_, Ok(r)), _) => format!("{}?{}", r.canonical_uri, r.canonical_query),
        (_, Some(q)) => format!("{path}?{q}"),
        (_, None) => path.to_string(),
    }
}

/// Attach the bound credential: a header, or for `aws_sts` a signature
/// over the request as it will be forwarded.
pub(super) fn attach(
    plan: &Plan,
    issued: &Issued,
    spec: &AttachSpec,
    method: &str,
    headers: &mut HeaderMap,
) -> anyhow::Result<()> {
    match (spec, plan) {
        (AttachSpec::SigV4, Plan::S3(_, Ok(r))) => creds::issuers::aws_sts::sign_s3(
            issued,
            &r.region,
            method,
            &r.canonical_uri,
            &r.canonical_query,
            headers,
            SystemTime::now(),
        ),
        (AttachSpec::SigV4, _) => anyhow::bail!("a SigV4 credential on a request that is not a mapped S3 request"),
        _ => creds::attach(issued, spec, headers),
    }
}
