---
title: "ADR-032 AWS STS and S3 Adapter as Built"
aliases: ["ADR-032"]
type: decision
section: decisions
tags: [sandbox/decisions, decision, topic/credentials, platform/cloud, invariant/i1, invariant/i3, invariant/i6, invariant/i7, milestone/m3]
status: built
confidence: medium
created: 2026-09-25
updated: 2026-09-25
summary: "S3 grants (`protocol = \"s3\"`, bucket plus read/write/delete key prefixes) map every request to s3.get, s3.list, s3.put or s3.delete or deny it; an `aws_sts` credential mints an AssumeRole session narrowed by an inline session policy compiled from the same prefixes (≤2,048 characters, checked at compile time), and the broker strips the agent's SigV4 signature (made with a sentinel access key ID) and re-signs with the session. Only S3 is brokered; signed-chunk uploads, versioned access, session tags and web-identity base credentials are not built."
related: ["[[AWS STS Session Policies]]", "[[Credential Injector and Issuers]]", "[[M3 CI Identity and MCP]]", "[[Just-in-Time Credential Minting]]", "[[I1 No Secrets in the Sandbox]]", "[[I7 Reject Foreign Credentials]]", "[[I6 Single Canonicaliser]]", "[[SymCC CI Gates]]", "[[Broker Cedar Schema]]", "[[Trifecta Session Labels]]", "[[ADR-005 Mint Credentials Per Task]]", "[[MOC Decisions]]"]
sources: ["https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html", "https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html", "https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4"]
superseded_by: 
---

# ADR-032 AWS STS and S3 Adapter as Built

> An agent reaches S3 with a sentinel; the broker decides per bucket and key prefix, and AWS enforces the same prefixes on the 15-minute session the broker minted.

## Status

built (2026-09-25, M3 step 4).

## Context

[[M3 CI Identity and MCP]] asks for `AssumeRole` with an inline session policy compiled from the grant, `DurationSeconds` 900 s by default, `SourceIdentity`, and SigV4 re-signing at egress (D6: "S3 read works via minted credentials; writes outside the prefix are denied"). [[AWS STS Session Policies]] left two things open: the request and response details beyond the record, and the streaming-payload strategy. Both were settled from primary sources on 2026-09-25: the STS API reference (parameters, their patterns and limits, the XML response) and the IAM User Guide's signing procedure, with the official SigV4 test suite (awslabs/aws-c-auth) as test vectors.

## Decision

1. **S3 grants.** `protocol = "s3"` with `s3 = { bucket, read, write, delete }` on an exact S3 endpoint host (virtual-hosted `<bucket>.s3.<region>.amazonaws.com` or path-style `s3.<region>.amazonaws.com`, also `s3-<region>` and `dualstack` forms). Prefixes are literal printable ASCII without a leading `/`, `*`, `?`, `$`, quotes or backslashes (wildcards or variables in Cedar `like` or IAM); `""` is the whole bucket; empty lists grant nothing. Compile errors, not runtime surprises, for anything else.
2. **Adapter** (`l7::s3`). Each request is `s3.get` (GetObject/HeadObject with response overrides), `s3.list` (ListObjects/ListObjectsV2 on the requested `prefix`), `s3.put` (PutObject, UploadPart, Create/Complete/Abort multipart, ListParts) or `s3.delete` (DeleteObject) on one bucket and key, or it is denied (`s3_route_unknown`): bucket and object subresources, `versionId`, batch `?delete`, presigned query authentication, repeated parameters, CopyObject (`x-amz-copy-source*`), `x-amz-acl`, `x-amz-grant-*`, `x-amz-tagging`, object-lock and website-redirect headers, and signed-chunk uploads. The action rides beside the request's Http action, as GitHub verbs do (so the Rule of Two's `http.write` forbid covers S3 writes).
3. **Cedar.** Schema actions `s3.get`, `s3.list`, `s3.put`, `s3.delete` on `Host` with `S3Ctx { bucket, key }`; a grant compiles to `context.bucket == B && context.key like "p*"` per prefix class. Reads raise `sensitive_read`; writes and deletes `external_effect`.
4. **Issuer** (`creds::issuers::aws_sts`, user or org `[issuers.aws_sts.<name>]`): `role_arn`, `region`, base credentials as secret references, optional `session_token`, `sts_endpoint`/`sts_addrs`, `duration` (15m default, 15m-12h) and `source_identity` (default on). The broker signs `AssumeRole` itself (service `sts`) with `RoleSessionName = broker-<session>`, `SourceIdentity` = the session's end user reduced to `[\w+=,.@-]`, and `Policy` = the grant's session policy (GetObject and conditional ListBucket for read prefixes, PutObject plus the multipart actions for write prefixes, DeleteObject for delete prefixes), compiled and size-checked (2,048 characters) when the policy compiles. The XML response is parsed strictly (one `Credentials`, one of each element, no markup or entities; errors name only the STS error code). The session is cached per scope digest for the run and zeroized with it.
5. **Sandbox side.** The credential's sentinel is `AWS_ACCESS_KEY_ID` (by default) and `AWS_SECRET_ACCESS_KEY` holds a fixed, non-secret placeholder, so SDKs and `curl --aws-sigv4` sign as usual. `creds::inspect` reads the access key ID from `Authorization: AWS4-HMAC-SHA256 Credential=…`; only this session's sentinel for this host is accepted (I7).
6. **Re-signing** (`creds::issuers::sigv4`, `aws_sts::sign_s3`). After authorization, every client credential is stripped and the broker forwards exactly the adapter's canonical URI (UriEncode, `/` kept) and canonical query (encoded, sorted), and signs `host`, `content-type`, `content-md5` and all `x-amz-*` headers with a fresh `x-amz-date` and the session token. **Payload:** a client `x-amz-content-sha256` that is a hex hash is kept and signed (S3 checks the body against it, so the body cannot be swapped); `UNSIGNED-PAYLOAD` and `STREAMING-UNSIGNED-PAYLOAD-TRAILER` are kept; absent means `UNSIGNED-PAYLOAD` (valid for S3 over TLS); signed-chunk modes are refused, because each chunk signature chains from the client's seed signature and cannot survive re-signing. The response filter cuts any response carrying the session's secret key or token (S3 error bodies can echo the canonical request).

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| Rely on the session policy alone (no Cedar check) | One layer; the broker could not explain or log denies, and a policy compiler bug would go unnoticed. Both layers, tested to agree. |
| Rely on Cedar alone (no session policy) | The minted credentials would carry the whole role; the proposal's point is that AWS enforces the narrowing too. |
| Buffer bodies to hash them | Large uploads would hit the inspection limit; S3 already verifies a client-sent hash. |
| Re-sign signed-chunk uploads chunk by chunk | Doable, but it means parsing and rewriting aws-chunked bodies in the proxy; SDKs over HTTPS default to unsigned payloads with trailing checksums. Deferred. |
| Allow `versionId` (GetObjectVersion) | Needs extra IAM actions in the session policy; denied until needed. |
| Session tags | Needs `sts:TagSession` in the role's trust policy; `RoleSessionName` and `SourceIdentity` already join CloudTrail to the audit log. Deferred. |

## Consequences

- D6 passes against a fake STS and a fake S3 that verify every signature and evaluate the session policy (`m3_s3`); the same three checks run against real AWS once a test account exists.
- The signer matches the AWS SigV4 test suite (four vectors) and curl's independent `--aws-sigv4` implementation.
- **Not built:** AWS services other than S3; web-identity base credentials (runner OIDC → `AssumeRoleWithWebIdentity`); signed-chunk uploads; versioned access; session tags and `PolicyArns`; learner proposals for S3 grants (the learner does not choose credentials or prefixes).
- The role's trust policy must allow `sts:SetSourceIdentity` unless `source_identity = false`.

## Invariants affected

Upholds I1 (no base or session secret in the sandbox; only a sentinel and a placeholder), I3 (the probabilistic learner cannot add S3 authority), I6 (bucket, key and query come from the canonical path; the forwarded target is regenerated, not passed through) and I7 (foreign access key IDs rejected). Weakens none.

## Relationships

- decided-by:: M3 build
- implements:: [[AWS STS Session Policies]]
- refines:: [[ADR-005 Mint Credentials Per Task]]
