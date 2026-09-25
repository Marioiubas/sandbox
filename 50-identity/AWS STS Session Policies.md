---
title: "AWS STS Session Policies"
aliases: ["AssumeRole", "STS"]
type: "standard"
section: "identity"
summary: "AssumeRole with an inline session policy (<=2,048 chars plus up to 10 ARNs) intersected with the role, 900 s-43,200 s lifetime (1 h when chaining), 50 tags and SourceIdentity in CloudTrail; the best native story, compiled by the broker."
tags: [sandbox/identity, standard, topic/credentials, topic/audit, platform/cloud, control/task-tok, control/cred-out, boundary/tb4, invariant/i1, milestone/m3]
status: built
confidence: high
milestone: M3
created: 2026-09-24
updated: 2026-09-25
code: ["code/crates/creds/src/issuers/aws_sts.rs", "code/crates/creds/src/issuers/sigv4.rs", "code/crates/policy/src/s3.rs", "code/crates/l7/src/s3.rs", "code/crates/brokerd/src/l7_pipeline/s3.rs"]
related: ["[[Just-in-Time Credential Minting]]", "[[Credential Injector and Issuers]]", "[[M3 CI Identity and MCP]]", "[[Policy Miner Safeguards]]", "[[Audit Recorder and Event Schema]]", "[[ADR-005 Mint Credentials Per Task]]", "[[Claude Code and sandbox-runtime]]", "[[Core Trait Contracts]]", "[[Tech Stack]]", "[[GCP Credential Access Boundaries]]"]
---

# AWS STS Session Policies

AWS STS `AssumeRole` returns temporary credentials whose effective permissions are the **intersection** of the role's policies and an inline session policy supplied at call time, for 900 seconds (15 minutes) up to 43,200 seconds, capped at one hour when chaining roles. The call can also stamp up to 50 session tags and a `SourceIdentity` that persists across chaining and is visible in CloudTrail. It is the best native downscoping story in the record: the broker compiles a Cedar grant into a session policy scoped to exact ARNs and prefixes, mints a 15-minute session per task, and re-signs requests with SigV4 at egress.

## Request parameters that matter

From the STS API reference ([AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)):

| Parameter | Constraint | Broker use |
|---|---|---|
| `DurationSeconds` | 900 s (15 min) to 43,200 s; capped at 1 h when chaining | **Proposal:** 900 s default for agent tasks |
| `Policy` (inline session policy) | combined with `PolicyArns`, a 2,048 plaintext-character limit | compiled from the Cedar grant |
| `PolicyArns` | up to 10 managed policy ARNs | org-provided reusable ceilings |
| `Tags` | up to 50 session tags | user, agent, task identifiers for ABAC conditions |
| `SourceIdentity` | ≤64 characters, persists across chaining, visible in CloudTrail | **Proposal:** the IdP subject or task ID |
| effective permissions | intersection of role policy and session policy | a session policy can only narrow |

`RoleArn` and `RoleSessionName` are also required by the API, and the response returns `Credentials` (`AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`); these are standard STS facts not extracted in the record, so confirm against the cited reference.

## Example: compile a task grant to a session policy

**Proposal** (research note 03 inference: "`s3:GetObject` on `arn:aws:s3:::bucket/tasks/123/*`"). Not tested.

Cedar-side intent: task `T-123` may read S3 objects under `tasks/123/` in bucket `acme-data`, nothing else. Compiled session policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::acme-data/tasks/123/*"] },
    { "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::acme-data"],
      "Condition": { "StringLike": { "s3:prefix": ["tasks/123/*"] } } }
  ]
}
```

AssumeRole call (parameter names from the API reference; values illustrative):

```text
RoleArn         = arn:aws:iam::<acct>:role/agent-broker-s3-read
RoleSessionName = task-T-123
DurationSeconds = 900
Policy          = <the JSON above, minified; must fit the 2,048-char budget>
SourceIdentity  = okta|00u1abc
Tags            = [ {Key: agent, Value: claude-code}, {Key: task, Value: T-123} ]
```

The role's own policy is the org ceiling (for example read-only on the data bucket); the session policy narrows it per task. Because the result is an intersection, a compiler bug can only produce *less* than the role allows, never more, which is a useful safety property for [[Policy Miner Safeguards]] ("derive the STS session policy from the operations actually observed").

## SigV4 re-signing at egress

- AWS SDKs sign each request with the credentials they hold. Inside the sandbox the SDK holds only sentinels, so the broker must **re-sign** the request with the minted session credentials after authorization.
- Claude Code's `mask` already re-signs AWS SigV4 (`credentials.awsPairs`, v2.1.224+) ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)); see [[Claude Code and sandbox-runtime]]. That is the precedent; the broker's difference is that the credentials are *minted per task* rather than a static key pair.
- **Proposal.** The `aws_sts` issuer's `attach()` strips the client's `Authorization`, `X-Amz-Security-Token` and `X-Amz-Date` headers, then computes a fresh SigV4 signature for the canonical request using the session credentials. Requests whose body hash cannot be computed (streamed payloads) need the SigV4 unsigned-payload or chunked modes; which to support is an implementation decision not covered by the record.

## Audit attribution

- `SourceIdentity` is visible in CloudTrail ([AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)), so the customer's own AWS audit shows which human's task made a call, joining the broker's hash-chained log to CloudTrail by task ID and session name ([[Audit Recorder and Event Schema]]).
- Research-note inference: tags or `SourceIdentity` carry the user, agent and task IDs into CloudTrail.

## Where the base credentials come from

- **Laptop:** the broker assumes the role from a base identity held outside the sandbox (keychain-held profile or an IdP-federated role; exact mechanism not specified in the record).
- **CI:** runner OIDC is exchanged by the broker; job secrets never enter the agent tree ([[M3 CI Identity and MCP]]).
- The CRED-OUT control means no AWS profile is reachable from the agent at all; the Amazon Q compromise is the motivating case ([AWS-2025-015](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)).

## Verdict for the broker

**Proposal.**

- **Use it for:** every AWS API call the agent makes; 15-minute sessions; session policies scoped to exact ARNs and prefixes; `SourceIdentity` for attribution.
- **Don't use it for:** policies larger than the 2,048-character budget (split tasks or use managed `PolicyArns` as reusable building blocks); anything that needs sub-15-minute lifetimes natively (enforce by broker-side expiry).
- **How we integrate it.** `issuers/aws_sts` in `crates/creds` implementing `CredentialIssuer { kind: "aws_sts" }` ([[Core Trait Contracts]]); STS client and SigV4 signer from the AWS Rust SDK or a focused SigV4 crate (choice unverified, [[Tech Stack]]); session cached per scope digest; the Cedar→IAM compiler lives in `crates/policy` and its output is size-checked before the call.

## How it connects

- implements:: [[Just-in-Time Credential Minting]]
- delivered-by:: [[Credential Injector and Issuers]] (`aws_sts` issuer)
- delivered-by:: [[M3 CI Identity and MCP]]
- depends-on:: [[Policy Miner Safeguards]] (session policy derived from observed operations)
- depends-on:: [[Audit Recorder and Event Schema]] (join with CloudTrail via SourceIdentity)
- decided-by:: [[ADR-005 Mint Credentials Per Task]]
- contrasts-with:: [[Claude Code and sandbox-runtime]] (static SigV4 pair re-signing)
- contrasts-with:: [[GCP Credential Access Boundaries]] (Cloud Storage only)

## Implications for the build

- M3 acceptance: S3 read works via minted credentials; writes outside the prefix are denied ([[M3 CI Identity and MCP]]). Test both the AWS-side denial (session policy) and the broker-side denial (Cedar) independently.
- Property-test the Cedar→IAM compiler: every emitted policy must be implied by the role policy ceiling and fit the size limit.
- CI uses a throwaway AWS account with a narrowly scoped role; its base credentials live in CI secrets or OIDC federation.

## Open questions

- ~~Required-parameter and response-shape details beyond the record must be confirmed from the API reference.~~ Resolved 2026-09-25 from the [STS API reference](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html): `RoleArn` (20-2048) and `RoleSessionName` (2-64, `[\w+=,.@-]*`) are required; `SourceIdentity` has the same pattern and may not begin with `aws:`; the response is XML with `Credentials` holding `AccessKeyId`, `SecretAccessKey`, `SessionToken` and an ISO 8601 `Expiration`; `DurationSeconds` defaults to 3600 when omitted (the broker always sends it).
- ~~The SigV4 streaming-payload strategy is undecided.~~ Decided in [[ADR-032 AWS STS and S3 Adapter as Built]]: keep a client payload hash (S3 verifies the body against it) or an unsigned payload; refuse signed-chunk uploads.

## Implementation notes

- The inline example above is what the compiler emits for `read = ["tasks/123/"]`, minified. Write prefixes add `s3:PutObject`, `s3:AbortMultipartUpload` and `s3:ListMultipartUploadParts`; delete prefixes add `s3:DeleteObject`; a `""` read prefix drops the `s3:prefix` condition so unprefixed listings match Cedar's decision ([[ADR-032 AWS STS and S3 Adapter as Built]]).
- The "2,048 plaintext characters" limit is checked when the policy compiles, so an oversized grant is a compile error rather than a runtime `AssumeRole` failure.
- For S3 the canonical request's payload hash is the `x-amz-content-sha256` value itself, including the literal `UNSIGNED-PAYLOAD` ([IAM User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html)).

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.

## Build log

- 2026-09-25: built for M3 ([[ADR-032 AWS STS and S3 Adapter as Built]]). `creds::issuers::aws_sts` (config, `AssumeRole` form body, strict XML parsing, SigV4-signed call with the base credentials, `sign_s3`), `creds::issuers::sigv4` (checked against four AWS SigV4 test-suite vectors and curl's `--aws-sigv4`), `policy::s3` (endpoint grammar, prefixes, session policy compiler with the 2,048-character check, reference check), `l7::s3` (operation map, canonical URI and query, header refusals). Tests: `policy::s3::tests::broker_and_aws_agree` (property: the reference decision and an IAM evaluation of the compiled session policy agree for every operation, bucket and key), `cedar::s3_tests::*`, `creds::issuers::aws_sts::tests::*`, `m3_s3::d6_*`; fuzz target `s3_route`. Tags and `PolicyArns` are not sent.
