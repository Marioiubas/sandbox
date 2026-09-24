---
title: "AWS AgentCore"
aliases: ["AgentCore", "AgentCore Policy", "AgentCore Identity"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/policy, topic/identity, topic/credentials, platform/cloud, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "AgentCore Runtime (microVM per session), Identity (workload access token binding agent and user, token vault per user-agent pair) and Policy (Cedar at the Gateway, default-deny, NL-to-Cedar verified by analysis, partial evaluation); AWS-bound and without provenance context."
related: ["[[Cedar]]", "[[Policy Learning Loop]]", "[[Agent Identity Brokers]]", "[[Provenance-Aware Cedar]]", "[[SymCC CI Gates]]", "[[Gap Analysis]]", "[[Trifecta Session Labels]]", "[[AWS STS Session Policies]]", "[[Broker Cedar Schema]]", "[[Just-in-Time Credential Minting]]", "[[Open Questions and Unverified Claims]]", "[[Product Thesis]]", "[[Risk Register]]", "[[I3 Probabilistic Components Only Narrow]]", "[[MCP Guard]]", "[[Cloud Sandbox Runtimes]]"]
sources: ["https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-how-it-works.html", "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html", "https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/", "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html", "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html", "https://aurascape.ai/resources/auralabs-research/silent-leak-dns-tunneling-aws-agentcore-code-interpreter/", "https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html"]
---

# AWS AgentCore

> AgentCore Runtime (microVM per session), Identity (workload access token binding agent and user, token vault per user-agent pair) and Policy (Cedar at the Gateway, default-deny, NL-to-Cedar verified by analysis, partial evaluation); AWS-bound and without provenance context.

## What it is

Amazon Bedrock AgentCore is AWS's managed platform for running and governing agents. Three parts matter to the broker: **Runtime**, **Identity**, and **Gateway + Policy**. It is the most complete single-vendor stack in the landscape and the strongest precedent for Cedar in agent authorization. The scoreboard names "AWS AgentCore Policy" first among incumbents for the broker wedge. It is closed and AWS-bound. Pricing and quotas are not in the record.

## Architecture teardown

### Runtime: isolation

Each session runs in a "dedicated microVM with completely isolated CPU, memory, and filesystem resources". Sessions last up to 8 hours and end after 15 minutes idle ([AWS docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-how-it-works.html)). Outbound auth goes through AgentCore Identity, which "manages these credentials securely, preventing credential exposure in your agent code or logs".

A security vendor reported a DNS-tunnelling risk in the AgentCore Code Interpreter; only the title was seen, the article was not fetched ([Aurascape](https://aurascape.ai/resources/auralabs-research/silent-leak-dns-tunneling-aws-agentcore-code-interpreter/)).

### Identity: credentials

- A **workload access token** is an AWS-signed opaque token that binds agent identity and user identity. It is obtained with `GetWorkloadAccessTokenForJWT` (which validates the IdP JWT `iss` and `sub`) or `GetWorkloadAccessTokenForUserId` (an unverified opaque string).
- It is used to fetch OAuth tokens and API keys from the **token vault** (`GetResourceOauth2Token`, `GetResourceApiKey`), partitioned per user-agent pair.
- Runtime passes it in an invocation header.

Source: [AWS docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html). Credentials can be user-delegated or autonomous ([AWS docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-how-it-works.html)).

### Gateway and Policy: authorization

- Policy "sits between the agent and the remote tools it calls" via AgentCore Gateway. It is **default-deny**, with Cedar evaluated on every tool invocation.
- It uses **partial evaluation** to determine which tool actions would be denied, and hides them from the LLM.
- **Natural-language authoring** runs a "neuro-symbolic feedback loop": an LLM drafts Cedar, a schema generated from MCP tool descriptions validates it, and Cedar Analysis checks for logical errors.
- It became available as part of Gateway, per a blog dated 20 May 2026.

Source: [AWS Security Blog](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/).

Schema details from the docs: principals are `AgentCore::OAuthUser` (from the JWT `sub`, with claim tags) or `AgentCore::IamEntity` (the IAM ARN). Actions are gateway tools and the resource is the Gateway. The schema is auto-generated from tool definitions, with tool inputs in context. It enforces "default-deny and forbid-wins" ([AWS docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html)). Automated reasoning flags overly permissive, overly restrictive and unsatisfiable policies. The docs read describe no control over tool outputs or data flow ([AWS docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html)).

> [!question] Unverified
> AgentCore Policy quotas, whether it has an enforce-versus-log (shadow) mode, and its exact Cedar context schema were not found in the docs read ([[Open Questions and Unverified Claims]]).

## Comparison with the broker

| Dimension | AgentCore | This broker |
|---|---|---|
| Where it runs | AWS only | Laptop, CI, K8s, remote sandboxes |
| Enforcement point | Gateway, agent→tool calls | Network egress of the whole process tree, plus MCP tool calls ([[MCP Guard]]) |
| Principal | OAuth user or IAM entity | `Task` carrying user, agent, repo and expiry ([[Broker Cedar Schema]]) |
| Policy authoring | NL→Cedar, checked by analysis | TOML + learned diffs, checked by SymCC gates including narrowing against the previous policy ([[SymCC CI Gates]]) |
| Session / provenance context | Not described | Trifecta labels from systems of record ([[Trifecta Session Labels]]) |
| Credentials | Token vault per user-agent pair | Minting per task with narrowed scope ([[Just-in-Time Credential Minting]]) |

## Strengths

- A production precedent for Cedar at an agent→tool boundary, default-deny and forbid-wins.
- Partial evaluation to hide denied tools, a good UX idea.
- Identity binds user and agent into one token, with a vault partitioned per pair.
- LLM-drafted policy that must pass automated analysis, the same "probabilistic may only propose" stance as [[I3 Probabilistic Components Only Narrow]].

## Weaknesses (versus this thesis)

- **AWS-bound.** No laptop or non-AWS CI story.
- **No provenance context described.** It authorizes calls on inputs and identity, not on where argument values came from; the report's audit table marks "add provenance and trifecta context" as the improvement ([[Provenance-Aware Cedar]]).
- **Tool-call level only.** It does not see raw egress from a code interpreter or shell; the reported DNS-tunnelling risk is that class.
- **No trace-mined learning.** Authoring is natural language, not observed behaviour ([[Policy Learning Loop]]).

## What we reuse or interoperate with

- **Adopt:** Cedar as the decision core ([[Cedar]]); default-deny and forbid-wins; analysis before any generated policy ships.
- **Consider:** partial evaluation to tell an agent up front which verbs its task lacks.
- **Interoperate:** in AWS, the broker's STS minting with session policies narrows AWS credentials per task ([[AWS STS Session Policies]]); `SourceIdentity` puts the user or agent ID into CloudTrail ([AWS STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)).

## How we differentiate

Vendor-neutral, process-level egress (not only tool calls), provenance and trifecta context, narrowing proofs against the previous policy, and learning from traces ([[Gap Analysis]]). The scoreboard names AgentCore as the main incumbent threat to the wedge ([[Risk Register]]).

## How it connects

- depends-on:: [[Cedar]]
- competes-with:: [[Product Thesis]]
- contrasts-with:: [[Policy Learning Loop]] (NL authoring, not trace mining)
- contrasts-with:: [[SymCC CI Gates]] (analysis, but no narrowing-against-previous gate described)
- contrasts-with:: [[Trifecta Session Labels]] (no session or provenance context described)
- example-of:: [[Agent Identity Brokers]] (Identity's token vault)
- Gap it leaves, taken up in: [[Provenance-Aware Cedar]]
- Siblings: [[Cloud Sandbox Runtimes]]
- Analysed in: [[Gap Analysis]], [[Risk Register]]

## Implications for the build

- Keep the broker's Cedar schema compatible in spirit (principal/action/resource/context), so a customer can reason about both with one mental model.
- Implement `broker why` with the same determinism AgentCore's partial evaluation implies: a denied action should say which forbid or missing permit decided it.

## Open questions

- Does AgentCore Policy support a shadow or log-only mode? Not found.
- Could the broker consume AgentCore Identity's token vault as an upstream issuer for AWS-hosted customers?

## Sources

- [AWS docs: Runtime how it works](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-how-it-works.html)
- [AWS docs: workload access token](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html)
- [AWS Security Blog: why AgentCore Policy chose Cedar](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/)
- [AWS docs: policy core concepts](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html); [AWS docs: policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html)
- [Aurascape: DNS tunnelling in AgentCore Code Interpreter](https://aurascape.ai/resources/auralabs-research/silent-leak-dns-tunneling-aws-agentcore-code-interpreter/) (title only)
- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
