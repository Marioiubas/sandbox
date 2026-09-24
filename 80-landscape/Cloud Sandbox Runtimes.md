---
title: "Cloud Sandbox Runtimes"
aliases: ["Cloudflare Sandbox", "E2B", "LangSmith Auth Proxy", "Runloop", "Daytona", "Modal", "Fly.io Sprites", "Kubernetes Agent Sandbox"]
type: product
section: landscape
tags: [sandbox/landscape, product, topic/market, topic/egress, topic/credentials, platform/cloud, platform/k8s, evidence/secondary]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Cloud runtimes and their egress/credential handling: Cloudflare Sandbox Outbound Workers, E2B (header transforms, 10-domain limit, blocked connections may look successful), LangSmith Auth Proxy (fail-closed callback credentials), Runloop (devbox-bound tokens), Daytona (went closed-source Jun 2026), Modal, Fly.io Sprites and Kubernetes Agent Sandbox."
related: ["[[TLS Termination and Per-Session CA]]", "[[Sentinel Swap Pattern]]", "[[DPoP and mTLS-Bound Tokens]]", "[[Architecture Overview]]", "[[Gap Analysis]]", "[[Firecracker]]", "[[gVisor]]", "[[ADR-014 Apache-2.0 Endpoint with Commercial ee]]", "[[Vercel Sandbox]]", "[[AWS AgentCore]]", "[[Topology-Forced Egress]]", "[[Internal Grant JWT]]", "[[Credential Injector and Issuers]]", "[[I1 No Secrets in the Sandbox]]", "[[Open Questions and Unverified Claims]]", "[[Product Thesis]]", "[[Conformance Probe Matrix]]", "[[I2 Fail-Closed Launch]]"]
sources: ["https://blog.cloudflare.com/sandbox-auth/", "https://developers.cloudflare.com/changelog/post/2026-04-13-sandbox-outbound-workers-tls-auth/", "https://docs.e2b.dev/network/internet-access.md", "https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes", "https://docs.runloop.ai/docs/devboxes/agent-gateways", "https://github.com/runloopai/api-client-ts/issues/839", "https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk", "https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/", "https://fly.io/learn/ai-sandbox-pricing/", "https://e2b.dev/pricing", "https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/", "https://github.com/kubernetes-sigs/agent-sandbox", "https://kubernetes.io/blog/2026/03/20/running-agents-on-kubernetes-with-agent-sandbox", "https://docs.cloud.google.com/kubernetes-engine/docs/how-to/agent-sandbox", "https://venturebeat.com/ai/how-e2b-became-essential-to-88-of-fortune-100-companies-and-raised-21-million/", "https://fly.io/sprites/"]
---

# Cloud Sandbox Runtimes

> Cloud runtimes and their egress/credential handling: Cloudflare Sandbox Outbound Workers, E2B (header transforms, 10-domain limit, blocked connections may look successful), LangSmith Auth Proxy (fail-closed callback credentials), Runloop (devbox-bound tokens), Daytona (went closed-source Jun 2026), Modal, Fly.io Sprites and Kubernetes Agent Sandbox.

## What they are

Hosted runtimes where agents execute in the vendor's cloud. They matter to the broker in three ways. They are evidence that proxy-side injection is commoditised. They offer patterns worth copying (fail-closed callbacks, sandbox-bound tokens, programmable egress). And they are future **deployment targets** for the broker's phase-2 remote-sandbox gateway mode ([[Architecture Overview]]). Vercel has its own note ([[Vercel Sandbox]]); AWS is in [[AWS AgentCore]].

Sandbox compute itself sells for cents per CPU-hour ([Fly.io](https://fly.io/sprites/)), which is why the scoreboard scores a pure "microVM sandbox" framing lower on payout than the broker wedge.

## Teardown table

| Vendor | Isolation | Egress and credential handling | Licence / BYOC | Price (per source date) |
|---|---|---|---|---|
| **Cloudflare Sandbox** | Containers on Workers | "Outbound Workers" as a programmable egress proxy on the same machine; per-sandbox ephemeral CA; secrets from Worker bindings; identity-aware via `ctx.containerId`; `outboundByHost` globs/CIDRs; `setOutboundHandler()` swaps handlers at runtime; local dev uses a `proxy-everything` nftables sidecar; in `@cloudflare/sandbox@0.8.9` (13 Apr 2026) ([Cloudflare](https://blog.cloudflare.com/sandbox-auth/); [changelog](https://developers.cloudflare.com/changelog/post/2026-04-13-sandbox-outbound-workers-tls-auth/)) | Closed | $0.072/vCPU-h active ([Fly.io](https://fly.io/learn/ai-sandbox-pricing/)) |
| **E2B** | Firecracker microVM ([MarkTechPost](https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/)) | `allowOut`/`denyOut` by IP, CIDR or domain; domain filtering only on :80 (Host) and :443 (SNI), no QUIC; per-host `transform.headers` injected from stored secrets or workload-identity tokens; **max 10 domains** per sandbox; "blocked connections may appear successful from inside the sandbox" ([E2B docs](https://docs.e2b.dev/network/internet-access.md)) | Apache-2.0 infra; BYOC via Terraform + Nomad + Consul | $0.0504/vCPU-h and $0.0162/GiB-h ([Fly.io](https://fly.io/learn/ai-sandbox-pricing/)); Pro $150/mo ([E2B pricing](https://e2b.dev/pricing)) |
| **LangSmith Sandboxes Auth Proxy** (21 May 2026) | Cloud sandboxes | Transparent interception, "not implemented by hoping every language… respects `HTTP_PROXY`"; per-host header rules of type `workspace_secret`, `plaintext` or `opaque` (write-only, encrypted); dynamic credentials from a customer **callback** called with target host and port, cached with a TTL; **fails closed** if the callback fails; network audit logs described as future ([LangChain](https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes)) | Closed | Not in the record |
| **Runloop** | microVM | "Agent Gateway": opaque, **devbox-bound** tokens with the real credential injected server-side; max 8 custom headers; config changes apply only to new or resumed devboxes ([Runloop docs](https://docs.runloop.ai/docs/devboxes/agent-gateways)); a token-invalidation bug on suspend/resume ([issue #839](https://github.com/runloopai/api-client-ts/issues/839)) | Closed, VPC deploy | $0.108/CPU-h ([MarkTechPost](https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/)) |
| **Daytona** | Containers, VM and Windows variants | `domainAllowList` (max 20), `networkAllowList` (10 IPv4 CIDRs) ([MarkTechPost](https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/)) | **Went closed-source in June 2026**; public repo frozen at v0.190.0 AGPL-3.0; stated reason: protecting isolation code from "AI-assisted exploit discovery" ([bex.co](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk)) | $0.0504/vCPU-h ([Fly.io](https://fly.io/learn/ai-sandbox-pricing/)) |
| **Modal** | gVisor containers | `outbound_domain_allowlist` in beta; no credential injection documented | Closed, no BYOC ([MarkTechPost](https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/)) | $0.1419/core-h ([Fly.io](https://fly.io/learn/ai-sandbox-pricing/)) |
| **Fly.io Sprites** | Firecracker microVM | Network policy not detailed in sources reviewed | Closed | $0.07/CPU-h used, bandwidth not metered, Hero plan $100/mo ([Fly.io](https://fly.io/learn/ai-sandbox-pricing/)) |
| **Kubernetes Agent Sandbox** | Kubernetes workloads | Manages "isolated, stateful, singleton workloads" for agent runtimes ([GitHub](https://github.com/kubernetes-sigs/agent-sandbox)); on the Kubernetes blog on 20 Mar 2026 ([Kubernetes blog](https://kubernetes.io/blog/2026/03/20/running-agents-on-kubernetes-with-agent-sandbox)); productised as GKE Agent Sandbox ([GKE docs](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/agent-sandbox)) | kubernetes-sigs project; licence not in the record | Not in the record |

E2B and Modal secrets were plain environment variables inside the sandbox; E2B's docs say they "are not private in the OS" ([Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)). E2B has since added egress header transforms, per the table.

On the market side, E2B raised $21M while reporting use at 88% of the Fortune 100 ([VentureBeat](https://venturebeat.com/ai/how-e2b-became-essential-to-88-of-fortune-100-companies-and-raised-21-million/)).

> [!question] Unverified
> Kubernetes Agent Sandbox CRD details (the research note names Sandbox, SandboxTemplate, SandboxClaim and WarmPool, but the blog fetch returned only metadata) and its network and credential handling are unconfirmed. Modal's and Daytona's credential-injection capabilities are "not detailed" in the sources. Several prices come from a single aggregator (Fly.io's pricing page) and are dated. See [[Open Questions and Unverified Claims]].

## Patterns worth copying

- **Per-sandbox ephemeral CA** (Cloudflare, like Vercel) → [[TLS Termination and Per-Session CA]].
- **Identity-aware egress handler** (`ctx.containerId`) → the broker keys every decision by session and task.
- **Fail-closed dynamic-credential callback** (LangSmith) → an issuer failure must deny the request, never pass it without a credential ([[Credential Injector and Issuers]], [[I2 Fail-Closed Launch]] spirit).
- **Sandbox-bound tokens** (Runloop's devbox-bound tokens, useless outside the issuing environment) → the broker's per-session sentinels and the DPoP-bound grant JWT ([[DPoP and mTLS-Bound Tokens]], [[Internal Grant JWT]]).
- **Transparent interception** (LangSmith, Cloudflare's nftables sidecar) → [[Topology-Forced Egress]].

## Anti-patterns to avoid

- **Env-var secrets** (E2B's and Modal's original model) → violates [[I1 No Secrets in the Sandbox]].
- **"Blocked connections may appear successful"** (E2B) → the broker must fail loudly with a reason the agent and user can see, or false "success" corrupts both the task and the audit trail.
- **QUIC defeats domain filtering** (E2B) → the broker blocks UDP/443 so clients fall back to TCP.
- **Small hard caps** (10 domains, 8 headers) → policy size must not be the limiting factor; Cedar's latency is independent of that scale.
- **Config changes only for new sessions** (Runloop) → the broker's grants are entities, so revocation takes effect on the next request.

## Strengths and weaknesses (as a group)

**Strengths:** strong isolation (Firecracker, gVisor), host-side injection, some transparent interception, and a fail-closed callback.

**Weaknesses versus this thesis:** each is cloud- or vendor-bound, uses its own config format, mostly swaps static secrets or env vars, scopes at host level, and offers little IdP binding or policy learning ([[Gap Analysis]]). Daytona's relicensing shows the licence risk of depending on a vendor's isolation code ([[ADR-014 Apache-2.0 Endpoint with Commercial ee]]).

## What we reuse or interoperate with

**Proposal (phase 2):** Remote-sandbox gateway mode makes the broker the upstream proxy for E2B, Vercel `forwardURL`, Docker sbx and Cloudflare outbound handlers, with vendor OIDC as the identity source ([[Architecture Overview]]). The Kubernetes deployment mode integrates with Agent Sandbox `SandboxTemplate` and a node or sidecar broker with pod netns rules.

## How we differentiate

One policy and audit stream across every runtime (laptop, CI, K8s and these clouds), minting bound to user, agent, repo and task, and deny-by-default L7 semantics ([[Gap Analysis]]).

## How it connects

- competes-with:: [[Product Thesis]] (in their clouds only)
- depends-on:: [[Firecracker]] (E2B, Fly.io Sprites)
- depends-on:: [[gVisor]] (Modal)
- example-of:: [[Sentinel Swap Pattern]]
- example-of:: [[TLS Termination and Per-Session CA]] (Cloudflare)
- example-of:: [[DPoP and mTLS-Bound Tokens]] (Runloop's bound-token idea)
- contrasts-with:: [[I1 No Secrets in the Sandbox]] (env-var secrets)
- Evidence for: [[ADR-014 Apache-2.0 Endpoint with Commercial ee]] (Daytona)
- Deployment targets in: [[Architecture Overview]] (gateway and Kubernetes modes)
- Siblings: [[Vercel Sandbox]], [[AWS AgentCore]]

## Implications for the build

- Add probes for "blocked looks successful": every deny must surface as a connection error or an HTTP 403 with a broker reason header, and be logged ([[Conformance Probe Matrix]]).
- Design the issuer trait so a callback-style issuer (LangSmith pattern) is possible: host and port in, credential and TTL out, deny on error.
- Keep gateway mode's identity mapping pluggable per vendor OIDC token.

## Open questions

- Which of these vendors will accept an external upstream proxy per sandbox? Only Vercel's `forwardURL` and Cloudflare's handlers are documented as programmable.
- What does GKE Agent Sandbox do for egress and credentials?

## Sources

- [Cloudflare blog: sandbox auth](https://blog.cloudflare.com/sandbox-auth/); [Cloudflare changelog](https://developers.cloudflare.com/changelog/post/2026-04-13-sandbox-outbound-workers-tls-auth/)
- [E2B docs: internet access](https://docs.e2b.dev/network/internet-access.md); [E2B pricing](https://e2b.dev/pricing)
- [LangChain: LangSmith Auth Proxy](https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes)
- [Runloop docs: agent gateways](https://docs.runloop.ai/docs/devboxes/agent-gateways); [Runloop issue #839](https://github.com/runloopai/api-client-ts/issues/839)
- [bex.co: Daytona closed source](https://bex.co/blog/2026/09/12/daytona-closed-source-agent-sandbox-oss-risk)
- [MarkTechPost, Aug 2026](https://www.marktechpost.com/2026/08/27/best-agent-sandboxes-2026-cold-start-pricing-network-policy/); [Fly.io: AI sandbox pricing](https://fly.io/learn/ai-sandbox-pricing/); [Fly.io Sprites](https://fly.io/sprites/)
- [Zujkowski](https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/)
- [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox); [Kubernetes blog](https://kubernetes.io/blog/2026/03/20/running-agents-on-kubernetes-with-agent-sandbox); [GKE Agent Sandbox](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/agent-sandbox)
- [VentureBeat: E2B](https://venturebeat.com/ai/how-e2b-became-essential-to-88-of-fortune-100-companies-and-raised-21-million/)
