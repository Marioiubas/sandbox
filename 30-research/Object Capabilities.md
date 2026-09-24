---
title: "Object Capabilities"
aliases: ["Ocap", "Confused Deputy", "POLA", "Membranes", "Principle of Least Authority"]
type: concept
section: research
tags: [sandbox/research, concept, topic/credentials, topic/policy, topic/mcp, invariant/i1, invariant/i7, control/cred-out, control/task-tok, evidence/unverified]
status: verified
confidence: medium
created: 2026-09-24
updated: 2026-09-24
summary: "Authority only through unforgeable, attenuable references (Miller: POLA, caretakers, membranes), the confused deputy (Hardy 1988, now a named MCP-proxy attack), and why CaMeL/FIDES 'capabilities' are IFC labels, leaving the credential broker as the missing ocap layer."
related: ["[[Macaroons and Biscuit]]", "[[Information Flow Control]]", "[[CaMeL]]", "[[FIDES]]", "[[MCP Authorization Spec]]", "[[Revocable Sub-Agent Delegation]]", "[[Just-in-Time Credential Minting]]", "[[Sentinel Swap Pattern]]", "[[I1 No Secrets in the Sandbox]]", "[[ADR-001 Value Lives in the Broker]]", "[[I7 Reject Foreign Credentials]]", "[[Claude Cowork Allowed-Domain Abuse]]", "[[Progent]]", "[[Design Patterns for Securing LLM Agents]]", "[[Credential Broker as Label Authority]]", "[[MCP Guard]]", "[[Internal Grant JWT]]", "[[Open Questions and Unverified Claims]]"]
sources: ["https://dl.acm.org/doi/10.1145/54289.871709", "http://www.erights.org/talks/thesis/", "https://jscholarship.library.jhu.edu/handle/1774.2/873", "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices", "https://arxiv.org/html/2503.18813", "https://arxiv.org/html/2505.23643", "https://arxiv.org/abs/2606.26479", "https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach", "https://www.anthropic.com/engineering/how-we-contain-claude"]
---

# Object Capabilities

In the object-capability (ocap) model, authority exists only as an unforgeable reference that a principal holds, and holders can pass on weaker (attenuated) references but never forge stronger ones. The LLM agent is the textbook confused deputy: it cannot tell whose authority it is exercising. The agent-security literature borrows the word "capability" but mostly means information-flow labels, so the ocap layer (who holds which real credential) is still missing. That missing layer is the credential broker.

## The ideas, precisely

### Designation bundled with authority

The confused-deputy problem comes from Hardy, "The Confused Deputy (or why capabilities might have been invented)", ACM SIGOPS Operating Systems Review vol. 22 no. 4, 1988 ([ACM DL](https://dl.acm.org/doi/10.1145/54289.871709)). A privileged program (the deputy) is handed a *name* by a less-privileged caller and uses its *own* authority on that name. The caller has effectively borrowed authority it never held. The capability fix is to make the name and the authority one object: if you can name a resource, it is because someone gave you a reference that also carries the right to use it.

Miller's thesis, "Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control" (Johns Hopkins, 2006; [erights.org](http://www.erights.org/talks/thesis/); [JHU repository](https://jscholarship.library.jhu.edu/handle/1774.2/873)), generalises this into the object-capability model:

- **Authority only via held references.** No ambient authority: no global namespace a process can reach into.
- **POLA (principle of least authority).** Give each component exactly the references its job needs.
- **Attenuation.** A holder can wrap a reference in a *forwarder* that passes on only some operations.
- **Caretakers.** A forwarder with an off switch: the grantor keeps a revoker, so the delegated reference can be cut later.
- **Membranes.** A caretaker applied transitively: every reference that flows out through the membrane is itself wrapped, so revoking the membrane revokes everything derived from it.

> [!question] Unverified
> The research record summarised Miller's thesis and Hardy's paper from background knowledge; neither text was re-read (listed in [[Open Questions and Unverified Claims]]). The definitions above are the standard ones, but cite the primary texts before quoting them in shipped docs.

### The confused deputy is now a named MCP attack

The MCP Security Best Practices document names "confused deputy" as a live attack on MCP proxy servers that combine a static OAuth client ID, dynamic client registration and consent cookies. The required mitigations are per-client consent, exact redirect-URI matching and single-use `state` ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)). The same document bans **token passthrough**: "MCP servers MUST NOT accept any tokens that were not explicitly issued for the MCP server", citing control circumvention, broken audit trails and use of the server as an exfiltration proxy. It also mandates progressive least-privilege scopes: minimal initial scope, incremental elevation through `WWW-Authenticate scope=` challenges, and no wildcard or omnibus scopes ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)).

The Cloud Security Alliance makes the same point for enterprise identity: static OAuth 2.1/SAML/OIDC scopes are insufficient for agents, and the confused-deputy problem grows when agents inherit broad permissions. It calls for just-in-time credentials "automatically expiring after task completion", a session authority for immediate revocation, and delegation chains from human to agent to sub-agent ([CSA](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)).

The Claude Cowork incident is the confused deputy in its purest agent form. A planted attacker API key was used against the allowlisted `api.anthropic.com`, and "the egress proxy checked the destination, saw api.anthropic.com, and let it through" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)). The proxy checked *where*, not *whose authority*. See [[Claude Cowork Allowed-Domain Abuse]].

### The terminology trap

CaMeL's "capabilities" are metadata tags carrying *readers* (who may see a value) and *provenance* (user literal, tool X, interpreter transformation) ([arXiv 2503.18813](https://arxiv.org/html/2503.18813)). FIDES uses a confidentiality × integrity label lattice ([arXiv 2505.23643](https://arxiv.org/html/2505.23643)). Both are [[Information Flow Control]], not ocap. Neither gives the executor unforgeable, attenuable references to external resources: both rely on whatever ambient credentials the tool layer holds ([arXiv 2503.18813](https://arxiv.org/html/2503.18813); [arXiv 2505.23643](https://arxiv.org/html/2505.23643)). A 2026 adaptive-evaluation paper frames CaMeL, FIDES, Progent and RTBAS as classic Biba integrity protection, reference monitoring and least privilege ([arXiv 2606.26479](https://arxiv.org/abs/2606.26479)), which is accurate: none of them is an ocap system.

So an implementer who reads "capability-based" in [[CaMeL]] or [[FIDES]] must not assume the credential question is solved. It is not addressed.

## The broker as the ocap layer

The research inference that shapes the whole product: treat the LLM as a confusable deputy **by construction**. It should never *hold* a credential, only *name* a capability that the broker resolves. That is the ocap answer both to token passthrough and to secrets in the context window (research note 02, Q1 inferences). The report ranks it as design principle 4: "Keep credentials out of the context window, so the model names capabilities and never holds them."

**Proposal.** Resolution inside the broker, per request:

```text
agent request  (host, method, path, body, sentinel)      # the model's "name"
  └─ canonicalise + classify   → AuthzRequest[]          # what is being asked
     └─ Cedar authorize(Task, action, resource, ctx)     # is this name within the grant?
        └─ CredentialIssuer.mint(grant)                  # the real authority, scoped + short-lived
           └─ attach at egress; strip/reject foreign creds (I7)
```

The sandbox holds only a per-session sentinel ([[Sentinel Swap Pattern]]), which designates the session's authority but is useless off-host. The real authority is minted just in time and never leaves broker memory ([[Just-in-Time Credential Minting]]). A credential the broker did not issue is rejected ([[I7 Reject Foreign Credentials]]), which is exactly the Cowork fix: the Cowork proxy accepts "only the VM's own provisioned session token" ([Anthropic](https://www.anthropic.com/engineering/how-we-contain-claude)).

## Adopt / Improve / Add

- **Adopt:** POLA as the default for every grant; "the model names, the broker holds" as the structural rule behind [[I1 No Secrets in the Sandbox]]; the MCP passthrough ban and progressive scopes as the external contract the broker satisfies by minting a fresh audience-bound token per upstream ([[MCP Authorization Spec]]).
- **Improve:** The literature's "capabilities" are labels without authority. **Proposal:** pair every label decision with an actual attenuated credential, so a policy decision and the authority it permits are the same object at egress.
- **Add:** **Proposal:** caretaker- and membrane-style revocation for sub-agents and map-reduce workers. No agent paper in the record evaluates capability revocation or sub-agent attenuation, although Miller's caretakers and membranes give the model ([erights.org](http://www.erights.org/talks/thesis/)). This is [[Revocable Sub-Agent Delegation]]; the token format for it is discussed in [[Macaroons and Biscuit]].

## How it connects

- mitigates:: [[Claude Cowork Allowed-Domain Abuse]]
- contrasts-with:: [[Information Flow Control]]
- contrasts-with:: [[CaMeL]]
- contrasts-with:: [[FIDES]]

[[Macaroons and Biscuit]] are the token-shaped form of the model. Notes that implement or extend this concept: [[ADR-001 Value Lives in the Broker]] (the decision to own the authority layer rather than an isolation primitive), [[Just-in-Time Credential Minting]], [[Sentinel Swap Pattern]], [[I1 No Secrets in the Sandbox]], [[I7 Reject Foreign Credentials]], [[Internal Grant JWT]] (the cross-host form of a held reference), [[MCP Guard]] (the agent can name a server but not choose its command), [[Revocable Sub-Agent Delegation]] and [[Credential Broker as Label Authority]]. [[Progent]] is the closest agent paper to POLA with monotonic attenuation; the [[Design Patterns for Securing LLM Agents]] Map-Reduce pattern is where attenuated sub-grants are most needed.

## Implications for the build

- No code path may place credential material in the sandbox's env, files, argv or response bodies; the sentinel is a designator, not a secret (I1 test: canary scan).
- The proxy must decide on *whose authority* as well as *which destination*: every request carrying a credential not minted by this broker is rejected (I7 test: attacker-planted key to an allowed host).
- Never forward a user's IdP token as-is to an upstream or MCP server; always exchange and narrow it (CLAUDE.md non-negotiable).
- Grants are data (Cedar entities) so they can be revoked without a policy recompile; design the entity model so a future caretaker can revoke a subtree of derived grants.

## Open questions

- Re-read Miller (2006) and Hardy (1988) before quoting them in shipped documentation.
- How should caretaker revocation propagate to already-minted upstream tokens whose TTL has not expired (GitHub installation tokens last 1 hour)? Not in the record.
- The MCP confused-deputy text cited is the 2025-06-18 best-practices page; confirm it is unchanged in the 2026-07-28 specification revision.

## Sources

- Hardy 1988, [ACM DL](https://dl.acm.org/doi/10.1145/54289.871709)
- Miller 2006, [erights.org](http://www.erights.org/talks/thesis/); [JHU repository](https://jscholarship.library.jhu.edu/handle/1774.2/873)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
- CaMeL, [arXiv 2503.18813](https://arxiv.org/html/2503.18813); FIDES, [arXiv 2505.23643](https://arxiv.org/html/2505.23643)
- Adaptive evaluation of out-of-band defenses, [arXiv 2606.26479](https://arxiv.org/abs/2606.26479)
- [CSA Agentic AI IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)
- [Anthropic, How we contain Claude](https://www.anthropic.com/engineering/how-we-contain-claude)
