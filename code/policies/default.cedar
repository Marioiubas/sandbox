// Default policy set shipped with every broker (Example Cedar Policies).
// Four forbids are the hard floor; permits come from the compiled
// broker.toml grants. Every policy has an @id (named by `broker why`).

@id("credential-host-ceiling")
@reason("credential_host_ceiling")
forbid (principal, action == Broker::Action::"credential.use", resource)
unless { resource.allowed_hosts.contains(context.dest_host)
         || resource.allowed_domains.containsAny(context.dest_domains) };

@id("task-expiry")
@reason("task_expired")
forbid (principal, action, resource)
when { context.session.now >= principal.expires_at };

@id("rule-of-two")
@reason("rule_of_two")
forbid (principal, action in [Broker::Action::"http.write", Broker::Action::"git.push"], resource)
when {
  !(context has adapted && context.adapted) &&
  !(context has model_api && context.model_api) &&
  context.session.trifecta.untrusted_input && context.session.trifecta.sensitive_read
}
unless { context.session.approved };

// On GitHub and S3 hosts the verb decides (a GraphQL query is a POST that
// writes nothing); every write those adapters map is one of these.
@id("rule-of-two-verbs")
@reason("rule_of_two")
forbid (
  principal,
  action in [
    Broker::Action::"pr.create", Broker::Action::"pr.merge", Broker::Action::"issue.comment",
    Broker::Action::"contents.write", Broker::Action::"gist.create",
    Broker::Action::"s3.put", Broker::Action::"s3.delete"
  ],
  resource
)
when { context.session.trifecta.untrusted_input && context.session.trifecta.sensitive_read }
unless { context.session.approved };

@id("rule-of-two-mcp")
@reason("rule_of_two")
forbid (principal, action == Broker::Action::"mcp.call_tool", resource)
when { context.write && context.session.trifecta.untrusted_input && context.session.trifecta.sensitive_read }
unless { context.session.approved };

@id("pinned-mcp-only")
@reason("mcp_unpinned")
forbid (principal, action == Broker::Action::"mcp.call_tool", resource)
unless { resource.pinned };

@id("publish-needs-approval")
@reason("needs_approval")
forbid (principal, action == Broker::Action::"pkg.publish", resource)
unless { context.session.approved };

@id("merge-needs-approval")
@reason("needs_approval")
forbid (principal, action == Broker::Action::"pr.merge", resource)
unless { context.session.approved };
