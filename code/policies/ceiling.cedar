// Org deny ceiling (Policy Miner Safeguards, P3): no learned, recorded or
// edited policy exceeds it, in any mode. Categories are assigned to hosts by
// the entity builder from built-in lists (DoH resolvers, paste sites,
// tunnels); an org bundle may extend them.

@id("ceiling-doh")
@reason("doh_endpoint")
forbid (principal, action, resource in Broker::HostCategory::"doh");

@id("ceiling-paste")
@reason("ceiling_paste_site")
forbid (principal, action, resource in Broker::HostCategory::"paste");

@id("ceiling-tunnel")
@reason("ceiling_tunnel")
forbid (principal, action, resource in Broker::HostCategory::"tunnel");
