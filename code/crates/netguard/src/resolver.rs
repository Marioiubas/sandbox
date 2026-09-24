//! Broker-owned name resolution.
//!
//! The sandbox never sends a DNS packet: CONNECT and SOCKS5 carry names, and
//! the broker resolves them here, *after* canonicalisation and host admission.
//! A name that policy does not admit is never queried upstream, because the
//! query name itself is the exfiltration channel (CVE-2025-55284).
//!
//! This module is the only place in the workspace allowed to call the system
//! resolver (see the I6 lint in `tests/lint`).

use crate::canon::{CanonicalHost, HostKind};
use audit::Reason;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[async_trait::async_trait]
pub trait PolicyResolver: Send + Sync {
    /// Resolve an already-admitted canonical name to A/AAAA addresses.
    /// IP-literal hosts resolve to themselves without any query.
    async fn resolve(&self, host: &CanonicalHost) -> Result<Vec<IpAddr>, Reason>;
}

/// The host's resolver via `getaddrinfo`, queried with an absolute name
/// (trailing dot appended after canonicalisation) so no search domain is ever
/// appended, with a timeout and a per-resolver cache clamped to `max_ttl`.
pub struct SystemResolver {
    timeout: Duration,
    max_ttl: Duration,
    cache: Mutex<HashMap<String, (Instant, Vec<IpAddr>)>>,
}

impl SystemResolver {
    pub fn new() -> Self {
        SystemResolver {
            timeout: Duration::from_secs(5),
            max_ttl: Duration::from_secs(60),
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for SystemResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl PolicyResolver for SystemResolver {
    async fn resolve(&self, host: &CanonicalHost) -> Result<Vec<IpAddr>, Reason> {
        if let Some(ip) = host.ip() {
            return Ok(vec![ip]);
        }
        let HostKind::Name { .. } = host.kind() else { return Err(Reason::ResolveFailed) };
        if let Ok(cache) = self.cache.lock()
            && let Some((at, addrs)) = cache.get(host.as_str())
            && at.elapsed() < self.max_ttl
        {
            return Ok(addrs.clone());
        }
        let fqdn = format!("{}.", host.as_str());
        let lookup = tokio::net::lookup_host((fqdn.as_str(), 0u16));
        let addrs: Vec<IpAddr> = match tokio::time::timeout(self.timeout, lookup).await {
            Ok(Ok(it)) => {
                let mut v: Vec<IpAddr> = it.map(|sa| sa.ip()).collect();
                v.sort_by_key(|a| (a.is_ipv6(), *a));
                v.dedup();
                v
            }
            _ => return Err(Reason::ResolveFailed),
        };
        if addrs.is_empty() {
            return Err(Reason::NoAddresses);
        }
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(host.as_str().to_string(), (Instant::now(), addrs.clone()));
        }
        Ok(addrs)
    }
}

/// A fixed name→address table that counts every query it receives. Tests
/// use it as the "authoritative server that logs every query": after a probe
/// run it must have seen zero queries for non-allowlisted names.
#[derive(Default)]
pub struct StaticResolver {
    table: HashMap<String, Vec<IpAddr>>,
    queries: Mutex<Vec<String>>,
    count: AtomicU64,
}

impl StaticResolver {
    pub fn new(entries: impl IntoIterator<Item = (String, Vec<IpAddr>)>) -> Self {
        StaticResolver { table: entries.into_iter().collect(), ..Default::default() }
    }

    pub fn queries(&self) -> Vec<String> {
        self.queries.lock().map(|q| q.clone()).unwrap_or_default()
    }

    pub fn query_count(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl PolicyResolver for StaticResolver {
    async fn resolve(&self, host: &CanonicalHost) -> Result<Vec<IpAddr>, Reason> {
        if let Some(ip) = host.ip() {
            return Ok(vec![ip]);
        }
        self.count.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut q) = self.queries.lock() {
            q.push(host.as_str().to_string());
        }
        match self.table.get(host.as_str()) {
            Some(v) if !v.is_empty() => Ok(v.clone()),
            Some(_) => Err(Reason::NoAddresses),
            None => Err(Reason::ResolveFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::canon_host;

    #[tokio::test]
    async fn static_resolver_counts_and_literals_skip_queries() {
        let r = StaticResolver::new([("a.test".to_string(), vec!["192.0.2.1".parse().unwrap()])]);
        assert!(r.resolve(&canon_host(b"a.test").unwrap()).await.is_ok());
        assert_eq!(r.resolve(&canon_host(b"b.test").unwrap()).await, Err(Reason::ResolveFailed));
        assert_eq!(
            r.resolve(&canon_host(b"1.2.3.4").unwrap()).await.unwrap(),
            vec!["1.2.3.4".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(r.query_count(), 2);
        assert_eq!(r.queries(), vec!["a.test", "b.test"]);
    }
}
