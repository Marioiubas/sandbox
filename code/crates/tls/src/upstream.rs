//! Re-originated TLS toward upstreams: full verification against public
//! roots (Mozilla's set) plus roots the user configured; never downgraded.

use netguard::{CanonicalHost, HostKind};
use rustls::ClientConfig;
use rustls_pki_types::{CertificateDer, ServerName};
use std::sync::Arc;

pub fn client_config(extra_roots: &[CertificateDer<'static>]) -> anyhow::Result<Arc<ClientConfig>> {
    let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    for c in extra_roots {
        roots.add(c.clone())?;
    }
    let mut cfg = ClientConfig::builder_with_provider(crate::session_ca::provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// The name the upstream certificate must match: the canonical host.
pub fn server_name(host: &CanonicalHost) -> anyhow::Result<ServerName<'static>> {
    Ok(match host.kind() {
        HostKind::Name { .. } => ServerName::try_from(host.as_str().to_string())?,
        HostKind::V4(a) => ServerName::IpAddress(std::net::IpAddr::V4(*a).into()),
        HostKind::V6(a) => ServerName::IpAddress(std::net::IpAddr::V6(*a).into()),
    })
}
