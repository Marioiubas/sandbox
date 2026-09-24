//! Per-session CA and leaf certificates for the L7 path.
//!
//! The CA is created just in time at session start, its private key lives
//! only in brokerd memory, and it is dropped at session end, so a leaked CA
//! certificate is useless after the session. It is never installed into a
//! host trust store: only the session's own trust bundle names it.

use netguard::{CanonicalHost, HostKind};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Leaf certificates live no longer than this (sessions renew by restarting).
const LEAF_LIFETIME: Duration = Duration::from_secs(24 * 3600);
const CA_LIFETIME: Duration = Duration::from_secs(48 * 3600);

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub struct SessionCa {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for SessionCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionCa(<key redacted>)")
    }
}

fn window(lifetime: Duration) -> (time::OffsetDateTime, time::OffsetDateTime) {
    let now = SystemTime::now();
    let nb = now.checked_sub(Duration::from_secs(3600)).unwrap_or(now);
    (time::OffsetDateTime::from(nb), time::OffsetDateTime::from(now + lifetime))
}

impl SessionCa {
    /// Create a CA for one session. `label` goes into the subject so the
    /// certificate is recognisable (for example the session ID).
    pub fn new(label: &str) -> anyhow::Result<Self> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("broker session CA {label}"));
        dn.push(DnType::OrganizationName, "broker (per-session, not trusted outside the sandbox)");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages =
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        (params.not_before, params.not_after) = window(CA_LIFETIME);
        let cert = params.self_signed(&key)?;
        let ca_der = cert.der().clone();
        let ca_pem = cert.pem();
        Ok(SessionCa {
            issuer: Issuer::new(params, key),
            ca_der,
            ca_pem,
            leaves: Mutex::new(HashMap::new()),
            provider: provider(),
        })
    }

    /// The CA certificate (PEM) for the sandbox's trust bundle. Never the key.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn ca_der(&self) -> &CertificateDer<'static> {
        &self.ca_der
    }

    /// A rustls server config presenting a leaf for exactly `host`, cached
    /// for the session. ALPN offers only HTTP/1.1 (h2 is not parsed yet).
    pub fn server_config(&self, host: &CanonicalHost) -> anyhow::Result<Arc<ServerConfig>> {
        if let Some(c) = self.leaves.lock().map_err(|_| anyhow::anyhow!("leaf cache poisoned"))?.get(host.as_str()) {
            return Ok(c.clone());
        }
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host.as_str().trim_start_matches('[').trim_end_matches(']'));
        params.distinguished_name = dn;
        params.subject_alt_names = vec![match host.kind() {
            HostKind::Name { .. } => SanType::DnsName(host.as_str().try_into()?),
            HostKind::V4(a) => SanType::IpAddress((*a).into()),
            HostKind::V6(a) => SanType::IpAddress((*a).into()),
        }];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        (params.not_before, params.not_after) = window(LEAF_LIFETIME);
        let leaf = params.signed_by(&key, &self.issuer)?;
        let chain = vec![leaf.der().clone(), self.ca_der.clone()];
        let pk = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut cfg = ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .with_no_client_auth()
            .with_single_cert(chain, pk)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.leaves
            .lock()
            .map_err(|_| anyhow::anyhow!("leaf cache poisoned"))?
            .insert(host.as_str().to_string(), cfg.clone());
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn client_trusting(ca: &SessionCa) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_der().clone()).unwrap();
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    async fn handshake(ca: &SessionCa, presented: &str, expected_by_client: &str) -> bool {
        let host = netguard::canon_host(presented.as_bytes()).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(ca.server_config(&host).unwrap());
        let connector = tokio_rustls::TlsConnector::from(client_trusting(ca));
        let (a, b) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            if let Ok(mut s) = acceptor.accept(a).await {
                let mut buf = [0u8; 4];
                let _ = s.read_exact(&mut buf).await;
                let _ = s.write_all(b"pong").await;
            }
        });
        let name = ServerName::try_from(expected_by_client.to_string()).unwrap();
        let ok = match connector.connect(name, b).await {
            Ok(mut c) => {
                c.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                c.read_exact(&mut buf).await.is_ok() && &buf == b"pong"
            }
            Err(_) => false,
        };
        server.abort();
        ok
    }

    #[tokio::test]
    async fn leaf_verifies_only_for_its_host() {
        let ca = SessionCa::new("test").unwrap();
        assert!(handshake(&ca, "api.github.com", "api.github.com").await);
        assert!(!handshake(&ca, "api.github.com", "evil.example").await);
        assert!(handshake(&ca, "127.0.0.1", "127.0.0.1").await);
        assert!(ca.ca_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(!format!("{ca:?}").contains("PRIVATE"));
    }

    #[tokio::test]
    async fn another_sessions_ca_is_not_trusted() {
        let a = SessionCa::new("a").unwrap();
        let b = SessionCa::new("b").unwrap();
        let host = netguard::canon_host(b"api.github.com").unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(a.server_config(&host).unwrap());
        let connector = tokio_rustls::TlsConnector::from(client_trusting(&b));
        let (x, y) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = acceptor.accept(x).await;
        });
        let r = connector.connect(ServerName::try_from("api.github.com").unwrap(), y).await;
        assert!(r.is_err());
    }
}
