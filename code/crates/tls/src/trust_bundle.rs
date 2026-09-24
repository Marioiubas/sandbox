//! The sandbox's trust bundle: the per-session CA plus public roots (and
//! any roots the user configured), written per session and pointed to by the
//! usual environment variables. The host trust store is never touched.

use rustls_pki_types::CertificateDer;
use std::fmt::Write;
use std::path::{Path, PathBuf};

pub fn der_to_pem(der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

/// Mozilla's root set (webpki-root-certs) as PEM.
pub fn public_roots_pem() -> String {
    let mut s = String::new();
    for c in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        s.push_str(&der_to_pem(c.as_ref()));
    }
    s
}

/// Parse every certificate in a PEM file (for user-configured extra roots).
pub fn load_pem_certs(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    use rustls_pki_types::pem::PemObject;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("{}: no certificates", path.display());
    }
    Ok(certs)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustBundle {
    /// The session CA alone (for additive settings such as NODE_EXTRA_CA_CERTS).
    pub ca_file: PathBuf,
    /// Session CA + extra roots + public roots (for replacing settings).
    pub bundle_file: PathBuf,
}

pub fn write(dir: &Path, ca_pem: &str, extra: &[CertificateDer<'static>]) -> anyhow::Result<TrustBundle> {
    std::fs::create_dir_all(dir)?;
    let ca_file = dir.join("broker-session-ca.pem");
    let bundle_file = dir.join("broker-trust-bundle.pem");
    std::fs::write(&ca_file, ca_pem)?;
    let mut bundle = String::new();
    bundle.push_str(ca_pem);
    for c in extra {
        bundle.push_str(&der_to_pem(c.as_ref()));
    }
    bundle.push_str(&public_roots_pem());
    std::fs::write(&bundle_file, bundle)?;
    Ok(TrustBundle { ca_file, bundle_file })
}

/// Environment variables that make common clients trust the bundle.
pub fn env_vars(tb: &TrustBundle) -> Vec<(String, String)> {
    let b = tb.bundle_file.display().to_string();
    let ca = tb.ca_file.display().to_string();
    let mut v = Vec::new();
    for k in [
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "PIP_CERT",
        "NPM_CONFIG_CAFILE",
        "npm_config_cafile",
        "AWS_CA_BUNDLE",
        "CARGO_HTTP_CAINFO",
        "DENO_CERT",
    ] {
        v.push((k.to_string(), b.clone()));
    }
    v.push(("NODE_EXTRA_CA_CERTS".into(), ca));
    v
}

/// A human-readable one-liner for audit rows.
pub fn describe(tb: &TrustBundle) -> String {
    let mut s = String::new();
    let _ =
        write!(s, "{} (+{} public roots)", tb.bundle_file.display(), webpki_root_certs::TLS_SERVER_ROOT_CERTS.len());
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_round_trip_and_bundle() {
        let ca = crate::session_ca::SessionCa::new("t").unwrap();
        let d = tempfile::tempdir().unwrap();
        let tb = write(d.path(), ca.ca_pem(), &[]).unwrap();
        let certs = load_pem_certs(&tb.bundle_file).unwrap();
        assert!(certs.len() > 100, "public roots present: {}", certs.len());
        assert_eq!(certs[0].as_ref(), ca.ca_der().as_ref(), "session CA first");
        assert_eq!(load_pem_certs(&tb.ca_file).unwrap().len(), 1);
        let env = env_vars(&tb);
        assert!(env.iter().any(|(k, v)| k == "SSL_CERT_FILE" && v.ends_with("broker-trust-bundle.pem")));
        assert!(env.iter().any(|(k, v)| k == "NODE_EXTRA_CA_CERTS" && v.ends_with("broker-session-ca.pem")));
        let text = std::fs::read_to_string(&tb.bundle_file).unwrap();
        assert!(!text.contains("PRIVATE KEY"), "never the key");
    }
}
