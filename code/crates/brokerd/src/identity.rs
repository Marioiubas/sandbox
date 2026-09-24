//! Session identity from an OIDC identity token (a CI runner's): verified
//! against the `[[identity.oidc]]` issuers of user or org policy with the
//! issuer's keys, fetched by the broker (discovery or `jwks_url`) or read
//! from `jwks_file`, and cached for an hour. The token decides who the
//! session is; it is never forwarded to an upstream, a server or the agent.

use crate::dirs::BrokerDirs;
use grant::oidc::{Identity, IssuerConfig, Jwks, OidcError};
use policy::PolicyFile;
use policy::config::OidcIssuerSpec;
use rustls_pki_types::CertificateDer;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(3600);
const MAX_DOC: usize = 256 << 10;

#[derive(Default)]
pub struct JwksCache {
    inner: Mutex<HashMap<String, (Jwks, Instant)>>,
}

impl JwksCache {
    fn get(&self, iss: &str) -> Option<Jwks> {
        let m = self.inner.lock().ok()?;
        m.get(iss).filter(|(_, at)| at.elapsed() < TTL).map(|(j, _)| j.clone())
    }

    fn put(&self, iss: &str, j: &Jwks) {
        if let Ok(mut m) = self.inner.lock() {
            m.insert(iss.to_string(), (j.clone(), Instant::now()));
        }
    }
}

async fn load(spec: &OidcIssuerSpec, dirs: &BrokerDirs, roots: &[CertificateDer<'static>]) -> Result<Jwks, String> {
    if let Some(f) = &spec.jwks_file {
        if f.contains('/') || f.starts_with('.') {
            return Err(format!("jwks_file {f:?} must be a file name in the broker config directory"));
        }
        let b = std::fs::read(dirs.config_dir.join(f)).map_err(|e| format!("jwks_file {f}: {e}"))?;
        return Jwks::parse(&b).map_err(|e| e.to_string());
    }
    let url = match &spec.jwks_url {
        Some(u) => u.clone(),
        None => {
            let d = crate::fetch::get(
                &format!("{}/.well-known/openid-configuration", spec.issuer.trim_end_matches('/')),
                roots,
                MAX_DOC,
            )
            .await?;
            let v: serde_json::Value = serde_json::from_slice(&d).map_err(|_| "the discovery document is not JSON")?;
            if v.get("issuer").and_then(|i| i.as_str()) != Some(spec.issuer.as_str()) {
                return Err("the discovery document names another issuer".into());
            }
            v.get("jwks_uri").and_then(|u| u.as_str()).ok_or("the discovery document has no jwks_uri")?.to_string()
        }
    };
    Jwks::parse(&crate::fetch::get(&url, roots, MAX_DOC).await?).map_err(|e| e.to_string())
}

/// Verify `token` for a session.
pub async fn verify(
    cache: &JwksCache,
    dirs: &BrokerDirs,
    user: &PolicyFile,
    roots: &[CertificateDer<'static>],
    token: &str,
) -> Result<Identity, String> {
    if user.identity.oidc.is_empty() {
        return Err("an identity token was given, but no [[identity.oidc]] issuer is configured".into());
    }
    let trusted: Vec<IssuerConfig> = user
        .identity
        .oidc
        .iter()
        .map(|o| IssuerConfig { issuer: o.issuer.clone(), audience: o.audience.clone() })
        .collect();
    let iss = grant::oidc::claimed_issuer(token).map_err(|e| e.to_string())?;
    let spec =
        user.identity.oidc.iter().find(|o| o.issuer == iss).ok_or_else(|| format!("issuer {iss:?} is not trusted"))?;
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let cached = cache.get(&iss);
    let jwks = match &cached {
        Some(j) => j.clone(),
        None => load(spec, dirs, roots).await?,
    };
    let r = match grant::oidc::verify(token, &trusted, &jwks, now) {
        // Keys rotate: one refetch when a cached set lacks the token's key.
        Err(OidcError::UnknownKey) if cached.is_some() => {
            let fresh = load(spec, dirs, roots).await?;
            cache.put(&iss, &fresh);
            grant::oidc::verify(token, &trusted, &fresh, now)
        }
        r => {
            if cached.is_none() {
                cache.put(&iss, &jwks);
            }
            r
        }
    };
    r.map_err(|e| e.to_string())
}
