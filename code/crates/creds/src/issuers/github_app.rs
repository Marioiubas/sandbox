//! GitHub App installation tokens (GitHub App Installation Tokens note).
//!
//! The request always names `repositories` and `permissions`: omitting
//! either gives the token the whole installation. The response is checked
//! against the request, and a token with any scope beyond it is discarded
//! (fail closed). Tokens last at most an hour upstream.

use super::{ApiEndpoint, Transport};
use crate::Secret;
use base64::Engine;
use policy::config::GitHubAppIssuerSpec;
use policy::{RepoId, SecretRef};
use ring::signature::RsaKeyPair;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct GitHubApp {
    pub name: String,
    pub app_id: String,
    pub installation_id: String,
    pub key_ref: SecretRef,
    pub api: ApiEndpoint,
}

impl std::fmt::Debug for GitHubApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubApp")
            .field("name", &self.name)
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .field("key_ref", &self.key_ref.describe())
            .field("api", &self.api.authority())
            .finish()
    }
}

impl GitHubApp {
    pub fn from_spec(name: &str, s: &GitHubAppIssuerSpec) -> Result<GitHubApp, String> {
        let ctx = |m: String| format!("[issuers.github_app.{name}]: {m}");
        if s.app_id.is_empty() || !s.app_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.') {
            return Err(ctx("app_id must be the numeric app ID or the client ID".into()));
        }
        if s.installation_id.is_empty() || !s.installation_id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ctx("installation_id must be numeric".into()));
        }
        Ok(GitHubApp {
            name: name.to_string(),
            app_id: s.app_id.clone(),
            installation_id: s.installation_id.clone(),
            key_ref: SecretRef::parse(&s.private_key).map_err(ctx)?,
            api: ApiEndpoint::parse(s.api_base.as_deref().unwrap_or("https://api.github.com"), &s.api_addrs)
                .map_err(ctx)?,
        })
    }

    pub fn token_path(&self) -> String {
        format!("{}/app/installations/{}/access_tokens", self.api.base_path, self.installation_id)
    }
}

/// Parse the app's PEM private key (PKCS#1 as GitHub issues it, or PKCS#8).
pub fn load_rsa_key(pem: &Secret) -> anyhow::Result<RsaKeyPair> {
    use rustls_pki_types::PrivateKeyDer;
    use rustls_pki_types::pem::PemObject;
    let der = PrivateKeyDer::from_pem_slice(pem.expose()).map_err(|_| anyhow::anyhow!("not a PEM private key"))?;
    let kp = match &der {
        PrivateKeyDer::Pkcs1(k) => RsaKeyPair::from_der(k.secret_pkcs1_der()),
        PrivateKeyDer::Pkcs8(k) => RsaKeyPair::from_pkcs8(k.secret_pkcs8_der()),
        _ => anyhow::bail!("the GitHub App key must be an RSA key"),
    };
    kp.map_err(|_| anyhow::anyhow!("the GitHub App key was rejected by the RSA parser"))
}

fn b64url(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// The app JWT: RS256, `iat` 60 s in the past (clock drift), `exp` 9 min
/// ahead (GitHub allows 10).
pub fn app_jwt(app_id: &str, key: &RsaKeyPair, now: SystemTime) -> anyhow::Result<Secret> {
    let t = now.duration_since(UNIX_EPOCH)?.as_secs();
    let iss = if app_id.bytes().all(|b| b.is_ascii_digit()) {
        serde_json::Value::from(app_id.parse::<u64>()?)
    } else {
        serde_json::Value::from(app_id)
    };
    let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = b64url(serde_json::json!({ "iat": t - 60, "exp": t + 540, "iss": iss }).to_string().as_bytes());
    let signing_input = format!("{header}.{claims}");
    let mut sig = vec![0u8; key.public().modulus_len()];
    key.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), signing_input.as_bytes(), &mut sig)
        .map_err(|_| anyhow::anyhow!("RSA signing failed"))?;
    Ok(Secret::new(format!("{signing_input}.{}", b64url(&sig)).into_bytes()))
}

/// The request body: always both `repositories` and `permissions`.
pub fn request_body(permissions: &BTreeMap<String, String>, repos: &[RepoId]) -> anyhow::Result<Vec<u8>> {
    if repos.is_empty() || permissions.is_empty() {
        anyhow::bail!("refusing to request an installation token without repositories and permissions");
    }
    let names: Vec<&str> = repos.iter().map(|r| r.name()).collect();
    Ok(serde_json::to_vec(&serde_json::json!({ "repositories": names, "permissions": permissions }))?)
}

fn level(s: &str) -> u8 {
    match s {
        "read" => 1,
        "write" => 2,
        "admin" => 3,
        _ => u8::MAX,
    }
}

/// Validate a token response against what was requested.
pub fn verify_response(
    status: u16,
    body: &[u8],
    permissions: &BTreeMap<String, String>,
    repos: &[RepoId],
) -> anyhow::Result<(Secret, SystemTime)> {
    if status != 201 {
        anyhow::bail!("GitHub answered {status} to the installation-token request");
    }
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| anyhow::anyhow!("response is not JSON"))?;
    let token = v.get("token").and_then(|t| t.as_str()).filter(|t| !t.is_empty());
    let token = token.ok_or_else(|| anyhow::anyhow!("response has no token"))?;
    if token.bytes().any(|b| !b.is_ascii_graphic()) {
        anyhow::bail!("token has unexpected bytes");
    }
    let exp =
        v.get("expires_at").and_then(|t| t.as_str()).ok_or_else(|| anyhow::anyhow!("response has no expires_at"))?;
    let exp = time::OffsetDateTime::parse(exp, &time::format_description::well_known::Rfc3339)
        .map_err(|_| anyhow::anyhow!("expires_at is not RFC 3339"))?;
    let exp = UNIX_EPOCH + Duration::from_secs(u64::try_from(exp.unix_timestamp()).unwrap_or(0));
    // Scope must be within the request (metadata:read is implicit for apps).
    if let Some(got) = v.get("permissions").and_then(|p| p.as_object()) {
        for (k, lvl) in got {
            let lvl = lvl.as_str().unwrap_or("");
            let allowed = match permissions.get(k) {
                Some(req) => level(lvl) <= level(req),
                None => k == "metadata" && lvl == "read",
            };
            if !allowed {
                anyhow::bail!("token scope exceeds the request ({k}: {lvl})");
            }
        }
    } else {
        anyhow::bail!("response does not state the token's permissions");
    }
    if v.get("repository_selection").and_then(|s| s.as_str()) == Some("all") {
        anyhow::bail!("token covers all repositories of the installation");
    }
    if let Some(list) = v.get("repositories").and_then(|r| r.as_array()) {
        for r in list {
            let name = r.get("name").and_then(|n| n.as_str()).unwrap_or("").to_ascii_lowercase();
            if !repos.iter().any(|x| x.name() == name) {
                anyhow::bail!("token covers an unrequested repository");
            }
        }
    }
    Ok((Secret::new(token.as_bytes().to_vec()), exp))
}

/// Mint one installation token.
pub async fn mint(
    app: &GitHubApp,
    key: &RsaKeyPair,
    transport: &dyn Transport,
    permissions: &BTreeMap<String, String>,
    repos: &[RepoId],
) -> anyhow::Result<(Secret, SystemTime)> {
    for r in repos {
        if !same_instance(app, r) {
            anyhow::bail!("repository {r} is not on this app's GitHub instance");
        }
    }
    let body = request_body(permissions, repos)?;
    let jwt = app_jwt(&app.app_id, key, SystemTime::now())?;
    let (status, resp) =
        tokio::time::timeout(Duration::from_secs(20), transport.post_json(&app.api, &app.token_path(), &jwt, body))
            .await
            .map_err(|_| anyhow::anyhow!("installation-token request timed out"))??;
    verify_response(status, &resp, permissions, repos)
}

/// `github.com` repositories belong to `api.github.com`; a GitHub
/// Enterprise Server (or test) instance serves git and API on one host.
pub fn same_instance(app: &GitHubApp, r: &RepoId) -> bool {
    if app.api.host.as_str() == "api.github.com" {
        r.authority() == "github.com"
    } else {
        r.authority().split(':').next() == Some(app.api.host.as_str())
    }
}

#[cfg(test)]
pub(crate) mod tests;
