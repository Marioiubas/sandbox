//! OIDC identity tokens (the runner's token in CI): the issuer must be one
//! the user or org policy names, exactly; the audience must be the one it
//! names; the token must be unexpired (60 s leeway); the signature must
//! verify with an RS256 key of that issuer's JWKS, selected by `kid`.
//! The token itself is never forwarded anywhere.

use crate::jwt::{self, JwtError};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

const LEEWAY: i64 = 60;

/// A trusted issuer (from `[[identity.oidc]]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerConfig {
    pub issuer: String,
    pub audience: String,
}

/// An issuer's signing keys: `(kid, n, e)` for RSA keys usable for RS256.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Jwks {
    pub keys: Vec<(String, Vec<u8>, Vec<u8>)>,
}

impl Jwks {
    /// Parse a JWKS document, keeping RSA signature keys that name a `kid`.
    pub fn parse(doc: &[u8]) -> Result<Jwks, OidcError> {
        let v: Value = serde_json::from_slice(doc).map_err(|_| OidcError::Jwks)?;
        let keys = v.get("keys").and_then(|k| k.as_array()).ok_or(OidcError::Jwks)?;
        let mut out = Vec::new();
        for k in keys {
            let s = |f: &str| k.get(f).and_then(|x| x.as_str());
            if s("kty") != Some("RSA") || s("use").is_some_and(|u| u != "sig") || s("alg").is_some_and(|a| a != "RS256")
            {
                continue;
            }
            let (Some(kid), Some(n), Some(e)) = (s("kid"), s("n"), s("e")) else { continue };
            let (Ok(n), Ok(e)) = (URL_SAFE_NO_PAD.decode(n), URL_SAFE_NO_PAD.decode(e)) else { continue };
            out.push((kid.to_string(), n, e));
        }
        Ok(Jwks { keys: out })
    }

    pub fn key(&self, kid: &str) -> Option<(&[u8], &[u8])> {
        self.keys.iter().find(|(k, ..)| k == kid).map(|(_, n, e)| (n.as_slice(), e.as_slice()))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OidcError {
    #[error(transparent)]
    Jwt(#[from] JwtError),
    #[error("the issuer {0:?} is not trusted by policy")]
    UntrustedIssuer(String),
    #[error("the audience is not {0:?}")]
    Audience(String),
    #[error("the token is expired or not yet valid")]
    Time,
    #[error("the token names no key (kid) its issuer publishes")]
    UnknownKey,
    #[error("the issuer's key set could not be read")]
    Jwks,
    #[error("the token has no usable subject")]
    Subject,
}

/// A verified identity.
#[derive(Clone, Debug, PartialEq)]
pub struct Identity {
    pub issuer: String,
    pub subject: String,
    /// All claims (for attribution; never forwarded).
    pub claims: Map<String, Value>,
    /// Groups, when the daemon was told which claim carries them
    /// (`broker login`); empty otherwise.
    pub groups: Vec<String>,
}

impl Identity {
    /// The string members of claim `name` (at most 200, each 1-256 bytes;
    /// anything else is ignored).
    pub fn groups_from(&self, name: &str) -> Vec<String> {
        let mut g: Vec<String> = match self.claims.get(name) {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
                .take(200)
                .map(str::to_string)
                .collect(),
            _ => vec![],
        };
        g.sort();
        g.dedup();
        g
    }
}

/// The issuer a token claims, before verification (to pick its key set).
pub fn claimed_issuer(token: &str) -> Result<String, OidcError> {
    let j = jwt::parse(token)?;
    j.claims.get("iss").and_then(|i| i.as_str()).map(str::to_string).ok_or(OidcError::UntrustedIssuer(String::new()))
}

/// Verify `token` against the trusted issuers, with `jwks` for its issuer.
pub fn verify(token: &str, trusted: &[IssuerConfig], jwks: &Jwks, now: i64) -> Result<Identity, OidcError> {
    let j = jwt::parse(token)?;
    if j.alg() != "RS256" {
        return Err(JwtError::Algorithm(j.alg().to_string()).into());
    }
    let iss = j.claims.get("iss").and_then(|i| i.as_str()).unwrap_or("").to_string();
    let cfg = trusted.iter().find(|c| c.issuer == iss).ok_or_else(|| OidcError::UntrustedIssuer(iss.clone()))?;
    let (n, e) = j.kid().and_then(|k| jwks.key(k)).ok_or(OidcError::UnknownKey)?;
    j.verify_rs256(n, e)?;
    let aud_ok = match j.claims.get("aud") {
        Some(Value::String(a)) => *a == cfg.audience,
        Some(Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(cfg.audience.as_str())),
        _ => false,
    };
    if !aud_ok {
        return Err(OidcError::Audience(cfg.audience.clone()));
    }
    let t = |k: &str| j.claims.get(k).and_then(|v| v.as_i64());
    match t("exp") {
        Some(exp) if exp + LEEWAY > now => {}
        _ => return Err(OidcError::Time),
    }
    if t("nbf").is_some_and(|nbf| nbf > now + LEEWAY) || t("iat").is_some_and(|iat| iat > now + LEEWAY) {
        return Err(OidcError::Time);
    }
    let subject = j.claims.get("sub").and_then(|s| s.as_str()).filter(|s| !s.is_empty() && s.len() <= 512);
    let subject = subject.ok_or(OidcError::Subject)?.to_string();
    Ok(Identity { issuer: iss, subject, claims: j.claims, groups: vec![] })
}

#[cfg(test)]
mod tests;
