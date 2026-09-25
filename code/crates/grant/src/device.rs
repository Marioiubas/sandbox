//! OAuth 2.0 Device Authorization Grant (RFC 8628) messages, parsed
//! strictly: the device authorization response and the token endpoint's
//! answers while polling (and to a refresh). No I/O here; `brokerd` runs
//! the flow. Token values are kept out of `Debug` and error messages.

use serde_json::Value;
use zeroize::Zeroizing;

/// RFC 8628 §3.4.
pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// RFC 8628 §3.2: "If no value is provided, clients MUST use 5".
pub const DEFAULT_INTERVAL: u64 = 5;
/// RFC 8628 §3.5: `slow_down` adds 5 seconds for this and later requests.
pub const SLOW_DOWN_STEP: u64 = 5;

const MAX_BODY: usize = 64 << 10;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeviceError {
    #[error("the identity provider answered HTTP {0}")]
    Status(u16),
    #[error("the identity provider's answer is not a JSON object")]
    NotJson,
    #[error("the identity provider's answer lacks a valid {0}")]
    Field(&'static str),
    #[error("the identity provider refused: {0}")]
    Refused(String),
}

/// The device authorization response (RFC 8628 §3.2).
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceAuthorization {
    pub device_code: Zeroizing<String>,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

impl std::fmt::Debug for DeviceAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceAuthorization")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .finish()
    }
}

/// Tokens from the token endpoint; only the ID token and the refresh token
/// are kept (the access token is never used).
#[derive(Clone, PartialEq, Eq)]
pub struct Tokens {
    pub id_token: Zeroizing<String>,
    pub refresh_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tokens(<redacted>, refresh: {})", self.refresh_token.is_some())
    }
}

/// One answer from the token endpoint (RFC 8628 §3.5).
#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    Pending,
    SlowDown,
    Denied,
    Expired,
    Tokens(Tokens),
}

fn object(status_ok: bool, status: u16, body: &[u8]) -> Result<serde_json::Map<String, Value>, DeviceError> {
    if body.len() > MAX_BODY {
        return Err(DeviceError::NotJson);
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(m)) => Ok(m),
        _ if !status_ok => Err(DeviceError::Status(status)),
        _ => Err(DeviceError::NotJson),
    }
}

/// Printable ASCII without spaces, 1..=max bytes.
fn token_like(v: Option<&Value>, max: usize) -> Option<String> {
    let s = v?.as_str()?;
    (!s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic())).then(|| s.to_string())
}

fn https_uri(v: Option<&Value>) -> Option<String> {
    token_like(v, 2048).filter(|u| u.starts_with("https://") && u.len() > "https://".len())
}

/// Parse the device authorization response.
pub fn parse_authorization(status: u16, body: &[u8]) -> Result<DeviceAuthorization, DeviceError> {
    let m = object(status == 200, status, body)?;
    if status != 200 {
        return Err(refusal(&m).unwrap_or(DeviceError::Status(status)));
    }
    let n = |k: &'static str| m.get(k).and_then(Value::as_u64);
    let interval = match m.get("interval") {
        None => DEFAULT_INTERVAL,
        Some(_) => n("interval").filter(|i| (1..=300).contains(i)).ok_or(DeviceError::Field("interval"))?,
    };
    let complete = match m.get("verification_uri_complete") {
        None => None,
        v => Some(https_uri(v).ok_or(DeviceError::Field("verification_uri_complete"))?),
    };
    Ok(DeviceAuthorization {
        device_code: Zeroizing::new(token_like(m.get("device_code"), 4096).ok_or(DeviceError::Field("device_code"))?),
        user_code: token_like(m.get("user_code"), 64).ok_or(DeviceError::Field("user_code"))?,
        verification_uri: https_uri(m.get("verification_uri")).ok_or(DeviceError::Field("verification_uri"))?,
        verification_uri_complete: complete,
        expires_in: n("expires_in").filter(|e| (1..=86_400).contains(e)).ok_or(DeviceError::Field("expires_in"))?,
        interval,
    })
}

/// An OAuth error response's code, reduced to `[a-z_]` (never a value).
fn refusal(m: &serde_json::Map<String, Value>) -> Option<DeviceError> {
    let e = m.get("error")?.as_str()?;
    let code: String = e.chars().filter(|c| c.is_ascii_lowercase() || *c == '_').take(64).collect();
    Some(DeviceError::Refused(if code.is_empty() { "unknown".into() } else { code }))
}

/// Parse a token endpoint answer, while polling or to a refresh.
pub fn parse_token_response(status: u16, body: &[u8]) -> Result<Poll, DeviceError> {
    let m = object(status == 200, status, body)?;
    if status == 200 {
        let id_token = token_like(m.get("id_token"), 16 << 10).ok_or(DeviceError::Field("id_token"))?;
        let refresh_token = match m.get("refresh_token") {
            None => None,
            v => Some(Zeroizing::new(token_like(v, 16 << 10).ok_or(DeviceError::Field("refresh_token"))?)),
        };
        return Ok(Poll::Tokens(Tokens { id_token: Zeroizing::new(id_token), refresh_token }));
    }
    match refusal(&m) {
        Some(DeviceError::Refused(c)) => Ok(match c.as_str() {
            "authorization_pending" => Poll::Pending,
            "slow_down" => Poll::SlowDown,
            "access_denied" => Poll::Denied,
            "expired_token" => Poll::Expired,
            _ => return Err(DeviceError::Refused(c)),
        }),
        _ => Err(DeviceError::Status(status)),
    }
}

/// The interval for the next poll after `p`.
pub fn next_interval(current: u64, p: &Poll) -> u64 {
    match p {
        Poll::SlowDown => current.saturating_add(SLOW_DOWN_STEP).min(600),
        _ => current,
    }
}

/// An `application/x-www-form-urlencoded` body (every byte but
/// `A-Za-z0-9-._~` percent-encoded).
pub fn form(pairs: &[(&str, &str)]) -> String {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    };
    pairs.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
}

#[cfg(test)]
mod tests;
