//! `broker login`: OIDC device login (RFC 8628) to the identity provider
//! named in `[identity.login]` of user or org policy. The daemon runs the
//! flow, verifies the ID token (exact issuer, audience = the client ID,
//! expiry, RS256 signature with the issuer's keys) and keeps the identity
//! and any refresh token in memory only, never on disk. New sessions are
//! attributed to the login's subject and groups. No IdP token is ever
//! forwarded to an upstream, an MCP server or the agent.

use crate::fetch;
use crate::identity::roots as daemon_roots;
use crate::session::Daemon;
use grant::device::{self, Poll, Tokens};
use grant::oidc::{Identity, IssuerConfig, Jwks, OidcError};
use policy::PolicyFile;
use policy::config::LoginSpec;
use rustls_pki_types::CertificateDer;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const MAX_DOC: usize = 256 << 10;
/// Refresh an ID token this long before it expires.
const REFRESH_MARGIN: i64 = 120;

/// The issuer's endpoints, from its discovery document.
pub struct Endpoints {
    device: String,
    token: String,
    jwks_uri: String,
    jwks: Mutex<Jwks>,
}

struct Current {
    spec: LoginSpec,
    endpoints: Arc<Endpoints>,
    identity: Identity,
    id_exp: i64,
    refresh: Option<Zeroizing<String>>,
    until: SystemTime,
}

struct Pending {
    spec: LoginSpec,
    endpoints: Arc<Endpoints>,
    device_code: Zeroizing<String>,
    interval: u64,
    deadline: Instant,
}

/// The daemon's login state.
#[derive(Default)]
pub struct Logins {
    current: Mutex<Option<Current>>,
    pending: Mutex<HashMap<String, Pending>>,
}

impl Logins {
    /// A login is held (the daemon stays up while it is).
    pub fn held(&self) -> bool {
        self.current.lock().map(|c| c.as_ref().is_some_and(|c| c.until > SystemTime::now())).unwrap_or(false)
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn pins(spec: &LoginSpec) -> Vec<IpAddr> {
    spec.addrs.iter().filter_map(|a| a.parse().ok()).collect()
}

fn spec_of(user: &PolicyFile) -> Result<&LoginSpec, String> {
    user.identity.login.as_ref().ok_or_else(|| "no [identity.login] is configured in your broker.toml".to_string())
}

async fn discover(spec: &LoginSpec, roots: &[CertificateDer<'static>]) -> Result<Endpoints, String> {
    let issuer = fetch::Target::parse(&spec.issuer)?;
    let url = format!("{}/.well-known/openid-configuration", spec.issuer.trim_end_matches('/'));
    let doc = fetch::get_pinned(&url, &pins(spec), roots, MAX_DOC).await?;
    let v: Value = serde_json::from_slice(&doc).map_err(|_| "the discovery document is not JSON")?;
    if v.get("issuer").and_then(Value::as_str) != Some(spec.issuer.as_str()) {
        return Err("the discovery document names another issuer".into());
    }
    let endpoint = |k: &str| -> Result<String, String> {
        let u = v.get(k).and_then(Value::as_str).ok_or_else(|| format!("the discovery document has no {k}"))?;
        if !fetch::Target::parse(u)?.same_origin(&issuer) {
            return Err(format!("the discovery document's {k} is not on the issuer's host"));
        }
        Ok(u.to_string())
    };
    let (device, token, jwks_uri) =
        (endpoint("device_authorization_endpoint")?, endpoint("token_endpoint")?, endpoint("jwks_uri")?);
    let jwks =
        Jwks::parse(&fetch::get_pinned(&jwks_uri, &pins(spec), roots, MAX_DOC).await?).map_err(|e| e.to_string())?;
    Ok(Endpoints { device, token, jwks_uri, jwks: Mutex::new(jwks) })
}

/// Verify an ID token from the token endpoint; refetch the key set once
/// when it lacks the token's key.
async fn verify(
    spec: &LoginSpec,
    ep: &Endpoints,
    roots: &[CertificateDer<'static>],
    tokens: &Tokens,
) -> Result<(Identity, i64), String> {
    let trusted = [IssuerConfig { issuer: spec.issuer.clone(), audience: spec.client_id.clone() }];
    let jwks = ep.jwks.lock().map_err(|_| "key cache poisoned")?.clone();
    let r = match grant::oidc::verify(&tokens.id_token, &trusted, &jwks, now()) {
        Err(OidcError::UnknownKey) => {
            let fresh = Jwks::parse(&fetch::get_pinned(&ep.jwks_uri, &pins(spec), roots, MAX_DOC).await?)
                .map_err(|e| e.to_string())?;
            *ep.jwks.lock().map_err(|_| "key cache poisoned")? = fresh.clone();
            grant::oidc::verify(&tokens.id_token, &trusted, &fresh, now())
        }
        r => r,
    };
    let mut id = r.map_err(|e| format!("the ID token was rejected: {e}"))?;
    id.groups = id.groups_from(spec.groups_claim());
    let exp = id.claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
    Ok((id, exp))
}

fn login_id() -> String {
    let mut b = [0u8; 12];
    getrandom::fill(&mut b).expect("OS randomness");
    hex::encode(b)
}

/// `login.start`: discover the issuer and ask for a device code.
pub async fn start(d: &Daemon) -> Result<Value, String> {
    let user = crate::session_util::load_user_policy(&d.dirs).map_err(|e| format!("{e:#}"))?;
    let spec = spec_of(&user)?.clone();
    let roots = daemon_roots(&d.dirs, &user)?;
    let ep = Arc::new(discover(&spec, &roots).await?);
    let body = device::form(&[("client_id", &spec.client_id), ("scope", &spec.scopes().join(" "))]);
    let (status, resp) = fetch::request(&ep.device, &pins(&spec), Some(&body), &roots, MAX_DOC).await?;
    let a = device::parse_authorization(status, &resp).map_err(|e| e.to_string())?;
    let id = login_id();
    let out = json!({
        "login_id": id, "issuer": spec.issuer, "user_code": a.user_code, "verification_uri": a.verification_uri,
        "verification_uri_complete": a.verification_uri_complete, "expires_in": a.expires_in,
    });
    let p = Pending {
        spec,
        endpoints: ep,
        device_code: a.device_code,
        interval: a.interval,
        deadline: Instant::now() + Duration::from_secs(a.expires_in),
    };
    d.logins.pending.lock().map_err(|_| "login state poisoned")?.insert(id, p);
    Ok(out)
}

fn summary(c: &Current) -> Value {
    json!({
        "issuer": c.identity.issuer, "subject": c.identity.subject, "groups": c.identity.groups,
        "until": c.until.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        "refreshable": c.refresh.is_some(),
    })
}

/// `login.wait`: poll the token endpoint until the user approves, denies
/// or the code expires (RFC 8628 §3.5).
pub async fn wait(d: &Daemon, id: &str) -> Result<Value, String> {
    let p = d.logins.pending.lock().map_err(|_| "login state poisoned")?.remove(id);
    let mut p = p.ok_or("no login in progress with that id")?;
    let user = crate::session_util::load_user_policy(&d.dirs).map_err(|e| format!("{e:#}"))?;
    let roots = daemon_roots(&d.dirs, &user)?;
    let body = device::form(&[
        ("grant_type", device::GRANT_TYPE),
        ("device_code", &p.device_code),
        ("client_id", &p.spec.client_id),
    ]);
    let body = Zeroizing::new(body);
    loop {
        tokio::time::sleep(Duration::from_secs(p.interval)).await;
        if Instant::now() >= p.deadline {
            return Err("the code expired before sign-in finished; run `broker login` again".into());
        }
        let (status, resp) = fetch::request(&p.endpoints.token, &pins(&p.spec), Some(&body), &roots, MAX_DOC).await?;
        let poll = device::parse_token_response(status, &resp).map_err(|e| e.to_string())?;
        p.interval = device::next_interval(p.interval, &poll);
        let tokens = match poll {
            Poll::Pending | Poll::SlowDown => continue,
            Poll::Denied => return Err("the sign-in was denied".into()),
            Poll::Expired => return Err("the code expired before sign-in finished; run `broker login` again".into()),
            Poll::Tokens(t) => t,
        };
        let (identity, id_exp) = verify(&p.spec, &p.endpoints, &roots, &tokens).await?;
        let c = Current {
            until: SystemTime::now() + p.spec.max_age(),
            spec: p.spec,
            endpoints: p.endpoints,
            identity,
            id_exp,
            refresh: tokens.refresh_token,
        };
        let out = summary(&c);
        *d.logins.current.lock().map_err(|_| "login state poisoned")? = Some(c);
        return Ok(out);
    }
}

/// `login.status`.
pub fn status(d: &Daemon) -> Value {
    match d.logins.current.lock().ok().as_deref() {
        Some(Some(c)) if c.until > SystemTime::now() => summary(c),
        _ => Value::Null,
    }
}

/// `login.logout`: forget the login (identity and tokens).
pub fn logout(d: &Daemon) -> bool {
    d.logins.current.lock().map(|mut c| c.take().is_some()).unwrap_or(false)
}

/// The login identity for a new session: `None` when no login is configured
/// or held (unless `required`, which refuses); refreshed when its ID token
/// is about to expire. A login made for another issuer or client is ignored.
pub async fn session_identity(
    d: &Daemon,
    user: &PolicyFile,
    roots: &[CertificateDer<'static>],
) -> Result<Option<Identity>, String> {
    let Some(spec) = user.identity.login.as_ref() else { return Ok(None) };
    let none = |why: &str| {
        if spec.required { Err(format!("{why}; run `broker login` (required by policy)")) } else { Ok(None) }
    };
    let (ep, refresh) = {
        let mut cur = d.logins.current.lock().map_err(|_| "login state poisoned")?;
        match cur.as_ref() {
            Some(c) if c.spec.issuer != spec.issuer || c.spec.client_id != spec.client_id => {
                *cur = None;
                return none("the login is for another identity provider");
            }
            Some(c) if c.until <= SystemTime::now() => {
                *cur = None;
                return none("the login has expired");
            }
            Some(c) if c.id_exp - now() > REFRESH_MARGIN => return Ok(Some(c.identity.clone())),
            Some(c) => (c.endpoints.clone(), c.refresh.clone()),
            None => return none("no login is held"),
        }
    };
    let Some(rt) = refresh else {
        logout(d);
        return none("the login's ID token expired and cannot be refreshed");
    };
    let body = Zeroizing::new(device::form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", &rt),
        ("client_id", &spec.client_id),
        ("scope", &spec.scopes().join(" ")),
    ]));
    let refreshed = async {
        let (status, resp) = fetch::request(&ep.token, &pins(spec), Some(&body), roots, MAX_DOC).await?;
        match device::parse_token_response(status, &resp).map_err(|e| e.to_string())? {
            Poll::Tokens(t) => {
                let (id, exp) = verify(spec, &ep, roots, &t).await?;
                Ok((id, exp, t.refresh_token))
            }
            _ => Err("the refresh was not answered with tokens".to_string()),
        }
    }
    .await;
    match refreshed {
        Ok((id, exp, new_rt)) => {
            let mut cur = d.logins.current.lock().map_err(|_| "login state poisoned")?;
            if let Some(c) = cur.as_mut() {
                if id.subject != c.identity.subject {
                    *cur = None;
                    return Err("the refreshed ID token names another subject; signed out".into());
                }
                c.identity = id.clone();
                c.id_exp = exp;
                if new_rt.is_some() {
                    c.refresh = new_rt;
                }
            }
            Ok(Some(id))
        }
        Err(e) => {
            logout(d);
            none(&format!("the login could not be refreshed ({e})"))
        }
    }
}
