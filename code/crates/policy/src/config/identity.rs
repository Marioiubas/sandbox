//! `[identity]`: OIDC issuers whose identity tokens may attribute a session
//! (CI runners) and the identity provider `broker login` signs in to. User
//! or org scope only; repository policy may not contain it.

use serde::Deserialize;

/// Identity sources (user or org scope): OIDC issuers whose identity
/// tokens (a CI runner's, for example) may attribute a session, and the
/// identity provider `broker login` signs in to.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    #[serde(default)]
    pub oidc: Vec<OidcIssuerSpec>,
    pub login: Option<LoginSpec>,
}

/// `[identity.login]`: OIDC device login (RFC 8628) for `broker login`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoginSpec {
    /// The identity provider's issuer (`https://`); its discovery document
    /// must name the device authorization, token and key endpoints on the
    /// same host.
    pub issuer: String,
    /// A public client registered for the device flow.
    pub client_id: String,
    /// Scopes to request; must include `openid`. Default
    /// `["openid", "profile", "offline_access"]`.
    pub scopes: Option<Vec<String>>,
    /// The ID-token claim listing the user's groups. Default `groups`.
    pub groups_claim: Option<String>,
    /// Pinned addresses for the issuer's host (tests, private IdPs); no
    /// DNS query then. Without them the host must resolve to public addresses.
    #[serde(default)]
    pub addrs: Vec<String>,
    /// Refuse sessions without a current login (instead of the local user).
    #[serde(default)]
    pub required: bool,
    /// How long a login lasts before signing in again (`12h` default, at most `7d`).
    pub max_age: Option<String>,
}

impl LoginSpec {
    pub fn scopes(&self) -> Vec<String> {
        self.scopes.clone().unwrap_or_else(|| vec!["openid".into(), "profile".into(), "offline_access".into()])
    }
    pub fn groups_claim(&self) -> &str {
        self.groups_claim.as_deref().unwrap_or("groups")
    }
    pub fn max_age(&self) -> std::time::Duration {
        self.max_age
            .as_deref()
            .and_then(|m| crate::l7::parse_ttl(m).ok())
            .unwrap_or(std::time::Duration::from_secs(12 * 3600))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcIssuerSpec {
    /// The exact `iss` value, an `https://` URL.
    pub issuer: String,
    /// The `aud` value tokens must carry for this broker.
    pub audience: String,
    /// The issuer's key set; default: its OIDC discovery document.
    pub jwks_url: Option<String>,
    /// A key set file in the broker config directory (air-gapped setups).
    pub jwks_file: Option<String>,
}

impl IdentitySection {
    pub fn validate(&self) -> anyhow::Result<()> {
        for o in &self.oidc {
            if !o.issuer.starts_with("https://") || o.issuer.len() > 512 {
                anyhow::bail!("identity.oidc issuer {:?} must be an https:// URL", o.issuer);
            }
            if o.audience.is_empty() || o.audience.len() > 256 {
                anyhow::bail!("identity.oidc audience for {} must be 1-256 bytes", o.issuer);
            }
            if o.jwks_url.as_ref().is_some_and(|u| !u.starts_with("https://")) {
                anyhow::bail!("identity.oidc jwks_url for {} must be https://", o.issuer);
            }
            if o.jwks_url.is_some() && o.jwks_file.is_some() {
                anyhow::bail!("identity.oidc for {}: jwks_url and jwks_file are exclusive", o.issuer);
            }
        }
        if let Some(l) = &self.login {
            let rest = l.issuer.strip_prefix("https://").unwrap_or("");
            if rest.is_empty() || l.issuer.len() > 512 || l.issuer.bytes().any(|b| !b.is_ascii_graphic()) {
                anyhow::bail!("identity.login issuer {:?} must be an https:// URL", l.issuer);
            }
            if l.client_id.is_empty() || l.client_id.len() > 256 || l.client_id.bytes().any(|b| !b.is_ascii_graphic()) {
                anyhow::bail!("identity.login client_id must be 1-256 printable characters");
            }
            let scopes = l.scopes();
            if !scopes.iter().any(|s| s == "openid")
                || scopes.iter().any(|s| s.is_empty() || s.bytes().any(|b| !b.is_ascii_graphic()))
            {
                anyhow::bail!("identity.login scopes must include openid and contain no spaces");
            }
            if l.groups_claim().is_empty() || l.groups_claim().len() > 64 {
                anyhow::bail!("identity.login groups_claim must be 1-64 characters");
            }
            if let Some(m) = &l.max_age {
                let d = crate::l7::parse_ttl(m).map_err(|e| anyhow::anyhow!("identity.login max_age: {e}"))?;
                if d > std::time::Duration::from_secs(7 * 86_400) {
                    anyhow::bail!("identity.login max_age is at most 7d");
                }
            }
            for a in &l.addrs {
                if a.parse::<std::net::IpAddr>().is_err() {
                    anyhow::bail!("identity.login addrs: {a:?} is not an IP address");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::parse_policy_str;

    #[test]
    fn login_settings_are_validated() {
        let ok = "version = 1\n[identity.login]\nissuer = \"https://idp.example.com\"\nclient_id = \"0oa1\"\n";
        let p = parse_policy_str(ok).unwrap();
        let l = p.identity.login.unwrap();
        assert_eq!(l.scopes(), ["openid", "profile", "offline_access"]);
        assert_eq!((l.groups_claim(), l.max_age().as_secs(), l.required), ("groups", 12 * 3600, false));
        for bad in [
            "issuer = \"http://idp.example.com\"\nclient_id = \"x\"",
            "issuer = \"https://\"\nclient_id = \"x\"",
            "issuer = \"https://idp.example.com\"\nclient_id = \"\"",
            "issuer = \"https://idp.example.com\"\nclient_id = \"x\"\nscopes = [\"profile\"]",
            "issuer = \"https://idp.example.com\"\nclient_id = \"x\"\nscopes = [\"openid groups\"]",
            "issuer = \"https://idp.example.com\"\nclient_id = \"x\"\nmax_age = \"30d\"",
            "issuer = \"https://idp.example.com\"\nclient_id = \"x\"\naddrs = [\"idp.internal\"]",
            "issuer = \"https://idp.example.com\"\nclient_id = \"x\"\nclient_secret = \"s\"",
        ] {
            assert!(parse_policy_str(&format!("version = 1\n[identity.login]\n{bad}\n")).is_err(), "{bad}");
        }
    }
}
