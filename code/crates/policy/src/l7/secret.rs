//! Secret references (`keychain:`, `env:`, `file:`, alternatives with `|`,
//! `#json.path` selectors). Resolution lives in `creds`; nothing here reads a
//! secret.

use super::*;

/// Where a secret comes from. Resolution lives in `creds`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretSource {
    Keychain {
        service: String,
        account: Option<String>,
    },
    /// An environment variable of brokerd itself (CI secrets), never the sandbox's.
    Env(String),
    /// A file name inside the broker config directory, or a `~/` path.
    File(String),
}

/// One place a secret may live, optionally selecting a JSON string field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretAlt {
    pub source: SecretSource,
    /// Select a string field of a JSON secret (`#a.b`).
    pub json_path: Vec<String>,
}

/// A secret reference: one or more alternatives (`a|b`), tried in order;
/// the first that yields a secret is used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef {
    pub alternatives: Vec<SecretAlt>,
}

fn parse_alt(whole: &str, s: &str) -> Result<SecretAlt, String> {
    let (src, path) = match s.split_once('#') {
        Some((a, p)) => (a, p.split('.').map(str::to_string).collect::<Vec<_>>()),
        None => (s, vec![]),
    };
    if path.iter().any(|p| p.is_empty()) {
        return Err(format!("secret reference {whole:?}: empty JSON path component"));
    }
    let nonempty = |v: &str| -> Result<String, String> {
        if v.is_empty() || v.bytes().any(|b| b < 0x20 || b == 0x7f) {
            Err(format!("secret reference {whole:?} is empty or has control bytes"))
        } else {
            Ok(v.to_string())
        }
    };
    let source = if let Some(rest) = src.strip_prefix("keychain:") {
        match rest.split_once('/') {
            Some((svc, acct)) => SecretSource::Keychain { service: nonempty(svc)?, account: Some(nonempty(acct)?) },
            None => SecretSource::Keychain { service: nonempty(rest)?, account: None },
        }
    } else if let Some(v) = src.strip_prefix("env:") {
        if !env_name_ok(v) {
            return Err(format!("secret reference {whole:?}: bad variable name"));
        }
        SecretSource::Env(v.to_string())
    } else if let Some(f) = src.strip_prefix("file:") {
        let f = nonempty(f)?;
        let ok = match f.strip_prefix("~/") {
            // Home-relative: an agent's own credential file (made deny-read
            // for the sandbox by the profile that names it).
            Some(rest) => !rest.is_empty() && rest.split('/').all(|c| !c.is_empty() && c != "." && c != ".."),
            // Otherwise a file name in the broker config dir.
            None => !f.contains('/') && !f.starts_with('.'),
        };
        if !ok {
            return Err(format!(
                "secret reference {whole:?}: file: takes a name in the broker config dir or a ~/ path"
            ));
        }
        SecretSource::File(f)
    } else {
        return Err(format!("secret reference {whole:?}: use keychain:, env: or file:"));
    };
    Ok(SecretAlt { source, json_path: path })
}

impl SecretRef {
    pub fn parse(s: &str) -> Result<SecretRef, String> {
        let alternatives = s.split('|').map(|a| parse_alt(s, a)).collect::<Result<Vec<_>, _>>()?;
        Ok(SecretRef { alternatives })
    }

    pub fn describe(&self) -> String {
        self.alternatives
            .iter()
            .map(|a| {
                let base = match &a.source {
                    SecretSource::Keychain { service, account: Some(ac) } => format!("keychain:{service}/{ac}"),
                    SecretSource::Keychain { service, account: None } => format!("keychain:{service}"),
                    SecretSource::Env(v) => format!("env:{v}"),
                    SecretSource::File(f) => format!("file:{f}"),
                };
                if a.json_path.is_empty() { base } else { format!("{base}#{}", a.json_path.join(".")) }
            })
            .collect::<Vec<_>>()
            .join("|")
    }
}
