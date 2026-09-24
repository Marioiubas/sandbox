//! Per-session L7 setup (M1): the session CA and trust bundle, the
//! credential sentinels, issuers and upstream trust. Nothing here puts a
//! secret into the sandbox: the environment receives only the bundle paths
//! and the sentinels (I1).

use crate::dirs::BrokerDirs;
use crate::l7_pipeline::{L7Ctx, MAX_INSPECTED_BODY};
use crate::upstream::BrokerTransport;
use audit::SessionId;
use creds::SessionCreds;
use creds::issuers::github_app::GitHubApp;
use creds::secrets::OsSecrets;
use netguard::resolver::PolicyResolver;
use policy::{EgressPolicy, PolicyFile};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tls::trust_bundle::TrustBundle;

pub struct L7Setup {
    pub ctx: Arc<L7Ctx>,
    /// Trust-bundle variables and credential sentinels for the sandbox.
    pub env: Vec<(String, String)>,
    pub bundle: TrustBundle,
    /// `id (kind)` per declared credential, for the session.start row.
    pub credentials: Vec<String>,
}

fn root_path(p: &str, config_dir: &Path, home: &Path) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        home.join(rest)
    } else if p.starts_with('/') {
        PathBuf::from(p)
    } else {
        config_dir.join(p)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn setup(
    id: &SessionId,
    egress: &EgressPolicy,
    user: &PolicyFile,
    dirs: &BrokerDirs,
    home: &Path,
    resolver: Arc<dyn PolicyResolver>,
    session_tmp: &Path,
    channel_sentinel: Option<Vec<u8>>,
) -> anyhow::Result<L7Setup> {
    let ca = Arc::new(tls::session_ca::SessionCa::new(id.as_str())?);
    let mut extra = Vec::new();
    for r in &user.tls.extra_roots {
        extra.extend(tls::trust_bundle::load_pem_certs(&root_path(r, &dirs.config_dir, home))?);
    }
    // The bundle lives in the session's temp dir: it only affects what the
    // sandbox's own clients trust; the broker verifies upstreams itself.
    let bundle = tls::trust_bundle::write(&session_tmp.join("broker-ca"), ca.ca_pem(), &extra)?;
    let upstream_tls = tls::upstream::client_config(&extra)?;
    let mut issuers = BTreeMap::new();
    for (name, spec) in &user.issuers.github_app {
        issuers.insert(name.clone(), GitHubApp::from_spec(name, spec).map_err(|m| anyhow::anyhow!(m))?);
    }
    let transport = Arc::new(BrokerTransport { resolver, tls: upstream_tls.clone() });
    let reader = Arc::new(OsSecrets { config_dir: dirs.config_dir.clone(), home: home.to_path_buf() });
    let defs = egress.credentials();
    let credentials = defs.iter().map(|c| format!("{} ({})", c.id, c.kind.as_str())).collect();
    let creds = Arc::new(SessionCreds::new(id.as_str(), &defs, issuers, reader, transport));
    let mut env = tls::trust_bundle::env_vars(&bundle);
    env.extend(creds.sentinels.env());
    let ctx = Arc::new(L7Ctx {
        ca,
        upstream_tls,
        creds,
        channel_sentinel,
        max_body: MAX_INSPECTED_BODY,
        visibility: Default::default(),
    });
    Ok(L7Setup { ctx, env, bundle, credentials })
}
