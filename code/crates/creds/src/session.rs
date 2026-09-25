//! Per-session credential state: sentinels, loaded static secrets and
//! minted tokens, cached by scope digest. Dropped (and zeroized) with the
//! session; nothing is written to disk.

use crate::issuers::Transport;
use crate::issuers::aws_sts::{self, AwsSts, BaseCreds};
use crate::issuers::github_app::{self, GitHubApp};
use crate::secrets::SecretReader;
use crate::sentinel::Sentinels;
use crate::{AwsKeys, Issued, Secret};
use policy::{AllowedBinding, CredKind, CredentialDef};
use ring::signature::RsaKeyPair;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Refresh a cached credential this long before it would expire.
pub const REFRESH_MARGIN: Duration = Duration::from_secs(120);

/// A mint or load failure. The message names the credential and the cause,
/// never secret material.
#[derive(Debug, thiserror::Error)]
#[error("credential {credential}: {message}")]
pub struct MintError {
    pub credential: String,
    pub message: String,
}

pub struct SessionCreds {
    session: String,
    pub sentinels: Sentinels,
    reader: Arc<dyn SecretReader>,
    transport: Arc<dyn Transport>,
    issuers: BTreeMap<String, GitHubApp>,
    aws: BTreeMap<String, AwsSts>,
    /// `SourceIdentity` for STS sessions (the session's end user).
    source_identity: Option<String>,
    cache: tokio::sync::Mutex<HashMap<[u8; 32], Arc<Issued>>>,
    keys: Mutex<HashMap<String, Arc<RsaKeyPair>>>,
    /// Upstream mint/load operations performed (tests assert "no mint without allow").
    pub mints: AtomicU64,
}

impl std::fmt::Debug for SessionCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionCreds({}, {:?})", self.session, self.sentinels)
    }
}

/// `H(kind || credential || issuer audience || sorted permissions ||
/// sorted resources || session)`: equal authority reuses one token; a
/// narrower need never receives a broader cached one.
pub fn scope_digest(def: &CredentialDef, issuers: &BTreeMap<String, GitHubApp>, session: &str) -> [u8; 32] {
    let v = match &def.kind {
        CredKind::Static { secret } => serde_json::json!({
            "kind": "static", "credential": def.id, "ref": secret.describe(), "session": session,
        }),
        CredKind::GitHubApp { issuer, permissions, repos } => {
            let mut r: Vec<String> = repos.iter().map(|x| x.to_string()).collect();
            r.sort();
            serde_json::json!({
                "kind": "github_app", "credential": def.id, "issuer": issuer,
                "audience": issuers.get(issuer).map(|i| i.api.authority()),
                "permissions": permissions, "repos": r, "session": session,
            })
        }
        CredKind::AwsSts { issuer, session_policy } => serde_json::json!({
            "kind": "aws_sts", "credential": def.id, "issuer": issuer, "policy": session_policy, "session": session,
        }),
    };
    Sha256::digest(v.to_string().as_bytes()).into()
}

fn usable(i: &Issued, now: SystemTime) -> bool {
    let ok = |t: Option<SystemTime>| t.is_none_or(|t| t > now + REFRESH_MARGIN);
    ok(i.expires_at) && ok(i.reuse_until)
}

impl SessionCreds {
    pub fn new(
        session: &str,
        creds: &[Arc<CredentialDef>],
        issuers: BTreeMap<String, GitHubApp>,
        reader: Arc<dyn SecretReader>,
        transport: Arc<dyn Transport>,
    ) -> SessionCreds {
        SessionCreds {
            session: session.to_string(),
            sentinels: Sentinels::issue(creds),
            reader,
            transport,
            issuers,
            aws: BTreeMap::new(),
            source_identity: None,
            cache: tokio::sync::Mutex::new(HashMap::new()),
            keys: Mutex::new(HashMap::new()),
            mints: AtomicU64::new(0),
        }
    }

    /// Add `aws_sts` issuers, and the end user STS sessions name as their
    /// `SourceIdentity`.
    pub fn with_aws_sts(mut self, issuers: BTreeMap<String, AwsSts>, source_identity: Option<String>) -> SessionCreds {
        self.aws = issuers;
        self.source_identity = source_identity;
        self
    }

    /// The credential for an allowed request: a cached handle when the same
    /// scope is still valid (`reused = true`), else a fresh mint or load.
    pub async fn get(&self, binding: &AllowedBinding) -> Result<(Arc<Issued>, bool), MintError> {
        let def = binding.credential();
        let err = |m: String| MintError { credential: def.id.clone(), message: m };
        let digest = scope_digest(def, &self.issuers, &self.session);
        let mut cache = self.cache.lock().await;
        if let Some(i) = cache.get(&digest)
            && usable(i, SystemTime::now())
        {
            return Ok((i.clone(), true));
        }
        self.mints.fetch_add(1, Ordering::Relaxed);
        let issued = match &def.kind {
            CredKind::Static { secret } => {
                let (reader, r) = (self.reader.clone(), secret.clone());
                let s = tokio::task::spawn_blocking(move || reader.read(&r))
                    .await
                    .map_err(|e| err(format!("reader task: {e}")))?
                    .map_err(|e| err(format!("{e:#}")))?;
                Issued::new(&def.id, "static", s, None, None, digest, "load")
            }
            CredKind::GitHubApp { issuer, permissions, repos } => {
                if repos.is_empty() {
                    return Err(err("the token would cover no repository (is ${repo_remote} unresolved?)".into()));
                }
                let app = self.issuers.get(issuer).ok_or_else(|| err(format!("no issuer {issuer}")))?;
                let key = self.app_key(app).await.map_err(|e| err(format!("{e:#}")))?;
                let (tok, exp) = github_app::mint(app, &key, self.transport.as_ref(), permissions, repos)
                    .await
                    .map_err(|e| err(format!("{e:#}")))?;
                let now = SystemTime::now();
                if exp <= now + REFRESH_MARGIN {
                    return Err(err("minted token is already (nearly) expired".into()));
                }
                let reuse = def.ttl.map(|t| now + t).map(|r| r.min(exp)).unwrap_or(exp);
                Issued::new(&def.id, "github_app", tok, Some(exp), Some(reuse), digest, "mint")
            }
            CredKind::AwsSts { issuer, session_policy } => {
                let sts = self.aws.get(issuer).ok_or_else(|| err(format!("no issuer {issuer}")))?;
                let base = self.aws_base(sts).await.map_err(|e| err(format!("{e:#}")))?;
                let name = aws_sts::sts_name(&format!("broker-{}", self.session));
                let who = self.source_identity.as_deref().filter(|_| sts.source_identity).map(aws_sts::sts_name);
                let s = aws_sts::mint(sts, &base, self.transport.as_ref(), session_policy, &name, who.as_deref())
                    .await
                    .map_err(|e| err(format!("{e:#}")))?;
                let now = SystemTime::now();
                if s.expires_at <= now + REFRESH_MARGIN {
                    return Err(err("minted session is already (nearly) expired".into()));
                }
                let reuse = def.ttl.map(|t| now + t).map(|r| r.min(s.expires_at)).unwrap_or(s.expires_at);
                let keys = AwsKeys { access_key_id: s.access_key_id, session_token: s.session_token };
                Issued::new(&def.id, "aws_sts", s.secret_access_key, Some(s.expires_at), Some(reuse), digest, "mint")
                    .with_aws(keys)
            }
        };
        let issued = Arc::new(issued);
        cache.insert(digest, issued.clone());
        Ok((issued, false))
    }

    /// The base credentials of an STS issuer, read for each mint.
    async fn aws_base(&self, sts: &AwsSts) -> anyhow::Result<BaseCreds> {
        let reader = self.reader.clone();
        let refs = (sts.access_key_id.clone(), sts.secret_access_key.clone(), sts.session_token.clone());
        tokio::task::spawn_blocking(move || {
            Ok(BaseCreds {
                access_key_id: reader.read(&refs.0)?,
                secret_access_key: reader.read(&refs.1)?,
                session_token: refs.2.as_ref().map(|r| reader.read(r)).transpose()?,
            })
        })
        .await?
    }

    async fn app_key(&self, app: &GitHubApp) -> anyhow::Result<Arc<RsaKeyPair>> {
        if let Some(k) = self.keys.lock().map_err(|_| anyhow::anyhow!("key cache poisoned"))?.get(&app.name) {
            return Ok(k.clone());
        }
        let (reader, r) = (self.reader.clone(), app.key_ref.clone());
        let pem: Secret = tokio::task::spawn_blocking(move || reader.read(&r)).await??;
        let key = Arc::new(github_app::load_rsa_key(&pem)?);
        self.keys.lock().map_err(|_| anyhow::anyhow!("key cache poisoned"))?.insert(app.name.clone(), key.clone());
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuers::ApiEndpoint;
    use netguard::HostPattern;
    use policy::l7::SecretSource;
    use policy::{AttachSpec, CompileEnv, EgressPolicy, RepoId, SecretRef};

    struct MapReader(HashMap<String, Vec<u8>>);
    impl SecretReader for MapReader {
        fn read_raw(&self, src: &SecretSource) -> anyhow::Result<Secret> {
            let k = format!("{src:?}");
            self.0.get(&k).map(|v| Secret::new(v.clone())).ok_or_else(|| anyhow::anyhow!("missing"))
        }
    }

    struct CountingTransport(AtomicU64);
    #[async_trait::async_trait]
    impl Transport for CountingTransport {
        async fn post_json(
            &self,
            _: &ApiEndpoint,
            _: &str,
            _: &Secret,
            body: Vec<u8>,
        ) -> anyhow::Result<(u16, Vec<u8>)> {
            let n = self.0.fetch_add(1, Ordering::Relaxed);
            let v: serde_json::Value = serde_json::from_slice(&body)?;
            let perms = v["permissions"].clone();
            Ok((
                201,
                serde_json::to_vec(&serde_json::json!({
                    "token": format!("ghs_tok{n}"), "expires_at": "2099-01-01T00:00:00Z", "permissions": perms,
                }))?,
            ))
        }
    }

    fn policy_with(extra: &str) -> EgressPolicy {
        let text = format!(
            "version = 1\n[[egress]]\nhost = \"github.com\"\nid = \"git\"\nprotocol = \"git\"\n\
             allow = {{ push = {{ repo = \"${{repo_remote}}\", refs = [\"agent/*\"] }} }}\n{extra}"
        );
        let p = policy::config::parse_policy_str(&text).unwrap();
        let env = CompileEnv {
            repo_remote: RepoId::parse("github.com/acme/web"),
            github_app_issuers: ["acme".to_string()].into_iter().collect(),
            ..Default::default()
        };
        EgressPolicy::compile_with([("user", p.egress.as_slice())], &env).unwrap()
    }

    fn binding(p: &EgressPolicy, refname: &str) -> Option<AllowedBinding> {
        let adm = p.admit_host(&netguard::canon_host(b"github.com").unwrap(), 443).unwrap();
        let a = policy::Action::GitPush {
            repo: RepoId::parse("github.com/acme/web").unwrap(),
            refname: refname.into(),
            force: false,
            update: "t",
        };
        p.authorize_l7(&adm, &[a]).binding
    }

    fn session(p: &EgressPolicy, pem: Secret) -> (SessionCreds, Arc<CountingTransport>) {
        let mut m = HashMap::new();
        m.insert(format!("{:?}", SecretSource::Env("GH_KEY".into())), pem.expose().to_vec());
        let spec = policy::config::GitHubAppIssuerSpec {
            app_id: "1".into(),
            installation_id: "2".into(),
            private_key: "env:GH_KEY".into(),
            api_base: None,
            api_addrs: vec![],
        };
        let issuers: BTreeMap<_, _> = [("acme".to_string(), GitHubApp::from_spec("acme", &spec).unwrap())].into();
        let t = Arc::new(CountingTransport(AtomicU64::new(0)));
        (SessionCreds::new("sess-1", &p.credentials(), issuers, Arc::new(MapReader(m)), t.clone()), t)
    }

    #[tokio::test]
    async fn mints_once_per_scope_and_never_without_allow() {
        let p = policy_with(
            "credential = { kind = \"github_app\", issuer = \"acme\", permissions = { contents = \"write\" }, repos = [\"${repo_remote}\"], ttl = \"30m\" }\n",
        );
        let (s, t) = session(&p, crate::issuers::github_app::tests::test_key_pem());
        assert!(binding(&p, "refs/heads/main").is_none(), "denied request: no binding, so nothing to mint with");
        assert_eq!(s.mints.load(Ordering::Relaxed), 0);
        let b = binding(&p, "refs/heads/agent/x").unwrap();
        let (i1, reused1) = s.get(&b).await.unwrap();
        let (i2, reused2) = s.get(&b).await.unwrap();
        assert!(!reused1 && reused2);
        assert!(Arc::ptr_eq(&i1, &i2));
        assert_eq!(t.0.load(Ordering::Relaxed), 1, "one upstream mint for one scope");
        let reuse = i1.reuse_until.unwrap().duration_since(SystemTime::now()).unwrap();
        assert!(reuse <= Duration::from_secs(1800), "ttl bounds reuse");
    }

    #[tokio::test]
    async fn narrower_scope_gets_its_own_token() {
        let wide = policy_with(
            "credential = { kind = \"github_app\", issuer = \"acme\", permissions = { contents = \"write\" }, repos = [\"${repo_remote}\"] }\n",
        );
        let narrow = policy_with(
            "credential = { kind = \"github_app\", issuer = \"acme\", permissions = { contents = \"read\" }, repos = [\"${repo_remote}\"] }\n",
        );
        let issuers = BTreeMap::new();
        let dw = scope_digest(&wide.credentials()[0], &issuers, "s");
        let dn = scope_digest(&narrow.credentials()[0], &issuers, "s");
        assert_ne!(dw, dn);
        assert_ne!(dw, scope_digest(&wide.credentials()[0], &issuers, "other-session"));
        assert_eq!(dw, scope_digest(&wide.credentials()[0], &issuers, "s"));
    }

    #[tokio::test]
    async fn static_load_and_failures_name_no_secret() {
        let def = Arc::new(CredentialDef {
            id: "anthropic".into(),
            kind: CredKind::Static { secret: SecretRef::parse("env:KEY_SRC").unwrap() },
            attach: AttachSpec::Header { name: "x-api-key".into() },
            env: Some("ANTHROPIC_API_KEY".into()),
            swap_body: false,
            hosts: vec![HostPattern::parse("api.anthropic.com").unwrap()],
            ttl: None,
            high_risk: false,
        });
        let text = "version = 1\n[[egress]]\nhost = \"api.anthropic.com\"\n\
                    credential = { kind = \"static\", ref = \"env:KEY_SRC\", header = \"x-api-key\" }\n";
        let p = policy::config::parse_policy_str(text).unwrap();
        let pol = EgressPolicy::compile([("user", p.egress.as_slice())]).unwrap();
        let adm = pol.admit_host(&netguard::canon_host(b"api.anthropic.com").unwrap(), 443).unwrap();
        let b = pol
            .authorize_l7(&adm, &[policy::Action::Http { method: "POST".into(), path: "/v1/messages".into() }])
            .binding
            .unwrap();
        let mut m = HashMap::new();
        m.insert(format!("{:?}", SecretSource::Env("KEY_SRC".into())), b"sk-ant-CANARY".to_vec());
        let t = Arc::new(CountingTransport(AtomicU64::new(0)));
        let s = SessionCreds::new("s", &[def], BTreeMap::new(), Arc::new(MapReader(m)), t.clone());
        let (i, _) = s.get(&b).await.unwrap();
        assert_eq!(i.secret().expose(), b"sk-ant-CANARY");
        let empty = SessionCreds::new("s", &[], BTreeMap::new(), Arc::new(MapReader(HashMap::new())), t);
        let e = empty.get(&b).await.unwrap_err().to_string();
        assert!(e.contains("user:egress[0]") && !e.contains("CANARY"), "{e}");
    }
}
