//! M1 fixtures: fake HTTPS upstreams that the broker reaches over verified
//! TLS (a test CA handed to it as `[tls] extra_roots`), a fake LLM/echo API
//! that accepts only the real canary key, and a fake GitHub serving smart
//! HTTP through `git http-backend` plus an app installation-token endpoint
//! that verifies the RS256 app JWT.
//!
//! Every secret here is a canary generated for the test run; no real
//! credential is involved.

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A CA for fake upstreams. The broker trusts it through `extra_roots`;
/// the host trust store is never touched.
pub struct TestCa {
    pub ca: tls::session_ca::SessionCa,
    pub pem_path: PathBuf,
}

impl TestCa {
    pub fn new(dir: &Path) -> TestCa {
        let ca = tls::session_ca::SessionCa::new("conformance-upstream").unwrap();
        let pem_path = dir.join("test-upstream-ca.pem");
        std::fs::write(&pem_path, ca.ca_pem()).unwrap();
        TestCa { ca, pem_path }
    }
}

/// A request as the fake upstream saw it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    /// Everything the upstream received, for "did X ever arrive" checks.
    pub fn dump(&self) -> String {
        let mut s = format!("{} {}?{}\n", self.method, self.path, self.query.as_deref().unwrap_or(""));
        for (k, v) in &self.headers {
            s.push_str(&format!("{k}: {v}\n"));
        }
        s.push_str(&String::from_utf8_lossy(&self.body));
        s
    }
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Reply {
        Reply { status, headers: vec![], body: body.into() }
    }
    pub fn header(mut self, k: &str, v: &str) -> Reply {
        self.headers.push((k.into(), v.into()));
        self
    }
}

pub type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

pub struct HttpsServer {
    pub port: u16,
    pub host: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl HttpsServer {
    /// Serve `host` (the certificate's only name) on a loopback port.
    pub fn start(ca: &TestCa, host: &str, handler: Handler) -> HttpsServer {
        let std_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_l.set_nonblocking(true).unwrap();
        let port = std_l.local_addr().unwrap().port();
        let cfg = ca.ca.server_config(&netguard::canon_host(host.as_bytes()).unwrap()).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
            rt.block_on(async move {
                let l = tokio::net::TcpListener::from_std(std_l).unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                loop {
                    let Ok((s, _)) = l.accept().await else { continue };
                    let (acceptor, handler, seen) = (acceptor.clone(), handler.clone(), seen2.clone());
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(s).await else { return };
                        let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                            let (handler, seen) = (handler.clone(), seen.clone());
                            async move {
                                let (parts, body) = req.into_parts();
                                let body = body.collect().await.map(|c| c.to_bytes().to_vec()).unwrap_or_default();
                                let s = Seen {
                                    method: parts.method.to_string(),
                                    path: parts.uri.path().to_string(),
                                    query: parts.uri.query().map(str::to_string),
                                    headers: parts
                                        .headers
                                        .iter()
                                        .map(|(k, v)| {
                                            (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned())
                                        })
                                        .collect(),
                                    body,
                                };
                                seen.lock().unwrap().push(s.clone());
                                let r = tokio::task::spawn_blocking(move || handler(&s)).await.unwrap();
                                let mut resp = hyper::Response::new(Full::new(Bytes::from(r.body)));
                                *resp.status_mut() = hyper::StatusCode::from_u16(r.status).unwrap();
                                for (k, v) in r.headers {
                                    resp.headers_mut().append(
                                        http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                                        http::HeaderValue::from_str(&v).unwrap(),
                                    );
                                }
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        });
                        let _ =
                            hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), svc).await;
                    });
                }
            });
        });
        HttpsServer { port, host: host.to_string(), seen }
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Whether `needle` ever reached this upstream in any form it logged.
    pub fn received(&self, needle: &str) -> bool {
        self.seen().iter().any(|s| s.dump().contains(needle))
    }
}

fn gzip(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The fake LLM/echo API. Only requests carrying `key` in `x-api-key`
/// succeed on `/v1/messages`; the echo routes reflect what they received.
pub fn api_handler(key: String) -> Handler {
    Arc::new(move |s: &Seen| {
        let echo = || s.headers.iter().map(|(k, v)| format!("{k}: {v}\n")).collect::<String>();
        match s.path.as_str() {
            "/v1/messages" => {
                if s.header("x-api-key") == Some(key.as_str()) {
                    Reply::new(200, r#"{"type":"message","ok":true}"#)
                } else {
                    Reply::new(401, r#"{"type":"error","error":"invalid x-api-key"}"#)
                }
            }
            "/echo" => Reply::new(200, echo()),
            "/echo-gzip" => Reply::new(200, gzip(echo().as_bytes())).header("content-encoding", "gzip"),
            "/echo-header" => Reply::new(200, "header echo\n").header("x-echo", s.header("x-api-key").unwrap_or("-")),
            "/cookie" => Reply::new(200, "cookie set\n").header("set-cookie", "sid=planted; Path=/"),
            "/redirect" => {
                let to = s.query.as_deref().and_then(|q| q.strip_prefix("to=")).map(percent_decode).unwrap_or_default();
                Reply::new(302, "").header("location", &to)
            }
            _ => Reply::new(200, "plain\n"),
        }
    })
}

/// A throwaway RSA key for the fake GitHub App (generated per test run).
pub fn rsa_key_pem() -> Vec<u8> {
    let out = Command::new("openssl").args(["genrsa", "2048"]).output().expect("openssl on PATH");
    assert!(out.status.success(), "openssl genrsa failed");
    out.stdout
}

pub const APP_ID: u64 = 1234;
pub const INSTALLATION: &str = "7";

pub struct FakeGitHub {
    pub server: HttpsServer,
    pub root: tempfile::TempDir,
    pub key_pem: Vec<u8>,
    /// Token requests as received: `{"repositories": [...], "permissions": {...}}`.
    pub mints: Arc<Mutex<Vec<serde_json::Value>>>,
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .expect("git on PATH");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn host_git(dir: &Path, args: &[&str]) -> String {
    git(dir, args)
}

fn verify_jwt(jwt: &str, public_key: &[u8]) -> bool {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let dec = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok();
    let (Some(h), Some(c), Some(sig)) = (dec(parts[0]), dec(parts[1]), dec(parts[2])) else { return false };
    let h: serde_json::Value = serde_json::from_slice(&h).unwrap_or_default();
    let c: serde_json::Value = serde_json::from_slice(&c).unwrap_or_default();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let pk = ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, public_key);
    h["alg"] == "RS256"
        && c["iss"] == APP_ID
        && c["exp"].as_u64().is_some_and(|e| e > now && e <= now + 600)
        && pk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).is_ok()
}

fn cgi(root: &Path, s: &Seen) -> Reply {
    let mut c = Command::new("git");
    c.arg("http-backend")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_PROJECT_ROOT", root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REMOTE_USER", "x-access-token")
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("REQUEST_METHOD", &s.method)
        .env("PATH_INFO", &s.path)
        .env("QUERY_STRING", s.query.as_deref().unwrap_or(""))
        .env("CONTENT_TYPE", s.header("content-type").unwrap_or(""))
        .env("CONTENT_LENGTH", s.body.len().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(p) = s.header("git-protocol") {
        c.env("GIT_PROTOCOL", p);
    }
    if let Some(e) = s.header("content-encoding") {
        c.env("HTTP_CONTENT_ENCODING", e);
    }
    let mut child = c.spawn().expect("git http-backend");
    child.stdin.take().unwrap().write_all(&s.body).unwrap();
    let out = child.wait_with_output().unwrap();
    let raw = out.stdout;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2)));
    let Some((i, n)) = split else { return Reply::new(500, "bad CGI output") };
    let head = String::from_utf8_lossy(&raw[..i]).to_string();
    let mut r = Reply::new(200, raw[i + n..].to_vec());
    for line in head.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        if k.eq_ignore_ascii_case("status") {
            r.status = v.split_whitespace().next().and_then(|c| c.parse().ok()).unwrap_or(500);
        } else {
            r.headers.push((k.trim().to_string(), v.to_string()));
        }
    }
    r
}

impl FakeGitHub {
    pub fn start(ca: &TestCa, host: &str) -> FakeGitHub {
        let root = tempfile::Builder::new().prefix("bkgh.").tempdir_in("/tmp").unwrap();
        let key_pem = rsa_key_pem();
        let key = creds::issuers::github_app::load_rsa_key(&creds::Secret::new(key_pem.clone())).unwrap();
        use ring::signature::KeyPair;
        let public = key.public_key().as_ref().to_vec();
        let tokens: Arc<Mutex<HashMap<String, Vec<String>>>> = Arc::default();
        let mints: Arc<Mutex<Vec<serde_json::Value>>> = Arc::default();
        let (rootp, m2) = (root.path().to_path_buf(), mints.clone());
        let handler: Handler = Arc::new(move |s: &Seen| {
            if s.method == "POST" && s.path == format!("/app/installations/{INSTALLATION}/access_tokens") {
                let jwt = s.header("authorization").and_then(|a| a.strip_prefix("Bearer ")).unwrap_or("");
                if !verify_jwt(jwt, &public) {
                    return Reply::new(401, r#"{"message":"A JSON web token could not be decoded"}"#);
                }
                let req: serde_json::Value = serde_json::from_slice(&s.body).unwrap_or_default();
                m2.lock().unwrap().push(req.clone());
                let repos: Vec<String> = req["repositories"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                let mut b = [0u8; 16];
                getrandom::fill(&mut b).unwrap();
                let token = format!("ghs_fake{}", hex::encode(b));
                tokens.lock().unwrap().insert(token.clone(), repos.clone());
                let exp = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
                let body = serde_json::json!({
                    "token": token,
                    "expires_at": exp.format(&time::format_description::well_known::Rfc3339).unwrap(),
                    "permissions": req["permissions"],
                    "repository_selection": "selected",
                    "repositories": repos.iter().map(|r| serde_json::json!({"name": r})).collect::<Vec<_>>(),
                });
                return Reply::new(201, body.to_string()).header("content-type", "application/json");
            }
            // Smart HTTP: /owner/name.git/...
            let segs: Vec<&str> = s.path.trim_start_matches('/').splitn(3, '/').collect();
            let repo = segs.get(1).map(|r| r.trim_end_matches(".git").to_string()).unwrap_or_default();
            let authed = s
                .header("authorization")
                .and_then(|a| a.strip_prefix("Basic "))
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
                .and_then(|d| String::from_utf8(d).ok())
                .and_then(|d| d.strip_prefix("x-access-token:").map(str::to_string))
                .is_some_and(|t| tokens.lock().unwrap().get(&t).is_some_and(|rs| rs.contains(&repo)));
            if !authed {
                return Reply::new(401, "authentication required\n").header("www-authenticate", "Basic realm=\"fake\"");
            }
            let mut r = cgi(&rootp, s);
            if r.status == 0 {
                r.status = 500;
            }
            r
        });
        let server = HttpsServer::start(ca, host, handler);
        FakeGitHub { server, root, key_pem, mints }
    }

    /// A bare repository `owner/name.git` with one commit on `main` and
    /// the same commit on `agent/base`.
    pub fn create_repo(&self, owner: &str, name: &str) -> PathBuf {
        let bare = self.root.path().join(owner).join(format!("{name}.git"));
        std::fs::create_dir_all(&bare).unwrap();
        git(&bare, &["init", "-q", "--bare", "-b", "main"]);
        let work = tempfile::tempdir().unwrap();
        git(work.path(), &["init", "-q", "-b", "main"]);
        std::fs::write(work.path().join("README.md"), format!("{owner}/{name}\n")).unwrap();
        git(work.path(), &["add", "README.md"]);
        git(work.path(), &["commit", "-q", "-m", "initial"]);
        git(work.path(), &["push", "-q", &bare.display().to_string(), "main", "main:refs/heads/agent/base"]);
        bare
    }

    pub fn url(&self, owner: &str, name: &str) -> String {
        format!("https://{}:{}/{owner}/{name}.git", self.server.host, self.server.port)
    }

    /// `git rev-parse <rev>` in a bare repository, or None if absent.
    pub fn rev(&self, owner: &str, name: &str, rev: &str) -> Option<String> {
        let bare = self.root.path().join(owner).join(format!("{name}.git"));
        let out = Command::new("git")
            .args(["rev-parse", "--verify", "-q", rev])
            .current_dir(bare)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

/// Grant TOML for a fake upstream pinned to loopback.
pub fn loopback_grant(id: &str, host: &str, port: u16, extra: &str) -> String {
    format!(
        "[[egress]]\nid = \"{id}\"\nhost = \"{host}\"\nports = [{port}]\naddrs = [\"127.0.0.1\"]\nallow_addr_classes = [\"loopback\"]\n{extra}\n"
    )
}

/// A canary secret: recognisable, random per run, never a real credential.
pub fn canary(prefix: &str) -> String {
    let mut b = [0u8; 12];
    getrandom::fill(&mut b).unwrap();
    format!("{prefix}-CANARY-{}", hex::encode(b))
}

pub fn wait_for<T>(timeout: Duration, mut f: impl FnMut() -> Option<T>) -> Option<T> {
    let start = std::time::Instant::now();
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if start.elapsed() > timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
