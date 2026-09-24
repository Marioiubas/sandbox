//! Launch step: filesystem and network policy, the sandbox spec, the proxy
//! listener and the agent process. Split from `session.rs` to keep files
//! under 500 lines; any failure here refuses the launch.

use super::*;

impl Daemon {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn launch(
        self: &Arc<Self>,
        id: &SessionId,
        params: &StartParams,
        profile: &policy::ProfileFile,
        user_policy: &PolicyFile,
        egress: EgressPolicy,
        cwd: &Path,
        home: &Path,
        username: &str,
        session_dir: &Path,
        session_tmp: &Path,
        platform_tmp: Option<PathBuf>,
        stdio: [OwnedFd; 3],
        grants: Vec<String>,
        warnings: Vec<String>,
        shadow: Option<(String, Result<EgressPolicy, String>)>,
        identity: Option<grant::oidc::Identity>,
    ) -> Result<Running, StartFailure> {
        // Filesystem policy.
        let mut extra_write = Vec::new();
        for s in &profile.agent.state_write {
            let p = expand_profile_path(s, home, cwd);
            if !p.exists() {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&p)?;
            }
            extra_write.push(p);
        }
        for w in profile.filesystem.write.iter().chain(&user_policy.filesystem.write) {
            extra_write.push(expand_home(w, home));
        }
        let path_var = params.env.get("PATH").cloned();
        let fs = launcher::fs_compile::compile(&FsInputs {
            home: home.to_path_buf(),
            repo: repo_root(cwd),
            session_tmp: session_tmp.to_path_buf(),
            platform_tmp,
            extra_write,
            extra_deny_read: profile
                .filesystem
                .deny_read
                .iter()
                .chain(&user_policy.filesystem.deny_read)
                .map(|p| expand_home(p, home))
                .collect(),
            agent_config_readonly: profile.agent.config_readonly.iter().map(|p| expand_home(p, home)).collect(),
            path_dirs: path_var.as_deref().unwrap_or("").split(':').map(PathBuf::from).collect(),
            broker_dirs: self.dirs.all(),
            install_dir: self.shim.parent().map(Path::to_path_buf),
        })?;

        let faults = launcher::injected_faults();
        if faults.iter().any(|f| f == "proxy") {
            return Err("egress proxy listener unavailable (fault injected)".into());
        }
        // Data channel: per-session UDS on Linux, loopback port + sentinel on macOS.
        let (egress_ep, listener, auth, proxy_url, socks_url) = if cfg!(target_os = "linux") {
            let sock = session_dir.join("data.sock");
            let l = tokio::net::UnixListener::bind(&sock)?;
            let port = launcher::backends::linux::BRIDGE_PORT;
            (
                EgressEndpoint::Uds { path: sock, bridge_port: port },
                Listener::Unix(l),
                ChannelAuth::Implicit,
                format!("http://127.0.0.1:{port}"),
                format!("socks5h://127.0.0.1:{port}"),
            )
        } else {
            let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
            let port = l.local_addr()?.port();
            let sentinel = new_sentinel();
            (
                EgressEndpoint::Loopback(port),
                Listener::Tcp(l),
                ChannelAuth::Sentinel(sentinel.clone().into_bytes()),
                format!("http://broker:{sentinel}@127.0.0.1:{port}"),
                format!("socks5h://broker:{sentinel}@127.0.0.1:{port}"),
            )
        };

        // Environment: allowlist + proxy variables + sentinel; never the host env (I1).
        let mut env = BTreeMap::new();
        for (k, v) in &params.env {
            let allowed = ENV_ALLOW.contains(&k.as_str()) || profile.agent.env_passthrough.contains(k);
            if allowed && !policy::config::env_name_is_secretish(k) {
                env.insert(k.clone(), v.clone());
            }
        }
        env.insert("HOME".into(), home.display().to_string());
        env.insert("USER".into(), username.to_string());
        env.insert("LOGNAME".into(), username.to_string());
        env.insert("TMPDIR".into(), session_tmp.display().to_string());
        for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            env.insert(k.into(), proxy_url.clone());
        }
        for k in ["ALL_PROXY", "all_proxy"] {
            env.insert(k.into(), socks_url.clone());
        }
        env.insert("NODE_USE_ENV_PROXY".into(), "1".into());
        env.insert("BROKER_SESSION".into(), id.to_string());
        // SSH remotes become brokerable HTTPS (Git Smart-HTTP Adapter).
        env.insert("GIT_CONFIG_COUNT".into(), "2".into());
        env.insert("GIT_CONFIG_KEY_0".into(), "url.https://github.com/.insteadOf".into());
        env.insert("GIT_CONFIG_VALUE_0".into(), "git@github.com:".into());
        env.insert("GIT_CONFIG_KEY_1".into(), "url.https://github.com/.insteadof".into());
        env.insert("GIT_CONFIG_VALUE_1".into(), "ssh://git@github.com/".into());

        // M1: session CA, trust bundle and credential sentinels (never secrets).
        let channel_sentinel = match &auth {
            ChannelAuth::Sentinel(b) => Some(b.clone()),
            _ => None,
        };
        let l7 = crate::session_l7::setup(
            id,
            &egress,
            user_policy,
            &self.dirs,
            home,
            self.resolver.clone(),
            session_tmp,
            channel_sentinel,
        )
        .map_err(|e| format!("L7 setup: {e:#}"))?;
        for (k, v) in &l7.env {
            env.insert(k.clone(), v.clone());
        }

        let tty = tty_path(&stdio);
        let agent_path = resolve_command(&params.argv[0], path_var.as_deref(), cwd);
        let agent_sha = agent_path.as_deref().and_then(|p| self.hash_binary(p));
        let spec = SandboxSpec {
            session: id.to_string(),
            argv: params.argv.iter().map(Into::into).collect(),
            cwd: cwd.to_path_buf(),
            env,
            fs: fs.clone(),
            egress: egress_ep.clone(),
            ca_bundle: Some(l7.bundle.bundle_file.clone()),
            stdio,
            tty_path: tty,
            session_dir: session_dir.to_path_buf(),
            shim: self.shim.clone(),
        };

        // Start the data plane before the agent, so its first request has a
        // listener (I2); then launch, which verifies the layers from inside.
        let enduser = identity.as_ref().map(|i| i.subject.clone()).unwrap_or_else(|| format!("local:{username}"));
        let stats = Arc::new(Stats::default());
        let egress_mode = egress.mode().as_str();
        let ctx = Arc::new(PipelineCtx {
            session: id.clone(),
            enduser: enduser.clone(),
            agent: params.argv[0].clone(),
            sandbox: self.backend.name().to_string(),
            policy: Arc::new(egress),
            resolver: self.resolver.clone(),
            recorder: self.recorder.clone() as Arc<dyn Recorder>,
            auth,
            stats: stats.clone(),
            connect_timeout: Duration::from_secs(10),
            sni_timeout: Duration::from_secs(15),
            l7: Some(l7.ctx.clone()),
            shadow: shadow.as_ref().and_then(|(_, r)| r.as_ref().ok()).map(|p| Arc::new(p.clone())),
            // Only agent sessions reach pinned servers; a server session never does.
            mcp: (!user_policy.mcp.is_empty() && !profile.name.starts_with("mcp:")).then(|| {
                Arc::new(crate::mcp::McpCtx {
                    daemon: Arc::downgrade(self),
                    user: user_policy.clone(),
                    dirs: self.dirs.clone(),
                })
            }),
        });
        // Write-ahead (I9): the session is on record before the agent can run;
        // if the log cannot take it, the agent never starts (I2).
        let egress_desc = match &egress_ep {
            EgressEndpoint::Uds { path, bridge_port } => format!("uds {} via 127.0.0.1:{bridge_port}", path.display()),
            EgressEndpoint::Loopback(p) => format!("loopback 127.0.0.1:{p} (sentinel-authenticated)"),
            EgressEndpoint::Vsock(c, p) => format!("vsock {c}:{p}"),
        };
        let probe_layers = self.backend.probe().map(|r| r.layers).unwrap_or_default();
        let mut ev = AuditEvent::new(EventKind::SessionStart)
            .session(id)
            .detail("profile", profile.name.as_str())
            .detail(
                "identity",
                match &identity {
                    Some(i) => serde_json::json!({ "issuer": i.issuer, "subject": i.subject, "claims": i.claims }),
                    None => serde_json::json!({ "issuer": "local", "subject": enduser }),
                },
            )
            .detail("mode", egress_mode)
            .detail("argv0", params.argv[0].as_str())
            .detail("cwd", cwd.display().to_string())
            .detail("egress", egress_desc.as_str())
            .detail("grants", grants.clone())
            .detail("writable", fs.writable.iter().map(|p| p.display().to_string()).collect::<Vec<_>>())
            .detail("layers", serde_json::to_value(&probe_layers).unwrap_or_default())
            .detail("credentials", l7.credentials.clone())
            .detail("trust_bundle", tls::trust_bundle::describe(&l7.bundle));
        if let Some((sha, r)) = &shadow {
            ev = ev.detail("shadow", serde_json::json!({ "candidate": sha, "error": r.as_ref().err() }));
        }
        ev.enduser = Some(enduser.clone());
        ev.agent = Some(params.argv[0].clone());
        ev.agent_sha256 = agent_sha;
        ev.sandbox = Some(self.backend.name().to_string());
        ev.task = Some(format!("task-{}", id));
        if faults.iter().any(|f| f == "audit") || self.recorder.append(&ev).is_err() {
            return Err(StartFailure {
                message: "audit log unavailable; the session was not started".into(),
                layers: probe_layers,
            });
        }

        let accept = tokio::spawn(accept_loop(listener, ctx));
        let backend = self.backend.clone();
        let launched = tokio::task::spawn_blocking(move || backend.launch(spec)).await;
        let handle = match launched {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                accept.abort();
                let layers = match e.downcast_ref::<launcher::LaunchError>() {
                    Some(le) if !le.layers.is_empty() => le.layers.clone(),
                    _ => self.backend.probe().map(|r| r.layers).unwrap_or_default(),
                };
                return Err(StartFailure { message: format!("{e:#}"), layers });
            }
            Err(e) => {
                accept.abort();
                return Err(StartFailure { message: format!("launcher task failed: {e}"), layers: vec![] });
            }
        };

        // The layers as verified from inside the sandbox by the shim.
        let mut ready = AuditEvent::new(EventKind::SessionReady)
            .session(id)
            .detail("layers", serde_json::to_value(&handle.verified).unwrap_or_default());
        ready.enduser = Some(enduser.clone());
        ready.agent = Some(params.argv[0].clone());
        ready.sandbox = Some(self.backend.name().to_string());
        if self.recorder.append(&ready).is_err() {
            // I9: no audit, no session.
            let mut child = handle.child;
            unsafe { libc::kill(-(handle.pid as i32), libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
            accept.abort();
            return Err(StartFailure { message: "audit log unavailable".into(), layers: handle.verified });
        }
        if let Ok(mut s) = self.sessions.lock() {
            s.insert(id.to_string(), handle.pid);
        }
        let result = StartResult {
            session_id: id.to_string(),
            backend: self.backend.name().to_string(),
            profile: profile.name.clone(),
            egress: egress_desc,
            grants,
            layers: handle.verified.clone(),
            warnings,
        };
        Ok(Running {
            id: id.clone(),
            result,
            pid: handle.pid,
            child: Some(handle.child),
            accept,
            session_dir: session_dir.to_path_buf(),
            session_tmp: session_tmp.to_path_buf(),
            placeholders: handle.placeholders,
            stats,
            recorder: self.recorder.clone(),
            backend_name: self.backend.name().to_string(),
            agent: params.argv[0].clone(),
            enduser,
        })
    }
}
