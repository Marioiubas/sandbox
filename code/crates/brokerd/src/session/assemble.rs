//! The session's policy layers: the built-in profile, the user's policy,
//! the approved repository policy (conjoined so it only narrows: I4, I5)
//! and, in shadow mode, the candidate evaluated beside them.

use super::{Daemon, StartFailure, TASK_LIFETIME_SECS};
use crate::profiles;
use crate::proto::StartParams;
use crate::session_util::*;
use audit::SessionId;
use policy::{EgressPolicy, PolicyFile, ProfileFile};
use std::path::Path;

pub(super) struct Assembled {
    pub profile: ProfileFile,
    pub user_policy: PolicyFile,
    pub egress: EgressPolicy,
    /// Shadow mode: the candidate's digest and compiled policy (or why not).
    pub shadow: Option<(String, Result<EgressPolicy, String>)>,
    pub grants: Vec<String>,
    pub warnings: Vec<String>,
    /// A verified identity token's identity (CI), if one was given.
    pub identity: Option<grant::oidc::Identity>,
}

impl Daemon {
    pub(super) fn assemble_policy(
        &self,
        id: &SessionId,
        params: &StartParams,
        cwd: &Path,
        username: &str,
        identity: Option<grant::oidc::Identity>,
    ) -> Result<Assembled, StartFailure> {
        let profile = match &params.profile {
            Some(p) => profiles::by_name(p)?,
            None => profiles::detect(&params.argv[0])?,
        };
        let user_policy = load_user_policy(&self.dirs)?;
        let mut a = self.assemble_layers(id, params, cwd, username, profile, user_policy, true, identity.as_ref())?;
        a.identity = identity;
        Ok(a)
    }

    /// The layers for a given profile and user policy. `agent` sessions
    /// get shadow candidates and their pinned MCP servers' call permits;
    /// an MCP server's own session gets neither.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn assemble_layers(
        &self,
        id: &SessionId,
        params: &StartParams,
        cwd: &Path,
        username: &str,
        profile: ProfileFile,
        user_policy: PolicyFile,
        agent: bool,
        identity: Option<&grant::oidc::Identity>,
    ) -> Result<Assembled, StartFailure> {
        let scope = format!("profile:{}", profile.name);
        // `${repo_remote}` comes from the checkout's own config file, read
        // without running git; unresolved, rules that use it grant nothing.
        let repo_remote = origin_remote(&repo_root(cwd));
        let mut mode = match params.mode.as_deref() {
            None | Some("enforce") => policy::cedar::Mode::Enforce,
            Some("record") => policy::cedar::Mode::Record,
            Some(m) => return Err(format!("unknown session mode {m:?}").into()),
        };
        // Shadow mode: an active candidate is evaluated beside the enforced
        // policy in enforce sessions (never in record mode).
        let candidate = match crate::shadow::load(&self.dirs) {
            Ok(c) => c.filter(|_| agent),
            Err(e) => return Err(format!("shadow candidate: {e:#}").into()),
        };
        if candidate.is_some() && mode == policy::cedar::Mode::Enforce {
            mode = policy::cedar::Mode::Shadow;
        }
        let agent_path = resolve_command(&params.argv[0], params.env.get("PATH").map(String::as_str), cwd);
        let agent_base = std::path::Path::new(&params.argv[0])
            .file_name()
            .map(|b| b.to_string_lossy().into_owned())
            .unwrap_or_else(|| params.argv[0].clone());
        // The principal of every decision: the Task, carrying user and agent.
        let session_info = policy::cedar::SessionInfo {
            session_id: id.to_string(),
            task_id: format!("task-{id}"),
            user: identity.map(|i| i.subject.clone()).unwrap_or_else(|| format!("local:{username}")),
            idp: identity.map(|i| i.issuer.clone()).unwrap_or_else(|| "local".into()),
            agent: agent_base,
            agent_sha256: agent_path.as_deref().and_then(|p| self.hash_binary(p)).unwrap_or_default(),
            repo: repo_remote.as_ref().map(|r| format!("{}/{}", r.owner(), r.name())).unwrap_or_default(),
            branch_prefix: "agent/".into(),
            expires_at: policy::cedar::entities::now_epoch() + TASK_LIFETIME_SECS,
            mode,
        };
        let compile_env = policy::CompileEnv {
            repo_remote,
            github_app_issuers: user_policy.issuers.github_app.keys().cloned().collect(),
            aws_sts_issuers: user_policy.issuers.aws_sts.keys().cloned().collect(),
            session: session_info,
        };
        let mut egress = EgressPolicy::compile_with(
            [(scope.as_str(), profile.egress.as_slice()), ("user", user_policy.egress.as_slice())],
            &compile_env,
        )?
        .with_mcp(&user_policy.mcp)?;
        // Repository policy: read here on the host, used only if its exact
        // content was approved, and conjoined so it can only narrow (I4, I5).
        let repo_status =
            crate::repo_policy::status(&self.dirs, &repo_root(cwd)).map_err(|e| format!("repository policy: {e:#}"))?;
        if let crate::repo_policy::Status::Approved { toml, cedar, .. } = &repo_status {
            let entries = toml.as_ref().map(|t| t.egress.clone()).unwrap_or_default();
            egress = egress
                .with_repo_layer(&entries, cedar.as_deref(), &compile_env)
                .map_err(|e| format!("approved repository policy does not compile: {e}"))?;
        }
        let shadow = candidate.filter(|_| mode == policy::cedar::Mode::Shadow).map(|(sha, file)| {
            let compiled = EgressPolicy::compile_with(
                [(scope.as_str(), profile.egress.as_slice()), ("candidate", file.egress.as_slice())],
                &compile_env,
            )
            .map_err(|e| e.to_string())
            .and_then(|p| match &repo_status {
                crate::repo_policy::Status::Approved { toml, cedar, .. } => {
                    let entries = toml.as_ref().map(|t| t.egress.clone()).unwrap_or_default();
                    p.with_repo_layer(&entries, cedar.as_deref(), &compile_env).map_err(|e| e.to_string())
                }
                _ => Ok(p),
            })
            // One session, one set of labels: the candidate sees what the policy sees.
            .map(|p| p.with_labels(egress.labels().clone()));
            (sha, compiled)
        });
        let mut grants: Vec<String> =
            egress.grants().iter().map(|g| format!("{} {}:{:?}", g.id, g.pattern, g.ports)).collect();
        if repo_status != crate::repo_policy::Status::Absent {
            grants.push(format!("repo policy: {}", repo_status.describe()));
        }
        let mut warnings = Vec::new();
        match &shadow {
            Some((sha, Ok(_))) => warnings.push(format!(
                "shadow mode: candidate {sha} is evaluated and logged beside your policy; it decides nothing"
            )),
            Some((sha, Err(e))) => {
                warnings.push(format!("shadow mode: candidate {sha} does not compile ({e}); it is not evaluated"))
            }
            None => {}
        }
        if egress.is_empty() {
            warnings.push("no egress grants: every network request will be denied (empty lists deny)".into());
        }
        if let crate::repo_policy::Status::Unapproved { sha256 } = &repo_status {
            warnings.push(format!(
                "repository policy in .broker/ is not approved ({sha256}); it is ignored until you run `broker policy approve`"
            ));
        }
        if compile_env.repo_remote.is_none()
            && egress.credentials().iter().any(|c| matches!(c.kind, policy::CredKind::GitHubApp { .. }))
        {
            warnings.push("no origin remote found: rules using ${repo_remote} grant nothing in this session".into());
        }
        Ok(Assembled { profile, user_policy, egress, shadow, grants, warnings, identity: None })
    }
}
