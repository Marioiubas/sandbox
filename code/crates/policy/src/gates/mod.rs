//! Formal policy gates (SymCC CI Gates, eval layer L5) on
//! `cedar-policy-symcc` with the cvc5 solver. Every gate is checked over
//! each request environment of the Broker schema it applies to; a failed
//! gate carries the synthesized counterexample request.
//!
//! Hard gates (a failure blocks; there is no override): ceiling, credential
//! confinement, never-errors, deny rules live, repository layer narrows.
//! The narrowing gate is soft: a widening is a request for human approval,
//! shown as the requests it newly permits (the "expansion delta").
//!
//! A proof covers the policy text relative to the schema. It does not prove
//! that the enforcement point turns hosts, paths and refs into the right
//! entities; the conformance suite tests that.

mod compose;
#[cfg(test)]
mod tests;

pub use compose::conjoin;

use crate::cedar::{CEILING_POLICIES, compile::lit, schema};
use crate::egress::EgressPolicy;
use cedar_policy::{ActionConstraint, Effect, Entities, EvalResult, Policy, PolicyId, PolicySet, RequestEnv};
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicy, CompiledPolicySet, Env, solver::LocalSolver};
use netguard::HostPattern;
use serde::Serialize;
use std::str::FromStr;

/// A brokered credential and the hosts it may be used for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredSpec {
    pub id: String,
    pub hosts: Vec<String>,
    pub domains: Vec<String>,
}

/// A complete base policy set as the daemon evaluates it, plus its
/// credentials (for the confinement gate).
#[derive(Clone, Debug)]
pub struct Bundle {
    pub set: PolicySet,
    pub credentials: Vec<CredSpec>,
    /// Permits that may allow a forced push: push rules with `force = true`,
    /// and plain host grants (their traffic is spliced, not inspected).
    pub force_opt_ins: Vec<String>,
}

impl Bundle {
    pub fn from_egress(p: &EgressPolicy) -> Bundle {
        let credentials = p
            .credentials()
            .iter()
            .map(|c| {
                let (mut hosts, mut domains) = (vec![], vec![]);
                for h in &c.hosts {
                    match h {
                        HostPattern::Exact(h) => hosts.push(h.as_str().to_string()),
                        HostPattern::Subdomains(b) => domains.push(b.as_str().to_string()),
                    }
                }
                CredSpec { id: c.id.clone(), hosts, domains }
            })
            .collect();
        let force_opt_ins = p
            .grants()
            .iter()
            .flat_map(|g| match g.l7.as_deref() {
                None => vec![format!("{}#any", g.id)],
                Some(r) => r
                    .push_rules()
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| r.force)
                    .map(|(k, _)| format!("{}#{}", g.id, crate::cedar::compile::push_suffix(k)))
                    .collect(),
            })
            .collect();
        Bundle { set: p.engine().base().clone(), credentials, force_opt_ins }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Gate {
    NeverErrors,
    Ceiling,
    CredentialConfinement,
    DenyLive,
    RepoNarrows,
    Narrowing,
}

impl Gate {
    pub const ALL: [Gate; 6] = [
        Gate::Ceiling,
        Gate::CredentialConfinement,
        Gate::NeverErrors,
        Gate::DenyLive,
        Gate::RepoNarrows,
        Gate::Narrowing,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Gate::NeverErrors => "never-errors",
            Gate::Ceiling => "ceiling",
            Gate::CredentialConfinement => "credential-confinement",
            Gate::DenyLive => "deny-live",
            Gate::RepoNarrows => "repo-narrows",
            Gate::Narrowing => "narrowing",
        }
    }

    /// Hard gates block with no override; narrowing asks for approval.
    pub fn hard(self) -> bool {
        self != Gate::Narrowing
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    Proved,
    Failed { counterexample: String },
    NotApplicable { why: String },
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub gate: Gate,
    /// What was checked (a policy ID, credential ID or action).
    pub subject: String,
    /// The request environment (action and resource type).
    pub env: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub solver: String,
    pub envs: usize,
    pub queries: usize,
    pub millis: u128,
    pub findings: Vec<Finding>,
}

impl Report {
    fn push(&mut self, gate: Gate, subject: impl Into<String>, env: impl Into<String>, outcome: Outcome) {
        self.findings.push(Finding { gate, subject: subject.into(), env: env.into(), outcome });
    }

    fn failed(&self, g: Gate) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(move |f| f.gate == g && matches!(f.outcome, Outcome::Failed { .. }))
    }

    pub fn hard_failures(&self) -> Vec<&Finding> {
        Gate::ALL.iter().filter(|g| g.hard()).flat_map(|g| self.failed(*g)).collect()
    }

    pub fn widenings(&self) -> Vec<&Finding> {
        self.failed(Gate::Narrowing).collect()
    }

    /// One line per gate: proved, failed (count) or not applicable.
    pub fn summary(&self) -> String {
        let mut out = Vec::new();
        for g in Gate::ALL {
            let of: Vec<&Finding> = self.findings.iter().filter(|f| f.gate == g).collect();
            let failed = of.iter().filter(|f| matches!(f.outcome, Outcome::Failed { .. })).count();
            let na = of.iter().find_map(|f| match &f.outcome {
                Outcome::NotApplicable { why } => Some(why.clone()),
                _ => None,
            });
            let state = match (failed, na, of.is_empty()) {
                (0, Some(why), _) => format!("not applicable ({why})"),
                (0, None, true) => "not applicable".to_string(),
                (0, None, false) => format!("proved ({} checks)", of.len()),
                (n, _, _) if g == Gate::Narrowing => format!("widens: {n} counterexample(s); human approval required"),
                (n, _, _) => format!("FAILED: {n} counterexample(s)"),
            };
            out.push(format!("{:<23} {state}", g.name()));
        }
        out.join("\n")
    }

    /// The summary plus every counterexample.
    pub fn render(&self) -> String {
        let mut s = self.summary();
        for f in self.findings.iter() {
            if let Outcome::Failed { counterexample } = &f.outcome {
                let what = if f.gate == Gate::Narrowing { "newly permits" } else { "counterexample" };
                s.push_str(&format!("\n{} [{}] {} {what}: {counterexample}", f.gate.name(), f.env, f.subject));
            }
        }
        s
    }
}

/// What to check. `old` enables the narrowing gate; `repo` the I4 gate.
pub struct Inputs<'a> {
    pub new: &'a Bundle,
    pub old: Option<&'a Bundle>,
    pub repo: Option<&'a PolicySet>,
}

/// The solver's version line, or why it cannot be run. The solver is the
/// `CVC5` environment variable, else `cvc5` on `PATH` (as `LocalSolver`).
pub fn solver_version() -> Result<String, String> {
    let path = std::env::var("CVC5").unwrap_or_else(|_| "cvc5".into());
    let out = std::process::Command::new(&path)
        .arg("--version")
        .output()
        .map_err(|e| format!("cvc5 not runnable ({path}): {e}; set CVC5 to a cvc5 1.3.1 binary"))?;
    let v = String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or("").to_string();
    if !out.status.success() || !v.contains("cvc5 version") {
        return Err(format!("{path} is not cvc5"));
    }
    Ok(v)
}

/// Run every applicable gate.
pub fn check(inputs: &Inputs) -> anyhow::Result<Report> {
    let solver = solver_version().map_err(|e| anyhow::anyhow!(e))?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let started = std::time::Instant::now();
    let mut r = rt.block_on(run(inputs))?;
    r.solver = solver;
    r.millis = started.elapsed().as_millis();
    Ok(r)
}

fn parse_set(src: &str) -> anyhow::Result<PolicySet> {
    let parsed = PolicySet::from_str(src).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut set = PolicySet::new();
    for (i, p) in parsed.policies().enumerate() {
        let id = p.annotation("id").map(str::to_string).unwrap_or_else(|| format!("p{i}"));
        set.add(p.new_id(PolicyId::new(id)))?;
    }
    Ok(set)
}

fn env_name(env: &RequestEnv) -> String {
    format!("{} on {}", env.action(), env.resource())
}

fn action_is(env: &RequestEnv, name: &str) -> bool {
    env.action().id().unescaped() == name
}

/// May the policy's action scope match this environment's action?
fn applies(p: &Policy, env: &RequestEnv, actions: &Entities) -> bool {
    let a = env.action();
    match p.action_constraint() {
        ActionConstraint::Any => true,
        ActionConstraint::Eq(u) => &u == a,
        ActionConstraint::In(us) => {
            us.iter().any(|u| u == a) || actions.ancestors(a).is_some_and(|mut anc| anc.any(|x| us.contains(x)))
        }
    }
}

/// A counterexample as one line: the action, the resource and the context
/// fields a reviewer needs (a path is shown as its first `n` segments; the
/// solver fills unused optional segments arbitrarily).
pub fn render_cex(env: &Env) -> String {
    let r = &env.request;
    let action = r.action().map(|a| a.id().unescaped().to_string()).unwrap_or_else(|| "?".into());
    let resource = r.resource().map(|u| u.to_string()).unwrap_or_else(|| "?".into());
    let mut parts = vec![format!("{action} on {resource}")];
    let Some(ctx) = r.context() else { return parts.remove(0) };
    if let Some(EvalResult::Record(p)) = ctx.get("path") {
        let n = match p.get("n") {
            Some(EvalResult::Long(n)) => *n,
            _ => 0,
        };
        let segs: Vec<String> = (0..n.clamp(0, 16))
            .map(|i| match p.get(format!("s{i}")) {
                Some(EvalResult::String(s)) => s.clone(),
                _ => "?".into(),
            })
            .collect();
        parts.push(format!("path /{}{}", segs.join("/"), if n > 16 { "/**" } else { "" }));
    }
    for k in ["dest_host", "ref", "force", "port", "tool"] {
        if let Some(v) = ctx.get(k) {
            parts.push(format!("{k} {v}"));
        }
    }
    if let Some(EvalResult::Record(sess)) = ctx.get("session") {
        for k in ["mode", "approved"] {
            if let Some(v) = sess.get(k) {
                parts.push(format!("session.{k} {v}"));
            }
        }
    }
    parts.join(", ")
}

async fn run(inputs: &Inputs<'_>) -> anyhow::Result<Report> {
    let s = schema();
    let actions = s.action_entities()?;
    let mut sym = CedarSymCompiler::new(LocalSolver::cvc5()?)?;
    let mut rep = Report::default();
    let ceiling = {
        let mut c = parse_set(CEILING_POLICIES)?;
        c.add(Policy::parse(Some(PolicyId::new("ceiling#permit-all")), "permit (principal, action, resource);")?)?;
        c
    };
    let composed = match inputs.repo {
        Some(repo) => Some(conjoin(&inputs.new.set, repo).map_err(|e| anyhow::anyhow!(e))?),
        None => None,
    };
    let deny_rules: Vec<Policy> = inputs
        .new
        .set
        .policies()
        .filter(|p| p.effect() == Effect::Forbid && p.annotation("reason").is_some())
        .cloned()
        .collect();
    let mut live: std::collections::BTreeMap<String, bool> =
        deny_rules.iter().map(|p| (p.id().to_string(), false)).collect();
    let all_policies: Vec<Policy> =
        inputs.new.set.policies().chain(inputs.repo.iter().flat_map(|r| r.policies())).cloned().collect();

    for env in s.request_envs() {
        rep.envs += 1;
        let en = env_name(&env);
        let new = CompiledPolicySet::compile(&inputs.new.set, &env, s)?;

        // Ceiling: nothing the bundle allows is outside the org ceiling.
        let ceil = CompiledPolicySet::compile(&ceiling, &env, s)?;
        rep.queries += 1;
        let o = match sym.check_implies_with_counterexample_opt(&new, &ceil).await? {
            None => Outcome::Proved,
            Some(cex) => Outcome::Failed { counterexample: render_cex(&cex) },
        };
        rep.push(Gate::Ceiling, "org ceiling", &en, o);

        // Never errors: an erroring forbid is skipped by Cedar semantics.
        for p in all_policies.iter().filter(|p| applies(p, &env, &actions)) {
            let cp = CompiledPolicy::compile(p, &env, s)?;
            rep.queries += 1;
            let o = match sym.check_never_errors_with_counterexample_opt(&cp).await? {
                None => Outcome::Proved,
                Some(cex) => Outcome::Failed { counterexample: render_cex(&cex) },
            };
            rep.push(Gate::NeverErrors, p.id().to_string(), &en, o);
        }

        // Deny rules can fire (a forbid that never matches denies nothing).
        for f in deny_rules.iter().filter(|p| applies(p, &env, &actions)) {
            if live[&f.id().to_string()] {
                continue;
            }
            let cp = CompiledPolicy::compile(f, &env, s)?;
            rep.queries += 1;
            if sym.check_never_matches_with_counterexample_opt(&cp).await?.is_some() {
                live.insert(f.id().to_string(), true);
            }
        }

        // High-risk actions: publish and merge never without approval; not
        // every forced push is allowed.
        for a in ["pkg.publish", "pr.merge"] {
            if !action_is(&env, a) {
                continue;
            }
            let reference = parse_set(&format!(
                "permit (principal, action == Broker::Action::{}, resource) when {{ context.session.approved }};",
                lit(a)
            ))?;
            let refc = CompiledPolicySet::compile(&reference, &env, s)?;
            rep.queries += 1;
            let o = match sym.check_implies_with_counterexample_opt(&new, &refc).await? {
                None => Outcome::Proved,
                Some(cex) => Outcome::Failed { counterexample: render_cex(&cex) },
            };
            rep.push(Gate::DenyLive, format!("{a} needs approval"), &en, o);
        }
        if action_is(&env, "git.push") {
            // Forced pushes only through grants that opt in (`force = true`)
            // or plain host grants; nothing else (record mode, defaults).
            let mut reference = parse_set(
                "permit (principal, action == Broker::Action::\"git.push\", resource) when { !context.force };",
            )?;
            for id in &inputs.new.force_opt_ins {
                if let Some(p) = inputs.new.set.policy(&PolicyId::new(id)) {
                    reference.add(p.clone())?;
                }
            }
            let refc = CompiledPolicySet::compile(&reference, &env, s)?;
            rep.queries += 1;
            let o = match sym.check_implies_with_counterexample_opt(&new, &refc).await? {
                None => Outcome::Proved,
                Some(cex) => Outcome::Failed { counterexample: render_cex(&cex) },
            };
            rep.push(Gate::DenyLive, "forced git.push only by opt-in grants", &en, o);
        }

        // Credential confinement, per brokered credential.
        if action_is(&env, "credential.use") {
            if inputs.new.credentials.is_empty() {
                rep.push(
                    Gate::CredentialConfinement,
                    "-",
                    &en,
                    Outcome::NotApplicable { why: "no brokered credentials".into() },
                );
            }
            for c in &inputs.new.credentials {
                let uid = format!("Broker::Credential::{}", lit(&c.id));
                let mut alts: Vec<String> = Vec::new();
                if !c.hosts.is_empty() {
                    let hs: Vec<String> = c.hosts.iter().map(|h| lit(h)).collect();
                    alts.push(format!("[{}].contains(context.dest_host)", hs.join(", ")));
                }
                if !c.domains.is_empty() {
                    let ds: Vec<String> = c.domains.iter().map(|d| lit(d)).collect();
                    alts.push(format!("context.dest_domains.containsAny([{}])", ds.join(", ")));
                }
                let allowed = if alts.is_empty() { "false".to_string() } else { alts.join(" || ") };
                let reference = parse_set(&format!(
                    "permit (principal, action, resource) when {{ resource != {uid} }};\n\
                     permit (principal, action, resource == {uid}) when {{ {allowed} }};"
                ))?;
                let refc = CompiledPolicySet::compile(&reference, &env, s)?;
                rep.queries += 1;
                let o = match sym.check_implies_with_counterexample_opt(&new, &refc).await? {
                    None => Outcome::Proved,
                    Some(cex) => Outcome::Failed { counterexample: render_cex(&cex) },
                };
                rep.push(Gate::CredentialConfinement, c.id.clone(), &en, o);
            }
        }

        // I4: the repository layer only narrows.
        if let Some(cs) = &composed {
            let cc = CompiledPolicySet::compile(cs, &env, s)?;
            rep.queries += 1;
            let o = match sym.check_implies_with_counterexample_opt(&cc, &new).await? {
                None => Outcome::Proved,
                Some(cex) => Outcome::Failed { counterexample: render_cex(&cex) },
            };
            rep.push(Gate::RepoNarrows, "repo ∧ base ⊆ base", &en, o);
        }

        // Narrowing against the baseline (soft).
        if let Some(old) = inputs.old {
            let oc = CompiledPolicySet::compile(&old.set, &env, s)?;
            rep.queries += 1;
            let o = match sym.check_implies_with_counterexample_opt(&new, &oc).await? {
                None => Outcome::Proved,
                Some(cex) => Outcome::Failed { counterexample: render_cex(&cex) },
            };
            rep.push(Gate::Narrowing, "new ⊆ baseline", &en, o);
        }
    }
    for (id, is_live) in live {
        let o = if is_live {
            Outcome::Proved
        } else {
            Outcome::Failed { counterexample: "this forbid matches no request in any environment".into() }
        };
        rep.push(Gate::DenyLive, id, "all", o);
    }
    if inputs.repo.is_none() {
        rep.push(Gate::RepoNarrows, "-", "-", Outcome::NotApplicable { why: "no repository layer".into() });
    }
    if inputs.old.is_none() {
        rep.push(Gate::Narrowing, "-", "-", Outcome::NotApplicable { why: "no baseline".into() });
    }
    Ok(rep)
}
