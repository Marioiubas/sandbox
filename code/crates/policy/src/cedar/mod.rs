//! The Cedar engine (Policy Engine and Entity Builder). Every egress and L7
//! decision is a Cedar authorization against the Broker schema:
//!
//! - the **base** set: the default forbids, the org ceiling, the record-mode
//!   permits and the permits compiled from built-in profile and user grants;
//! - the optional **repo** set, compiled from an approved `.broker/` policy;
//!   a request is allowed only if the base set allows it **and** the repo
//!   set (when present) allows it, so repo policy can only narrow (I4);
//! - evaluation errors, schema-invalid requests and empty request lists deny.

pub mod categories;
pub mod compile;
pub mod entities;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, Policy, PolicyId, PolicySet, Request, Schema, ValidationMode,
    Validator,
};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;

pub use compile::Compiled;
pub use entities::{Mode, SessionInfo};

pub const SCHEMA: &str = include_str!("schema.cedarschema");
pub const DEFAULT_POLICIES: &str = include_str!("../../../../policies/default.cedar");
pub const CEILING_POLICIES: &str = include_str!("../../../../policies/ceiling.cedar");

/// The schema, compiled once.
pub fn schema() -> &'static Schema {
    static S: std::sync::OnceLock<Schema> = std::sync::OnceLock::new();
    S.get_or_init(|| Schema::from_cedarschema_str(SCHEMA).expect("built-in schema compiles").0)
}

/// Parse and add policies, keeping their `@id` as the policy ID.
fn add_policies(set: &mut PolicySet, src: &str, what: &str) -> Result<(), String> {
    let parsed = PolicySet::from_str(src).map_err(|e| format!("{what}: {e}"))?;
    for p in parsed.policies() {
        let id = p.annotation("id").ok_or_else(|| format!("{what}: every policy needs an @id"))?;
        set.add(p.new_id(PolicyId::new(id))).map_err(|e| format!("{what}: {e}"))?;
    }
    Ok(())
}

fn add_compiled(set: &mut PolicySet, c: &Compiled) -> Result<(), String> {
    let p = Policy::parse(Some(PolicyId::new(&c.id)), &c.src).map_err(|e| format!("{}: {e}\n{}", c.id, c.src))?;
    set.add(p).map_err(|e| format!("{}: {e}", c.id))
}

/// Strict schema validation of a policy set.
pub fn validate(set: &PolicySet) -> Result<(), String> {
    let r = Validator::new(schema().clone()).validate(set, ValidationMode::Strict);
    if r.validation_passed() {
        Ok(())
    } else {
        Err(r.validation_errors().map(|e| e.to_string()).collect::<Vec<_>>().join("; "))
    }
}

/// The outcome of one Cedar request (after base/repo conjunction).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub allowed: bool,
    /// Base set: satisfied permits on allow, satisfied forbids on deny.
    pub determining: Vec<String>,
    /// Base allowed but the repo layer did not.
    pub repo_denied: bool,
    /// Any evaluation or request-validation error (always a deny).
    pub errors: Vec<String>,
}

impl Verdict {
    fn error(e: String) -> Verdict {
        Verdict { allowed: false, determining: vec![], repo_denied: false, errors: vec![e] }
    }
}

/// A compiled engine for one session's policy layers.
#[derive(Clone, Debug)]
pub struct Engine {
    base: PolicySet,
    repo: Option<PolicySet>,
    /// Policy ID → grant index (base grants).
    grant_of: HashMap<String, usize>,
    /// Policy ID → `@reason` of forbids.
    reasons: HashMap<String, String>,
}

impl Engine {
    /// Build the base set from compiled grant policies.
    pub fn new(compiled: &[Compiled]) -> Result<Engine, String> {
        let mut base = PolicySet::new();
        add_policies(&mut base, DEFAULT_POLICIES, "default policies")?;
        add_policies(&mut base, CEILING_POLICIES, "ceiling policies")?;
        for c in compile::record_policies().iter().chain(compiled) {
            add_compiled(&mut base, c)?;
        }
        validate(&base)?;
        let grant_of = compiled.iter().filter_map(|c| c.grant.map(|g| (c.id.clone(), g))).collect();
        let reasons = base
            .policies()
            .filter_map(|p| p.annotation("reason").map(|r| (p.id().to_string(), r.to_string())))
            .collect();
        Ok(Engine { base, repo: None, grant_of, reasons })
    }

    /// Conjoin a repo layer (compiled from approved `.broker/` policy, plus
    /// raw `.broker/policy.cedar` text). Everything in it can only narrow:
    /// a request must be allowed by the base set **and** by this set.
    pub fn with_repo(mut self, compiled: &[Compiled], cedar: Option<&str>) -> Result<Engine, String> {
        let mut set = PolicySet::new();
        for c in compiled {
            add_compiled(&mut set, c)?;
        }
        if let Some(src) = cedar {
            let parsed = PolicySet::from_str(src).map_err(|e| format!(".broker/policy.cedar: {e}"))?;
            for (i, p) in parsed.policies().enumerate() {
                let id =
                    format!("repo:cedar#{}", p.annotation("id").map(str::to_string).unwrap_or_else(|| i.to_string()));
                set.add(p.new_id(PolicyId::new(id))).map_err(|e| format!(".broker/policy.cedar: {e}"))?;
            }
            if parsed.templates().next().is_some() {
                return Err(".broker/policy.cedar: templates are not supported".into());
            }
        }
        // The repo layer never decides credential use (it cannot declare
        // credentials), so it neither grants nor blocks it.
        add_compiled(
            &mut set,
            &Compiled {
                id: "repo#credential-neutral".into(),
                grant: None,
                src: "@id(\"repo#credential-neutral\")\npermit (principal, action == Broker::Action::\"credential.use\", resource);".into(),
            },
        )?;
        validate(&set)?;
        self.repo = Some(set);
        Ok(self)
    }

    pub fn has_repo(&self) -> bool {
        self.repo.is_some()
    }

    pub fn base(&self) -> &PolicySet {
        &self.base
    }

    /// The same engine evaluating `base` alone (tests of the gates' single-set
    /// encoding of the repo conjunction).
    #[cfg(all(test, feature = "gates"))]
    pub(crate) fn with_base_only(mut self, base: PolicySet) -> Engine {
        self.base = base;
        self.repo = None;
        self
    }

    /// The conjoined repository layer, if any.
    pub fn repo(&self) -> Option<&PolicySet> {
        self.repo.as_ref()
    }

    pub fn grant_of(&self, policy_id: &str) -> Option<usize> {
        self.grant_of.get(policy_id).copied()
    }

    pub fn reason_of(&self, policy_id: &str) -> Option<&str> {
        self.reasons.get(policy_id).map(String::as_str)
    }

    /// Grants whose permits determined an allow.
    pub fn grants_in(&self, v: &Verdict) -> BTreeSet<usize> {
        v.determining.iter().filter_map(|id| self.grant_of(id)).collect()
    }

    /// Evaluate one request. `entities` is a JSON array of entities (the
    /// principal's and the resource's); `context` a JSON object.
    pub fn authorize(&self, action: &str, resource: &Value, entities: Vec<Value>, context: Value) -> Verdict {
        let s = schema();
        let parse_uid = |v: &Value| EntityUid::from_json(v.clone()).map_err(|e| e.to_string());
        let action_uid = match EntityUid::from_str(&format!("Broker::Action::{}", compile::lit(action))) {
            Ok(a) => a,
            Err(e) => return Verdict::error(e.to_string()),
        };
        let principal = match entities.iter().find(|e| e["uid"]["type"] == "Broker::Task").map(|e| parse_uid(&e["uid"]))
        {
            Some(Ok(p)) => p,
            _ => return Verdict::error("no Task principal".into()),
        };
        let resource = match parse_uid(resource) {
            Ok(r) => r,
            Err(e) => return Verdict::error(e),
        };
        let ctx = match Context::from_json_value(context, Some((s, &action_uid))) {
            Ok(c) => c,
            Err(e) => return Verdict::error(format!("context: {e}")),
        };
        let req = match Request::new(principal, action_uid, resource, ctx, Some(s)) {
            Ok(r) => r,
            Err(e) => return Verdict::error(format!("request: {e}")),
        };
        let ents = match Entities::from_json_value(Value::Array(entities), Some(s)) {
            Ok(e) => e,
            Err(e) => return Verdict::error(format!("entities: {e}")),
        };
        let auth = Authorizer::new();
        let r = auth.is_authorized(&req, &self.base, &ents);
        let errors: Vec<String> = r.diagnostics().errors().map(|e| e.to_string()).collect();
        let determining: Vec<String> = r.diagnostics().reason().map(|p| p.to_string()).collect();
        if !errors.is_empty() {
            return Verdict { allowed: false, determining, repo_denied: false, errors };
        }
        let base_ok = r.decision() == Decision::Allow;
        let (allowed, repo_denied) = match (&self.repo, base_ok) {
            (Some(repo), true) => {
                let rr = auth.is_authorized(&req, repo, &ents);
                let ok = rr.decision() == Decision::Allow && rr.diagnostics().errors().next().is_none();
                (ok, !ok)
            }
            (_, ok) => (ok, false),
        };
        Verdict { allowed, determining, repo_denied, errors }
    }
}

#[cfg(test)]
mod github_tests;
#[cfg(test)]
mod s3_tests;
#[cfg(test)]
mod tests;
