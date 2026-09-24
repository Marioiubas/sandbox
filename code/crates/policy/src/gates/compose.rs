//! The runtime conjunction "base allows and repo allows" (I4) as a single
//! policy set, so the analyzer can prove it narrows.

use cedar_policy::{Effect, Policy, PolicyId, PolicySet};

/// The base set, the repo layer's forbids, and one forbid (`repo#layer`)
/// that denies unless some repo permit matches. For every request without
/// evaluation errors this allows exactly what the runtime's two-set
/// conjunction allows; the runtime additionally denies on any error. Only
/// forbids are added to the base set.
pub fn conjoin(base: &PolicySet, repo: &PolicySet) -> Result<PolicySet, String> {
    let mut out = base.clone();
    let mut alts = Vec::new();
    for p in repo.policies() {
        match p.effect() {
            Effect::Forbid => out.add(p.clone()).map_err(|e| format!("{}: {e}", p.id()))?,
            Effect::Permit => {
                let ast: &cedar_policy_core::ast::Policy = p.as_ref();
                alts.push(format!("({})", ast.condition()));
            }
        }
    }
    if repo.templates().next().is_some() {
        return Err("templates are not supported in the repository layer".into());
    }
    let cond = if alts.is_empty() { "false".to_string() } else { alts.join(" || ") };
    let src = format!(
        "@id(\"repo#layer\")\n@reason(\"repo_policy_denied\")\nforbid (principal, action, resource)\nunless {{ {cond} }};"
    );
    let layer = Policy::parse(Some(PolicyId::new("repo#layer")), &src).map_err(|e| format!("repo#layer: {e}"))?;
    out.add(layer).map_err(|e| format!("repo#layer: {e}"))?;
    Ok(out)
}
