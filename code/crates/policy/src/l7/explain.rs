//! The explainer: the M1 reference semantics of L7 rules. Cedar decides;
//! this names the most specific reason for a deny and is the differential
//! oracle in property tests.

use super::*;

/// Deny reasons ranked from least to most specific, for reporting.
fn rank(r: Reason) -> u8 {
    match r {
        Reason::GitForcePush => 3,
        Reason::GitRefNotAllowed => 2,
        Reason::GitRepoNotAllowed => 1,
        Reason::GithubRepoNotAllowed => 2,
        Reason::GithubVerbNotAllowed => 1,
        _ => 0,
    }
}

/// The outcome of authorizing one terminated request.
#[derive(Clone, Debug)]
pub struct L7Decision {
    pub result: Result<(), Reason>,
    /// Grants that allowed (on allow) or were consulted (on deny).
    pub policy_ids: Vec<String>,
    pub binding: Option<AllowedBinding>,
    /// Per action: verb and result.
    pub actions: Vec<(String, Result<(), Reason>)>,
    /// Record mode: the enforce-mode decision would have denied, and why.
    pub would_deny: Option<Reason>,
}

/// The reference evaluation (M1 semantics) of `actions` against the grants
/// that admitted the connection. Since M2 Cedar makes the decision; this
/// explains denies with a specific reason and is the differential oracle in
/// tests. Each action must be allowed by some grant (a grant without L7
/// rules allows nothing: ADR-027); a grant's credential applies only if
/// that grant allowed every action.
pub fn explain<'a>(grants: impl IntoIterator<Item = (&'a str, Option<&'a L7Rules>)>, actions: &[Action]) -> L7Decision {
    let grants: Vec<(&str, Option<&L7Rules>)> = grants.into_iter().collect();
    let consulted: Vec<String> = grants.iter().map(|(id, _)| id.to_string()).collect();
    if actions.is_empty() {
        // An adapter that classified nothing: fail closed.
        return L7Decision {
            result: Err(Reason::L7NoRuleMatched),
            policy_ids: consulted,
            binding: None,
            actions: vec![],
            would_deny: None,
        };
    }
    let mut per_action = Vec::new();
    let mut allowing: BTreeSet<&str> = BTreeSet::new();
    let mut overall: Result<(), Reason> = Ok(());
    for a in actions {
        let mut best: Option<Reason> = None;
        let mut ok = false;
        for (id, rules) in &grants {
            // A plain grant (no rules) carries no L7 authority (ADR-027).
            match rules.map(|r| r.allows(a)).unwrap_or(Err(Reason::L7NoRuleMatched)) {
                Ok(()) => {
                    ok = true;
                    allowing.insert(id);
                }
                Err(r) => {
                    if best.is_none_or(|b| rank(r) > rank(b)) {
                        best = Some(r);
                    }
                }
            }
        }
        let r = if ok { Ok(()) } else { Err(best.unwrap_or(Reason::L7NoRuleMatched)) };
        if let (Err(e), Ok(())) = (r, overall) {
            overall = Err(e);
        }
        per_action.push((a.verb(), r));
    }
    if let Err(reason) = overall {
        return L7Decision {
            result: Err(reason),
            policy_ids: consulted,
            binding: None,
            actions: per_action,
            would_deny: None,
        };
    }
    // Grants that allowed every action.
    let full: Vec<&(&str, Option<&L7Rules>)> = grants
        .iter()
        .filter(|(_, rules)| actions.iter().all(|a| rules.map(|r| r.allows(a)).unwrap_or(Ok(())).is_ok()))
        .collect();
    let mut creds: Vec<(&str, &Arc<CredentialDef>)> =
        full.iter().filter_map(|(id, r)| r.and_then(|r| r.credential.as_ref()).map(|c| (*id, c))).collect();
    creds.dedup_by(|a, b| a.1.id == b.1.id);
    let policy_ids: Vec<String> = allowing.iter().map(|s| s.to_string()).collect();
    match creds.len() {
        0 => L7Decision { result: Ok(()), policy_ids, binding: None, actions: per_action, would_deny: None },
        1 => L7Decision {
            result: Ok(()),
            policy_ids,
            binding: Some(AllowedBinding::new(creds[0].1.clone(), creds[0].0)),
            actions: per_action,
            would_deny: None,
        },
        _ => L7Decision {
            result: Err(Reason::AmbiguousCredential),
            policy_ids,
            binding: None,
            actions: per_action,
            would_deny: None,
        },
    }
}
