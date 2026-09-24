//! GitHub verbs (GitHub API Adapter), repository visibility, and the
//! session trifecta labels (Trifecta Session Labels). Labels are raised
//! only by the broker from facts it observes; they never go back down.

use crate::config::EgressEntry;
use crate::l7::{CompileEnv, Protocol};
use crate::repo::{RepoId, RepoPattern};
use audit::Reason;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};

/// Verbs on a repository (resource `Repo`).
pub const REPO_VERBS: &[&str] = &["repo.read", "pr.create", "pr.merge", "issue.comment", "contents.write"];
/// Verbs on the API host itself (resource `Host`).
pub const HOST_VERBS: &[&str] = &["github.read", "gist.create"];

pub fn is_verb(v: &str) -> bool {
    REPO_VERBS.contains(&v) || HOST_VERBS.contains(&v)
}

pub fn is_repo_verb(v: &str) -> bool {
    REPO_VERBS.contains(&v)
}

/// Read verbs (everything else is write-class: `external_effect`).
pub fn is_read_verb(v: &str) -> bool {
    matches!(v, "repo.read" | "github.read")
}

/// Validate the `verbs` and `repos` keys: only on `protocol = "github"`,
/// known verbs only, `repos` defaulting to the task repository.
pub(crate) fn compile_verbs(
    grant_id: &str,
    e: &EgressEntry,
    protocol: Protocol,
    env: &CompileEnv,
) -> Result<(BTreeSet<String>, Vec<RepoPattern>), String> {
    if protocol != Protocol::GitHub {
        if e.verbs.is_some() || e.repos.is_some() {
            return Err(format!("{grant_id}: verbs and repos need protocol = \"github\""));
        }
        return Ok((BTreeSet::new(), vec![]));
    }
    if e.methods.is_some() || e.paths.is_some() {
        return Err(format!("{grant_id}: protocol = \"github\" takes verbs and repos, not methods/paths"));
    }
    let Some(vs) = &e.verbs else {
        return Err(format!("{grant_id}: protocol = \"github\" needs verbs (empty lists deny)"));
    };
    let mut verbs = BTreeSet::new();
    for v in vs {
        if !is_verb(v) {
            return Err(format!(
                "{grant_id}: unknown GitHub verb {v:?} ({})",
                [REPO_VERBS, HOST_VERBS].concat().join(", ")
            ));
        }
        verbs.insert(v.clone());
    }
    let default = vec!["${repo_remote}".to_string()];
    let repos = e
        .repos
        .as_ref()
        .unwrap_or(&default)
        .iter()
        .map(|r| RepoPattern::parse(r, env.repo_remote.as_ref()).map_err(|m| format!("{grant_id}: {m}")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((verbs, repos))
}

/// The reference (explainer) check of one verb against one grant.
pub(crate) fn rule_allows(
    verbs: &BTreeSet<String>,
    repos: &[RepoPattern],
    verb: &str,
    repo: Option<&RepoId>,
) -> Result<(), Reason> {
    if !verbs.contains(verb) {
        return Err(Reason::GithubVerbNotAllowed);
    }
    if is_repo_verb(verb) {
        match repo {
            Some(r) if repos.iter().any(|p| p.matches(r)) => Ok(()),
            _ => Err(Reason::GithubRepoNotAllowed),
        }
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Private,
    /// Not known (lookup failed or not done): treated as private for
    /// `sensitive_read` and as public for `untrusted_input` (both narrow).
    #[default]
    Unknown,
}

impl Visibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Private => "private",
            Visibility::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    UntrustedInput,
    SensitiveRead,
    ExternalEffect,
}

impl Label {
    pub fn as_str(&self) -> &'static str {
        match self {
            Label::UntrustedInput => "untrusted_input",
            Label::SensitiveRead => "sensitive_read",
            Label::ExternalEffect => "external_effect",
        }
    }
}

/// A snapshot of the labels, as the Cedar `Trifecta` record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Trifecta {
    pub untrusted_input: bool,
    pub sensitive_read: bool,
    pub external_effect: bool,
}

/// The session's labels. There is deliberately no way to lower one.
#[derive(Debug, Default)]
pub struct Labels {
    untrusted_input: AtomicBool,
    sensitive_read: AtomicBool,
    external_effect: AtomicBool,
}

impl Labels {
    fn cell(&self, l: Label) -> &AtomicBool {
        match l {
            Label::UntrustedInput => &self.untrusted_input,
            Label::SensitiveRead => &self.sensitive_read,
            Label::ExternalEffect => &self.external_effect,
        }
    }

    /// Raise a label; true when this call raised it.
    pub fn raise(&self, l: Label) -> bool {
        !self.cell(l).swap(true, Ordering::SeqCst)
    }

    pub fn get(&self, l: Label) -> bool {
        self.cell(l).load(Ordering::SeqCst)
    }

    pub fn snapshot(&self) -> Trifecta {
        Trifecta {
            untrusted_input: self.get(Label::UntrustedInput),
            sensitive_read: self.get(Label::SensitiveRead),
            external_effect: self.get(Label::ExternalEffect),
        }
    }
}

/// The labels a GitHub action raises, given the repository's visibility:
/// a read of a non-public repository is a sensitive read; issue, PR and
/// comment bodies (or search results) from a non-private source are
/// untrusted input; any write verb is an external effect.
pub fn labels_for(verb: &str, visibility: Visibility, bodies: bool) -> Vec<Label> {
    let mut out = Vec::new();
    if !is_read_verb(verb) {
        out.push(Label::ExternalEffect);
        return out;
    }
    if verb == "repo.read" && visibility != Visibility::Public {
        out.push(Label::SensitiveRead);
    }
    if bodies && visibility != Visibility::Private {
        out.push(Label::UntrustedInput);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn label() -> impl Strategy<Value = Label> {
        prop_oneof![Just(Label::UntrustedInput), Just(Label::SensitiveRead), Just(Label::ExternalEffect)]
    }

    proptest! {
        /// Labels are monotone: no sequence of operations lowers one.
        #[test]
        fn labels_never_go_down(ops in proptest::collection::vec(label(), 0..20)) {
            let l = Labels::default();
            let mut prev = l.snapshot();
            for op in ops {
                l.raise(op);
                let now = l.snapshot();
                prop_assert!(!prev.untrusted_input || now.untrusted_input);
                prop_assert!(!prev.sensitive_read || now.sensitive_read);
                prop_assert!(!prev.external_effect || now.external_effect);
                prop_assert!(l.get(op));
                prev = now;
            }
        }
    }

    #[test]
    fn label_rules() {
        use Visibility::*;
        assert_eq!(labels_for("repo.read", Private, false), vec![Label::SensitiveRead]);
        assert_eq!(labels_for("repo.read", Unknown, true), vec![Label::SensitiveRead, Label::UntrustedInput]);
        assert_eq!(labels_for("repo.read", Public, true), vec![Label::UntrustedInput]);
        assert!(labels_for("repo.read", Public, false).is_empty());
        assert_eq!(labels_for("github.read", Unknown, true), vec![Label::UntrustedInput]);
        assert_eq!(labels_for("pr.create", Public, false), vec![Label::ExternalEffect]);
    }
}
