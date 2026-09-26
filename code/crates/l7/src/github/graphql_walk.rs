//! The confinement walk over a GraphQL document's selections (ADR-035):
//! whether a read stays inside one repository ([`super::schema`]),
//! whether it reaches issue, PR or comment text, and whether a mutation's
//! result selects more than the written object's identity. Fragments are
//! walked once each; work and recursion are bounded.

use super::super::schema;
use super::{MAX_STEPS, invalid};
use crate::graphql::{Document, Field, Fragment, OpType, Selection};
use audit::Reason;
use std::collections::HashMap;

/// Deepest nesting of walks (selection sets and fragment spreads).
pub const MAX_WALK_DEPTH: usize = 128;

/// Leaves a mutation result may select without reading beyond the object
/// the mutation wrote or merged.
const IDENTITY: &[&str] = &[
    "__typename",
    "clientMutationId",
    "id",
    "number",
    "url",
    "resourcePath",
    "permalink",
    "databaseId",
    "state",
    "merged",
    "mergedAt",
    "isDraft",
    "closed",
    "createdAt",
    "updatedAt",
    "cursor",
    "login",
];

/// Objects of a mutation result that are the written object itself (or
/// its edge, or the acting user).
const RESULT_OBJECTS: &[&str] = &["pullRequest", "commentEdge", "node", "subject", "actor"];

#[derive(Clone, Copy, Default)]
pub(super) struct Summary {
    pub(super) unconfined: bool,
    pub(super) bodies: bool,
}

impl Summary {
    fn add(&mut self, o: Summary) {
        self.unconfined |= o.unconfined;
        self.bodies |= o.bodies;
    }
}

/// Walks selections against [`schema`], expanding fragments once each.
pub(super) struct Walk<'d> {
    frags: HashMap<&'d str, &'d Fragment>,
    memo: HashMap<&'d str, Summary>,
    stack: Vec<&'d str>,
    steps: usize,
    depth: usize,
}

impl<'d> Walk<'d> {
    pub(super) fn new(doc: &'d Document) -> Result<Walk<'d>, Reason> {
        let mut frags = HashMap::new();
        for f in &doc.fragments {
            if frags.insert(f.name.as_str(), f).is_some() {
                return invalid("duplicate fragment");
            }
        }
        Ok(Walk { frags, memo: HashMap::new(), stack: Vec::new(), steps: 0, depth: 0 })
    }

    fn step(&mut self) -> Result<(), Reason> {
        self.steps += 1;
        if self.steps > MAX_STEPS { invalid("document too large") } else { Ok(()) }
    }

    /// Recursion is bounded: fragment chains nest walks beyond the parser's
    /// own depth limit, and an unbounded chain would overflow the stack.
    fn enter(&mut self) -> Result<(), Reason> {
        self.depth += 1;
        if self.depth > MAX_WALK_DEPTH { invalid("nested too deeply") } else { Ok(()) }
    }

    fn fragment(&self, n: &str) -> Result<&'d Fragment, Reason> {
        if self.stack.contains(&n) {
            return invalid("fragment cycle");
        }
        self.frags.get(n).copied().ok_or(Reason::GithubGraphqlInvalid)
    }

    /// The operation's root fields, through fragments on the root type.
    pub(super) fn roots(&mut self, sel: &'d [Selection], ty: OpType) -> Result<Vec<&'d Field>, Reason> {
        let root = match ty {
            OpType::Query => "Query",
            OpType::Mutation => "Mutation",
            OpType::Subscription => "Subscription",
        };
        let mut out = Vec::new();
        self.roots_into(sel, root, &mut out)?;
        Ok(out)
    }

    fn roots_into(&mut self, sel: &'d [Selection], root: &str, out: &mut Vec<&'d Field>) -> Result<(), Reason> {
        self.enter()?;
        for s in sel {
            self.step()?;
            match s {
                Selection::Field(f) => out.push(f),
                Selection::Inline(on, inner) => {
                    if on.as_deref().is_some_and(|t| t != root) {
                        return invalid("root fragment on another type");
                    }
                    self.roots_into(inner, root, out)?;
                }
                Selection::Spread(n) => {
                    let fr = self.fragment(n)?;
                    if fr.on != root {
                        return invalid("root fragment on another type");
                    }
                    self.stack.push(n);
                    self.roots_into(&fr.selection, root, out)?;
                    self.stack.pop();
                }
            }
        }
        self.depth -= 1;
        Ok(())
    }

    /// Summarise a selection on type `ty`.
    pub(super) fn sel(&mut self, sel: &'d [Selection], ty: &str) -> Result<Summary, Reason> {
        self.enter()?;
        let mut acc = Summary::default();
        if schema::BODY_TYPES.contains(&ty) {
            acc.bodies = true;
        }
        for s in sel {
            self.step()?;
            match s {
                Selection::Field(f) if f.name == "__typename" => {}
                Selection::Field(f) => match schema::field(ty, &f.name) {
                    Some(None) if f.selection.is_none() => {}
                    Some(Some(t)) => acc.add(self.sel(f.selection.as_deref().unwrap_or(&[]), t)?),
                    _ => acc.add(Summary { unconfined: true, bodies: true }),
                },
                Selection::Inline(on, inner) => {
                    let t = on.as_deref().unwrap_or(ty);
                    if schema::is_type(t) {
                        acc.add(self.sel(inner, t)?);
                    } else {
                        acc.add(Summary { unconfined: true, bodies: true });
                    }
                }
                Selection::Spread(n) => {
                    let fr = self.fragment(n)?;
                    if let Some(m) = self.memo.get(n.as_str()) {
                        acc.add(*m);
                        continue;
                    }
                    let m = if schema::is_type(&fr.on) {
                        self.stack.push(n);
                        let m = self.sel(&fr.selection, &fr.on)?;
                        self.stack.pop();
                        m
                    } else {
                        Summary { unconfined: true, bodies: true }
                    };
                    self.memo.insert(n, m);
                    acc.add(m);
                }
            }
        }
        self.depth -= 1;
        Ok(acc)
    }

    /// Whether a mutation result selects only the identity of the objects
    /// the mutation wrote (IDs, numbers, URLs, state), not their repository
    /// or its other content.
    pub(super) fn identity_only(&mut self, sel: &'d [Selection]) -> Result<bool, Reason> {
        self.enter()?;
        for s in sel {
            self.step()?;
            let ok = match s {
                Selection::Field(f) => match &f.selection {
                    None => IDENTITY.contains(&f.name.as_str()),
                    Some(inner) => RESULT_OBJECTS.contains(&f.name.as_str()) && self.identity_only(inner)?,
                },
                Selection::Inline(_, inner) => self.identity_only(inner)?,
                Selection::Spread(n) => {
                    let fr = self.fragment(n)?;
                    self.stack.push(n);
                    let ok = self.identity_only(&fr.selection)?;
                    self.stack.pop();
                    ok
                }
            };
            if !ok {
                self.depth -= 1;
                return Ok(false);
            }
        }
        self.depth -= 1;
        Ok(true)
    }
}
