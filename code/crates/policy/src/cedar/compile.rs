//! broker.toml grants → Cedar permits. One grant compiles to a handful of
//! permits whose policy IDs map back to the grant (for `broker why`, the
//! credential binding and the learner). The compiler never emits `like` on
//! hosts: host scope is entity membership (`Host`, `Domain`), built by the
//! canonicaliser-fed entity builder.

use crate::egress::Grant;
use crate::glob::PathPattern;
use crate::l7::{L7Rules, Protocol};
use crate::repo::{RefPattern, RepoPattern};
use netguard::HostPattern;

use super::entities::PATH_SEGMENTS;

/// One compiled policy: its ID, the grant it came from, its source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Compiled {
    pub id: String,
    pub grant: Option<usize>,
    pub src: String,
}

/// A Cedar string literal (inputs are canonical ASCII; escape anyway).
pub fn lit(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if c.is_ascii_graphic() || c == ' ' => o.push(c),
            c => o.push_str(&format!("\\u{{{:x}}}", c as u32)),
        }
    }
    o.push('"');
    o
}

/// A Cedar `like` pattern: `*` stays a wildcard, everything else literal.
fn like_lit(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

pub const STANDARD_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];

pub fn http_action(method: &str) -> String {
    if STANDARD_METHODS.contains(&method) { format!("http.{method}") } else { "http.OTHER".into() }
}

fn action(a: &str) -> String {
    format!("Broker::Action::{}", lit(a))
}

fn host_cond(p: &HostPattern) -> String {
    match p {
        HostPattern::Exact(h) => format!("resource in Broker::Host::{}", lit(h.as_str())),
        HostPattern::Subdomains(b) => format!("resource in Broker::Domain::{}", lit(b.as_str())),
    }
}

fn ports_cond(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "false".into();
    }
    let list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    format!("[{}].contains(context.port)", list.join(", "))
}

fn classes_cond(g: &Grant) -> String {
    if matches!(&g.pattern, HostPattern::Exact(h) if h.is_ip_literal()) {
        // The literal's own address is the grant (M0 semantics).
        return "true".into();
    }
    let mut set: Vec<String> = vec![lit("public")];
    set.extend(g.allow_classes.iter().map(|c| lit(c.as_str())));
    format!("[{}].containsAll(context.addr_classes)", set.join(", "))
}

fn path_pattern_cond(p: &PathPattern) -> Result<String, String> {
    let segs = p.segments();
    let (prefix, open) = match segs.split_last() {
        Some((last, rest)) if last == "**" => (rest, true),
        _ => (segs, false),
    };
    if prefix.len() > PATH_SEGMENTS {
        return Err(format!("path pattern {:?} is deeper than {PATH_SEGMENTS} segments", p.as_str()));
    }
    let mut conds = vec![if open {
        format!("context.path.n >= {}", prefix.len())
    } else {
        format!("context.path.n == {}", prefix.len())
    }];
    for (i, seg) in prefix.iter().enumerate() {
        if seg == "*" {
            continue; // any single segment: existence is implied by n
        }
        let test = if seg.contains('*') {
            format!("context.path.s{i} like {}", like_lit(seg))
        } else {
            format!("context.path.s{i} == {}", lit(seg))
        };
        conds.push(format!("context.path has s{i} && {test}"));
    }
    Ok(format!("({})", conds.join(" && ")))
}

fn paths_cond(paths: Option<&[PathPattern]>) -> Result<String, String> {
    match paths {
        None => Ok("true".into()),
        Some([]) => Ok("false".into()),
        Some(ps) => Ok(format!("({})", ps.iter().map(path_pattern_cond).collect::<Result<Vec<_>, _>>()?.join(" || "))),
    }
}

fn repo_cond(p: &RepoPattern) -> String {
    match p {
        RepoPattern::Exact(r) => format!("resource == Broker::Repo::{}", lit(&r.to_string())),
        RepoPattern::Owner { authority, owner } => {
            format!("(resource.authority == {} && resource.owner == {})", lit(authority), lit(owner))
        }
        RepoPattern::Nothing(_) => "false".into(),
    }
}

fn refs_cond(refs: &[RefPattern]) -> String {
    if refs.is_empty() {
        return "false".into();
    }
    format!(
        "({})",
        refs.iter().map(|r| format!("context.ref like {}", like_lit(r.as_str()))).collect::<Vec<_>>().join(" || ")
    )
}

fn permit(id: &str, grant: usize, actions: &[String], when: &[String]) -> Compiled {
    let acts: Vec<String> = actions.iter().map(|a| action(a)).collect();
    let head =
        if acts.len() == 1 { format!("action == {}", acts[0]) } else { format!("action in [{}]", acts.join(", ")) };
    let cond = if when.is_empty() { "true".to_string() } else { when.join("\n       && ") };
    Compiled {
        id: id.to_string(),
        grant: Some(grant),
        src: format!("@id({})\npermit (principal, {head}, resource)\nwhen {{ {cond} }};", lit(id)),
    }
}

const ALL_L7: &[&str] = &["http.read", "http.write", "git.fetch", "git.advertise", "git.push"];

/// The permits of grant number `idx`.
pub fn grant_policies(idx: usize, g: &Grant) -> Result<Vec<Compiled>, String> {
    let id = |kind: &str| format!("{}#{kind}", g.id);
    let (h, p) = (host_cond(&g.pattern), ports_cond(&g.ports));
    let mut out = vec![
        permit(&id("resolve"), idx, &["net.resolve".into()], &[h.clone(), p.clone()]),
        permit(&id("connect"), idx, &["net.connect".into()], &[h.clone(), p.clone(), classes_cond(g)]),
    ];
    let Some(rules) = g.l7.as_deref() else {
        // A plain host grant allows every request on its host (M0/M1 semantics).
        let acts: Vec<String> = ALL_L7.iter().map(|s| s.to_string()).collect();
        out.push(permit(&id("any"), idx, &acts, &[h, p]));
        return Ok(out);
    };
    out.extend(l7_policies(&id, idx, rules, &h, &p)?);
    if let Some(c) = &rules.credential {
        out.push(Compiled {
            id: id("credential"),
            grant: Some(idx),
            src: format!(
                "@id({})\npermit (principal, action == Broker::Action::\"credential.use\", resource == Broker::Credential::{});",
                lit(&id("credential")),
                lit(&c.id)
            ),
        });
    }
    Ok(out)
}

/// Confine a brokered credential to its declared hosts in the policy text
/// itself. The default `credential-host-ceiling` forbid reads the hosts from
/// entity data, which the formal gates treat as arbitrary; this forbid makes
/// credential confinement provable from the policy alone (SymCC CI Gates).
pub fn confinement_policy(c: &crate::l7::CredentialDef) -> Compiled {
    let id = format!("credential:{}#confine", c.id);
    let (mut hosts, mut domains) = (vec![], vec![]);
    for p in &c.hosts {
        match p {
            HostPattern::Exact(h) => hosts.push(lit(h.as_str())),
            HostPattern::Subdomains(b) => domains.push(lit(b.as_str())),
        }
    }
    let mut alts = vec![];
    if !hosts.is_empty() {
        alts.push(format!("[{}].contains(context.dest_host)", hosts.join(", ")));
    }
    if !domains.is_empty() {
        alts.push(format!("context.dest_domains.containsAny([{}])", domains.join(", ")));
    }
    let allowed = if alts.is_empty() { "false".to_string() } else { alts.join(" || ") };
    Compiled {
        id: id.clone(),
        grant: None,
        src: format!(
            "@id({})\n@reason(\"credential_host_ceiling\")\nforbid (principal, action == Broker::Action::\"credential.use\", resource == Broker::Credential::{})\nunless {{ {allowed} }};",
            lit(&id),
            lit(&c.id)
        ),
    }
}

fn l7_policies(
    id: &dyn Fn(&str) -> String,
    idx: usize,
    rules: &L7Rules,
    h: &str,
    p: &str,
) -> Result<Vec<Compiled>, String> {
    let mut out = Vec::new();
    match rules.protocol {
        Protocol::Http | Protocol::Registry => {
            let paths = paths_cond(rules.paths())?;
            match rules.methods() {
                None => out.push(permit(
                    &id("http"),
                    idx,
                    &["http.read".into(), "http.write".into()],
                    &[h.into(), p.into(), paths.clone()],
                )),
                Some(ms) => {
                    let std: Vec<String> =
                        ms.iter().filter(|m| STANDARD_METHODS.contains(&m.as_str())).map(|m| http_action(m)).collect();
                    if !std.is_empty() {
                        out.push(permit(&id("http"), idx, &std, &[h.into(), p.into(), paths.clone()]));
                    }
                    for (k, m) in ms.iter().filter(|m| !STANDARD_METHODS.contains(&m.as_str())).enumerate() {
                        out.push(permit(
                            &id(&format!("http-other{k}")),
                            idx,
                            &["http.OTHER".into()],
                            &[h.into(), p.into(), format!("context.method == {}", lit(m)), paths.clone()],
                        ));
                    }
                    // Explicit write methods on a registry host are a publish
                    // grant (still subject to the approval forbid).
                    if rules.protocol == Protocol::Registry
                        && ms.iter().any(|m| !matches!(m.as_str(), "GET" | "HEAD" | "OPTIONS"))
                    {
                        out.push(permit(&id("publish"), idx, &["pkg.publish".into()], &[h.into(), p.into(), paths]));
                    }
                }
            }
        }
        Protocol::Git => {
            let fetch = rules.fetch();
            if !fetch.is_empty() {
                let any: Vec<String> = fetch.iter().map(repo_cond).collect();
                out.push(permit(
                    &id("fetch"),
                    idx,
                    &["git.fetch".into()],
                    &[h.into(), p.into(), format!("({})", any.join(" || "))],
                ));
            }
            for (k, r) in rules.push_rules().iter().enumerate() {
                let rc = repo_cond(&r.repo);
                out.push(permit(
                    &id(&format!("advertise{k}")),
                    idx,
                    &["git.advertise".into()],
                    &[h.into(), p.into(), rc.clone()],
                ));
                let force = if r.force { "true".to_string() } else { "!context.force".to_string() };
                out.push(permit(
                    &id(&push_suffix(k)),
                    idx,
                    &["git.push".into()],
                    &[h.into(), p.into(), rc, refs_cond(&r.refs), force],
                ));
            }
        }
    }
    Ok(out)
}

/// The ID suffix of a grant's `k`-th push permit (`<grant id>#push<k>`).
pub fn push_suffix(k: usize) -> String {
    format!("push{k}")
}

/// Record mode (learning): task permits relaxed to public HTTPS names; the
/// ceiling and default forbids still apply, and no credential is attached
/// that a grant does not bind.
pub fn record_policies() -> Vec<Compiled> {
    let net = "@id(\"record#net\")\npermit (principal, action in [Broker::Action::\"net.resolve\", Broker::Action::\"net.connect\"], resource)\n\
               when { context.session.mode == \"record\" && [443].contains(context.port) && !resource.ip_literal\n       && [\"public\"].containsAll(context.addr_classes) };";
    let l7 = "@id(\"record#l7\")\npermit (principal, action in [Broker::Action::\"http.read\", Broker::Action::\"http.write\", Broker::Action::\"git.fetch\", Broker::Action::\"git.advertise\"], resource)\n\
              when { context.session.mode == \"record\" };";
    // A forced push is never recorded: only a grant with `force = true` allows one.
    let push = "@id(\"record#push\")\npermit (principal, action == Broker::Action::\"git.push\", resource)\n\
                when { context.session.mode == \"record\" && !context.force };";
    vec![
        Compiled { id: "record#net".into(), grant: None, src: net.into() },
        Compiled { id: "record#l7".into(), grant: None, src: l7.into() },
        Compiled { id: "record#push".into(), grant: None, src: push.into() },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_and_paths() {
        assert_eq!(lit("a\"b\\c"), "\"a\\\"b\\\\c\"");
        let p = PathPattern::parse("/repos/*/*/issues").unwrap();
        assert_eq!(
            path_pattern_cond(&p).unwrap(),
            "(context.path.n == 4 && context.path has s0 && context.path.s0 == \"repos\" && context.path has s3 && context.path.s3 == \"issues\")"
        );
        let p = PathPattern::parse("/api/**").unwrap();
        assert_eq!(
            path_pattern_cond(&p).unwrap(),
            "(context.path.n >= 1 && context.path has s0 && context.path.s0 == \"api\")"
        );
        let p = PathPattern::parse("/v1/a*b").unwrap();
        assert!(path_pattern_cond(&p).unwrap().contains("context.path.s1 like \"a*b\""));
        assert_eq!(paths_cond(Some(&[])).unwrap(), "false");
        assert_eq!(paths_cond(None).unwrap(), "true");
        assert_eq!(http_action("PROPFIND"), "http.OTHER");
    }
}
