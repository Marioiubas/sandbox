//! Candidates → proposals under the Policy Miner Safeguards (G1-G10).
//! Everything here is deterministic; no model sits on this path (I3).

use crate::observe::{Corpus, Observation, What};
use crate::templatize::template;
use audit::Reason;
use policy::Action;
use policy::config::{EgressEntry, GitAllow, PushRule};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct Options {
    /// P1: a tuple is proposed only if seen in at least this many sessions.
    pub min_runs: usize,
    /// G3: collapse `/a/b/x`, `/a/b/y`, … to `/a/b/*` after n distinct
    /// children seen across m sessions.
    pub prefix_children: usize,
    pub prefix_runs: usize,
    /// G4: propose `*.name` only after k distinct subdomains.
    pub subdomain_k: usize,
    /// Branch prefix under which pushes are medium (not high) risk.
    pub branch_prefix: String,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            min_runs: 2,
            prefix_children: 3,
            prefix_runs: 2,
            subdomain_k: 3,
            branch_prefix: "refs/heads/agent/".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    pub fn as_str(&self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Proposal {
    pub entry: EgressEntry,
    pub risk: Risk,
    pub note: String,
    pub sessions: BTreeSet<String>,
    pub requests: usize,
    /// A recorded request this rule newly allows (the "counterexample" to
    /// narrowing that a reviewer sees).
    pub example: String,
}

impl Proposal {
    /// High-risk proposals are never active; a human must uncomment them (G7).
    pub fn needs_review(&self) -> bool {
        self.risk == Risk::High
    }
}

#[derive(Default)]
struct Support {
    sessions: BTreeSet<String>,
    requests: usize,
    example: String,
}

impl Support {
    fn add(&mut self, o: &Observation, example: String) {
        self.sessions.insert(o.session.clone());
        self.requests += 1;
        if self.example.is_empty() {
            self.example = example;
        }
    }
}

/// Templates per (host, port, method), with their support.
type PerMethod<'a> = BTreeMap<(String, u16, String), Vec<(String, &'a Support)>>;
/// Per git host: fetched repos, pushed (repo, force) → refs, support.
type GitHosts = BTreeMap<(String, u16), (BTreeSet<String>, BTreeMap<(String, bool), BTreeSet<String>>, Support)>;

#[derive(Default)]
pub struct Mined {
    pub proposals: Vec<Proposal>,
    /// Observed but blocked (ceiling or other hard denies), with counts.
    pub blocked: BTreeMap<(String, Reason), usize>,
    /// Candidates below the support threshold: description → sessions.
    pub insufficient: BTreeMap<String, usize>,
    /// G8: GitHub permissions derived per repository from observed operations.
    pub github_permissions: BTreeMap<String, BTreeMap<String, String>>,
}

fn registrable(host: &str) -> Option<String> {
    netguard::canon_host(host.as_bytes()).ok().and_then(|h| h.registrable().map(str::to_string))
}

fn method_risk(m: &str) -> Risk {
    match m {
        "GET" | "HEAD" | "OPTIONS" => Risk::Low,
        "POST" | "PUT" | "PATCH" => Risk::Medium,
        _ => Risk::High,
    }
}

pub fn mine(c: &Corpus, o: &Options) -> Mined {
    let mut m = Mined::default();
    let mut plain: BTreeMap<(String, u16), Support> = BTreeMap::new();
    let mut http: BTreeMap<(String, u16, String, String), Support> = BTreeMap::new();
    let mut fetch: BTreeMap<(String, u16, String), Support> = BTreeMap::new();
    let mut push: BTreeMap<(String, u16, String, String, bool), Support> = BTreeMap::new();
    for ob in &c.observations {
        if !ob.allowed {
            let what = match &ob.what {
                What::Connect => format!("connect {}:{}", ob.host, ob.port),
                What::L7(a) => a.iter().map(|a| a.verb()).collect::<Vec<_>>().join("; "),
            };
            *m.blocked.entry((what, ob.reason.unwrap_or(Reason::PolicyDenied))).or_default() += 1;
            continue;
        }
        if ob.would_deny.is_none() {
            continue; // already covered by current policy
        }
        match &ob.what {
            What::Connect => {
                plain.entry((ob.host.clone(), ob.port)).or_default().add(ob, format!("connect {}:{}", ob.host, ob.port))
            }
            What::L7(acts) => {
                for a in acts {
                    match a {
                        Action::Http { method, path } => http
                            .entry((ob.host.clone(), ob.port, method.clone(), template(path)))
                            .or_default()
                            .add(ob, format!("{method} https://{}{path}", ob.host)),
                        Action::GitFetch { repo } => {
                            fetch.entry((ob.host.clone(), ob.port, repo.to_string())).or_default().add(ob, a.verb())
                        }
                        Action::GitPushAdvertise { .. } => {} // implied by the push itself
                        Action::GitPush { repo, refname, force, .. } => push
                            .entry((ob.host.clone(), ob.port, repo.to_string(), refname.clone(), *force))
                            .or_default()
                            .add(ob, a.verb()),
                    }
                }
            }
        }
    }
    let supported = |s: &Support| s.sessions.len() >= o.min_runs;
    let mut insufficient = |desc: String, s: &Support| {
        m.insufficient.insert(desc, s.sessions.len());
    };

    // ---- plain hosts, with G4 subdomain collapse (never above registrable, G9)
    let mut by_reg: BTreeMap<(String, u16), Vec<(String, &Support)>> = BTreeMap::new();
    for ((host, port), s) in &plain {
        if !supported(s) {
            insufficient(format!("connect {host}:{port}"), s);
            continue;
        }
        let reg = registrable(host).unwrap_or_else(|| host.clone());
        by_reg.entry((reg, *port)).or_default().push((host.clone(), s));
    }
    for ((reg, port), hosts) in by_reg {
        let subs: Vec<&(String, &Support)> = hosts.iter().filter(|(h, _)| *h != reg).collect();
        // Never above the registrable domain, never over a public suffix (G9).
        let wildcard_ok = subs.len() >= o.subdomain_k && netguard::HostPattern::parse(&format!("*.{reg}")).is_ok();
        let mut emit = |host: String, group: Vec<&Support>, note: String| {
            let sessions: BTreeSet<String> = group.iter().flat_map(|s| s.sessions.iter().cloned()).collect();
            m.proposals.push(Proposal {
                entry: EgressEntry { host, ports: Some(vec![port]), ..Default::default() },
                risk: Risk::Medium,
                note,
                sessions,
                requests: group.iter().map(|s| s.requests).sum(),
                example: group.first().map(|s| s.example.clone()).unwrap_or_default(),
            });
        };
        if wildcard_ok {
            emit(
                format!("*.{reg}"),
                subs.iter().map(|(_, s)| *s).collect(),
                format!("{} distinct subdomains (G4)", subs.len()),
            );
            for (h, s) in hosts.iter().filter(|(h, _)| *h == reg) {
                emit(h.clone(), vec![*s], "host tunnelled, not inspected".into());
            }
        } else {
            for (h, s) in hosts {
                emit(h, vec![s], "host tunnelled, not inspected".into());
            }
        }
    }

    // ---- HTTP: one entry per (host, port, method); G3 prefix collapse; G5
    let mut per_method: PerMethod = BTreeMap::new();
    for ((host, port, method, tpl), s) in &http {
        if !supported(s) {
            insufficient(format!("{method} https://{host}{tpl}"), s);
            continue;
        }
        per_method.entry((host.clone(), *port, method.clone())).or_default().push((tpl.clone(), s));
    }
    for ((host, port, method), tpls) in per_method {
        let mut by_parent: BTreeMap<String, Vec<(String, &Support)>> = BTreeMap::new();
        for (t, s) in tpls {
            let parent = t.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default();
            by_parent.entry(parent).or_default().push((t, s));
        }
        let mut paths = BTreeSet::new();
        let mut sessions = BTreeSet::new();
        let (mut requests, mut example) = (0, String::new());
        for (parent, kids) in by_parent {
            let kid_sessions: BTreeSet<&String> = kids.iter().flat_map(|(_, s)| s.sessions.iter()).collect();
            if kids.len() >= o.prefix_children && kid_sessions.len() >= o.prefix_runs {
                paths.insert(format!("{parent}/*"));
            } else {
                paths.extend(kids.iter().map(|(t, _)| t.clone()));
            }
            for (_, s) in &kids {
                sessions.extend(s.sessions.iter().cloned());
                requests += s.requests;
                if example.is_empty() {
                    example = s.example.clone();
                }
            }
        }
        m.proposals.push(Proposal {
            entry: EgressEntry {
                host,
                ports: Some(vec![port]),
                methods: Some(vec![method.clone()]),
                paths: Some(paths.into_iter().collect()),
                ..Default::default()
            },
            risk: method_risk(&method),
            note: format!("{method} only, as observed (G5)"),
            sessions,
            requests,
            example,
        });
    }

    // ---- git: fetch and push per repository; force and non-agent refs are high risk
    let mut git_hosts: GitHosts = BTreeMap::new();
    for ((host, port, repo), s) in &fetch {
        if !supported(s) {
            insufficient(format!("git.fetch {repo}"), s);
            continue;
        }
        let e = git_hosts.entry((host.clone(), *port)).or_default();
        e.0.insert(repo.clone());
        e.2.sessions.extend(s.sessions.iter().cloned());
        e.2.requests += s.requests;
        m.github_permissions.entry(repo.clone()).or_default().entry("contents".into()).or_insert("read".into());
    }
    let mut high: Vec<Proposal> = Vec::new();
    for ((host, port, repo, refname, force), s) in &push {
        if !supported(s) {
            insufficient(format!("git.push {repo} {refname} force={force}"), s);
            continue;
        }
        m.github_permissions.entry(repo.clone()).or_default().insert("contents".into(), "write".into());
        let under_prefix = refname.starts_with(&o.branch_prefix);
        if *force || !under_prefix {
            high.push(Proposal {
                entry: EgressEntry {
                    host: host.clone(),
                    ports: Some(vec![*port]),
                    protocol: Some("git".into()),
                    allow: Some(GitAllow {
                        fetch: vec![],
                        push: vec![PushRule { repo: repo.clone(), refs: vec![refname.clone()], force: *force }],
                    }),
                    ..Default::default()
                },
                risk: Risk::High,
                note: if *force { "force push".into() } else { format!("push outside {}", o.branch_prefix) },
                sessions: s.sessions.clone(),
                requests: s.requests,
                example: s.example.clone(),
            });
            continue;
        }
        let e = git_hosts.entry((host.clone(), *port)).or_default();
        let short = refname.trim_start_matches("refs/heads/").to_string();
        e.1.entry((repo.clone(), false)).or_default().insert(short);
        e.2.sessions.extend(s.sessions.iter().cloned());
        e.2.requests += s.requests;
        if e.2.example.is_empty() {
            e.2.example = s.example.clone();
        }
    }
    for ((host, port), (fetches, pushes, s)) in git_hosts {
        let push_rules: Vec<PushRule> = pushes
            .into_iter()
            .map(|((repo, force), refs)| PushRule { repo, refs: refs.into_iter().collect(), force })
            .collect();
        let risk = if push_rules.is_empty() { Risk::Low } else { Risk::Medium };
        m.proposals.push(Proposal {
            entry: EgressEntry {
                host,
                ports: Some(vec![port]),
                protocol: Some("git".into()),
                allow: Some(GitAllow { fetch: fetches.into_iter().collect(), push: push_rules }),
                ..Default::default()
            },
            risk,
            note: "fetch and push as observed; refs listed exactly".into(),
            sessions: s.sessions,
            requests: s.requests,
            example: s.example,
        });
    }
    m.proposals.extend(high);
    m
}
