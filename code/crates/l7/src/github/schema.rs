//! The part of GitHub's GraphQL schema the adapter understands, as an
//! allowlist of (type, field) pairs. A read whose every selected field is
//! listed here is *confined*: from a repository it reaches only that
//! repository's own issues, pull requests, comments, labels and milestones,
//! and from actors only their public login-level fields. Any other field
//! (an owner's `repositories`, a PR's `headRepository`, timelines, projects,
//! sub-issues, `... on User { repositories }`) makes the read unconfined,
//! and an unconfined read counts as a host-wide read of possibly private
//! data (`github.read`, both read labels).
//!
//! Field names and types are from GitHub's GraphQL reference
//! (docs.github.com/en/graphql/reference: repos, issues, pulls, users;
//! checked 2026-09-25). A name GitHub does not have only makes GitHub
//! reject the query; soundness depends on every listed edge staying in the
//! repository, which is why edges are few.

/// (type, leaf fields, object-valued fields and their types)
type TypeDef = (&'static str, &'static [&'static str], &'static [(&'static str, &'static str)]);

const ISSUE_LEAVES: &[&str] = &[
    "id",
    "number",
    "title",
    "titleHTML",
    "body",
    "bodyText",
    "bodyHTML",
    "state",
    "stateReason",
    "url",
    "resourcePath",
    "createdAt",
    "updatedAt",
    "closedAt",
    "closed",
    "locked",
    "databaseId",
    "authorAssociation",
    "lastEditedAt",
    "publishedAt",
];

const PR_LEAVES: &[&str] = &[
    "id",
    "number",
    "title",
    "body",
    "bodyText",
    "bodyHTML",
    "state",
    "url",
    "resourcePath",
    "permalink",
    "createdAt",
    "updatedAt",
    "closedAt",
    "closed",
    "locked",
    "merged",
    "mergedAt",
    "isDraft",
    "mergeable",
    "baseRefName",
    "headRefName",
    "baseRefOid",
    "headRefOid",
    "additions",
    "deletions",
    "changedFiles",
    "reviewDecision",
    "databaseId",
    "authorAssociation",
    "isCrossRepository",
    "maintainerCanModify",
];

const ISSUE_EDGES: &[(&str, &str)] = &[
    ("author", "Actor"),
    ("editor", "Actor"),
    ("labels", "LabelConnection"),
    ("comments", "IssueCommentConnection"),
    ("assignees", "UserConnection"),
    ("milestone", "Milestone"),
    ("repository", "Repository"),
];

const PR_EDGES: &[(&str, &str)] = &[
    ("author", "Actor"),
    ("editor", "Actor"),
    ("mergedBy", "Actor"),
    ("labels", "LabelConnection"),
    ("comments", "IssueCommentConnection"),
    ("assignees", "UserConnection"),
    ("milestone", "Milestone"),
    ("repository", "Repository"),
];

const ACTOR: &[&str] = &["login", "url", "avatarUrl", "resourcePath"];
const PAGE: &[&str] = &["totalCount"];

const TYPES: &[TypeDef] = &[
    (
        "Repository",
        &[
            "id",
            "name",
            "nameWithOwner",
            "description",
            "url",
            "homepageUrl",
            "isPrivate",
            "isFork",
            "isArchived",
            "isTemplate",
            "isEmpty",
            "visibility",
            "createdAt",
            "updatedAt",
            "pushedAt",
            "stargazerCount",
            "forkCount",
            "databaseId",
            "hasIssuesEnabled",
            "hasWikiEnabled",
            "viewerPermission",
            "resourcePath",
        ],
        &[
            ("owner", "RepositoryOwner"),
            ("defaultBranchRef", "Ref"),
            ("issue", "Issue"),
            ("issues", "IssueConnection"),
            ("pullRequest", "PullRequest"),
            ("pullRequests", "PullRequestConnection"),
            ("issueOrPullRequest", "IssueOrPullRequest"),
            ("labels", "LabelConnection"),
            ("label", "Label"),
            ("milestone", "Milestone"),
            ("milestones", "MilestoneConnection"),
        ],
    ),
    ("Ref", &["id", "name", "prefix"], &[]),
    ("RepositoryOwner", &["id", "login", "url", "avatarUrl", "resourcePath"], &[]),
    ("Actor", ACTOR, &[]),
    ("User", &["id", "login", "name", "url", "avatarUrl", "resourcePath", "databaseId"], &[]),
    ("Issue", ISSUE_LEAVES, ISSUE_EDGES),
    ("PullRequest", PR_LEAVES, PR_EDGES),
    // A union: only fragments (`... on Issue`) select from it.
    ("IssueOrPullRequest", &[], &[]),
    (
        "IssueComment",
        &[
            "id",
            "body",
            "bodyText",
            "bodyHTML",
            "url",
            "createdAt",
            "updatedAt",
            "databaseId",
            "authorAssociation",
            "isMinimized",
        ],
        &[
            ("author", "Actor"),
            ("editor", "Actor"),
            ("issue", "Issue"),
            ("pullRequest", "PullRequest"),
            ("repository", "Repository"),
        ],
    ),
    ("Label", &["id", "name", "color", "description", "isDefault", "url", "createdAt"], &[]),
    (
        "Milestone",
        &["id", "number", "title", "description", "state", "dueOn", "url", "closed", "closedAt", "createdAt"],
        &[],
    ),
    ("IssueConnection", PAGE, &[("pageInfo", "PageInfo"), ("nodes", "Issue"), ("edges", "IssueEdge")]),
    ("IssueEdge", &["cursor"], &[("node", "Issue")]),
    (
        "PullRequestConnection",
        PAGE,
        &[("pageInfo", "PageInfo"), ("nodes", "PullRequest"), ("edges", "PullRequestEdge")],
    ),
    ("PullRequestEdge", &["cursor"], &[("node", "PullRequest")]),
    (
        "IssueCommentConnection",
        PAGE,
        &[("pageInfo", "PageInfo"), ("nodes", "IssueComment"), ("edges", "IssueCommentEdge")],
    ),
    ("IssueCommentEdge", &["cursor"], &[("node", "IssueComment")]),
    ("LabelConnection", PAGE, &[("pageInfo", "PageInfo"), ("nodes", "Label"), ("edges", "LabelEdge")]),
    ("LabelEdge", &["cursor"], &[("node", "Label")]),
    ("UserConnection", PAGE, &[("pageInfo", "PageInfo"), ("nodes", "User"), ("edges", "UserEdge")]),
    ("UserEdge", &["cursor"], &[("node", "User")]),
    ("MilestoneConnection", PAGE, &[("pageInfo", "PageInfo"), ("nodes", "Milestone"), ("edges", "MilestoneEdge")]),
    ("MilestoneEdge", &["cursor"], &[("node", "Milestone")]),
    ("PageInfo", &["hasNextPage", "hasPreviousPage", "startCursor", "endCursor"], &[]),
    ("RateLimit", &["cost", "limit", "nodeCount", "remaining", "resetAt", "used"], &[]),
    // Only as a mutation payload's `subject` (the commented issue or PR).
    ("Node", &["id"], &[]),
    ("CreatePullRequestPayload", &["clientMutationId"], &[("pullRequest", "PullRequest")]),
    ("MergePullRequestPayload", &["clientMutationId"], &[("actor", "Actor"), ("pullRequest", "PullRequest")]),
    ("EnablePullRequestAutoMergePayload", &["clientMutationId"], &[("actor", "Actor"), ("pullRequest", "PullRequest")]),
    ("EnqueuePullRequestPayload", &["clientMutationId"], &[]),
    ("AddCommentPayload", &["clientMutationId"], &[("commentEdge", "IssueCommentEdge"), ("subject", "Node")]),
];

/// Types whose fields hold attacker-writable text (issue, PR and comment
/// bodies and titles): selecting one flags the read as carrying bodies.
pub const BODY_TYPES: &[&str] = &["Issue", "PullRequest", "IssueComment"];

pub fn is_type(ty: &str) -> bool {
    TYPES.iter().any(|(t, _, _)| *t == ty)
}

/// `Some(None)`: a listed leaf; `Some(Some(T))`: a listed field of object
/// type `T`; `None`: not listed (the read is unconfined).
pub fn field(ty: &str, name: &str) -> Option<Option<&'static str>> {
    let (_, leaves, edges) = TYPES.iter().find(|(t, _, _)| *t == ty)?;
    if leaves.contains(&name) {
        return Some(None);
    }
    edges.iter().find(|(f, _)| *f == name).map(|(_, t)| Some(*t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_edge_leads_to_a_listed_type() {
        for (t, leaves, edges) in TYPES {
            for (f, to) in *edges {
                assert!(is_type(to), "{t}.{f} → {to} is not listed");
                assert!(!leaves.contains(f), "{t}.{f} is both a leaf and an edge");
            }
        }
    }

    #[test]
    fn the_known_escapes_are_not_listed() {
        for (t, f) in [
            ("RepositoryOwner", "repositories"),
            ("RepositoryOwner", "repository"),
            ("Repository", "forks"),
            ("Repository", "parent"),
            ("Repository", "templateRepository"),
            ("Repository", "object"),
            ("PullRequest", "headRepository"),
            ("PullRequest", "baseRepository"),
            ("PullRequest", "timelineItems"),
            ("PullRequest", "projectItems"),
            ("Issue", "subIssues"),
            ("Issue", "trackedIssues"),
            ("Issue", "timelineItems"),
            ("Issue", "projectItems"),
            ("User", "repositories"),
            ("User", "issues"),
            ("User", "email"),
        ] {
            assert_eq!(field(t, f), None, "{t}.{f}");
        }
    }
}
