---
title: "Dashboard"
aliases: ["Queries"]
type: meta
section: meta
tags: [sandbox/meta, meta, topic/build]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Dataview queries: notes by type and status, proposals needing verification, low-confidence notes, open problems, ADRs, milestones, build progress; Bases can mirror these."
related: ["[[Vault Conventions]]", "[[Build Log]]", "[[Open Questions and Unverified Claims]]", "[[MOC Decisions]]", "[[MOC Build]]", "[[MOC Open Problems]]"]
sources: []
---

# Dashboard

These views need the community **Dataview** plugin (enable JavaScript queries is *not* required; all blocks below are plain DQL). Every query excludes `templates/` and `code/`. Obsidian's core **Bases** plugin can mirror each view: create a `.base` file filtered on the same properties (`type`, `status`, `section`, `confidence`, `milestone`) and pick table or card layout. Without either plugin, the same answers come from `_manifest.json` with `jq` (see [[CLAUDE]] section 5).

## Build progress: milestones

```dataview
TABLE WITHOUT ID file.link AS Milestone, status, updated, summary
FROM "90-build"
WHERE type = "milestone"
SORT file.name ASC
```

The **current milestone** is the first row whose status is not `built`.

## Components and interfaces by status

```dataview
TABLE WITHOUT ID file.link AS Note, type, status, milestone, code
FROM "60-architecture" OR "70-policy"
WHERE type = "component" OR type = "interface"
SORT status ASC, file.name ASC
```

## Invariants and their tests

```dataview
TABLE WITHOUT ID file.link AS Invariant, status, updated
FROM "60-architecture/invariants"
SORT file.name ASC
```

## Notes by type

```dataview
TABLE WITHOUT ID type AS Type, length(rows) AS Notes
FROM -"templates" AND -"code"
GROUP BY type
SORT length(rows) DESC
```

## Notes by section and status

```dataview
TABLE WITHOUT ID section AS Section, length(filter(rows, (r) => r.status = "seedling")) AS Seedling, length(filter(rows, (r) => r.status = "draft")) AS Draft, length(filter(rows, (r) => r.status = "proposal")) AS Proposal, length(filter(rows, (r) => r.status = "verified")) AS Verified, length(filter(rows, (r) => r.status = "built")) AS Built
FROM -"templates" AND -"code"
GROUP BY section
SORT section ASC
```

## Proposals needing verification or build

Design recommendations not yet implemented. Check each against [[Open Questions and Unverified Claims]] before coding.

```dataview
TABLE WITHOUT ID file.link AS Note, section, confidence, updated
FROM -"templates" AND -"code"
WHERE status = "proposal"
SORT section ASC, file.name ASC
```

## Low-confidence and unverified notes

```dataview
TABLE WITHOUT ID file.link AS Note, section, status, summary
FROM -"templates" AND -"code"
WHERE confidence = "low" OR contains(tags, "evidence/unverified") OR contains(tags, "evidence/conflict") OR contains(tags, "evidence/single-source")
SORT section ASC
```

## Unwritten notes (seedlings and drafts)

```dataview
TABLE WITHOUT ID file.link AS Note, type, section
FROM -"templates" AND -"code"
WHERE status = "seedling" OR status = "draft"
SORT section ASC, file.name ASC
```

## Architecture decision records

```dataview
TABLE WITHOUT ID file.link AS ADR, status, superseded_by AS "Superseded by", summary
FROM "95-decisions"
WHERE type = "decision"
SORT file.name ASC
```

## Open problems

```dataview
TABLE WITHOUT ID file.link AS Problem, status, summary
FROM "99-open-problems"
WHERE type = "problem"
SORT file.name ASC
```

## Incidents and the notes that mitigate them

```dataview
TABLE WITHOUT ID file.link AS Incident, length(file.inlinks) AS Inbound, summary
FROM "20-threat-model/incidents"
SORT file.name ASC
```

## Recently updated

```dataview
TABLE WITHOUT ID file.link AS Note, type, status, updated
FROM -"templates" AND -"code"
SORT updated DESC, file.mtime DESC
LIMIT 25
```

## Orphans (no inbound links)

Every note must be reachable from a MOC; this list should stay empty.

```dataview
LIST
FROM -"templates" AND -"code"
WHERE length(file.inlinks) = 0 AND file.name != "00 Home"
```
