---
title: "Vault Conventions"
aliases: ["Conventions"]
type: meta
section: meta
tags: [sandbox/meta, meta]
status: verified
confidence: high
created: 2026-09-24
updated: 2026-09-24
summary: "Frontmatter schema, note types, tag vocabulary, status and confidence values, link semantics, file naming and template usage."
related: ["[[CLAUDE]]", "[[00 Home]]", "[[Dashboard]]", "[[Glossary]]", "[[Bibliography]]", "[[Build Log]]", "[[Open Questions and Unverified Claims]]"]
sources: []
---

# Vault Conventions

Every writer (human or agent) follows these rules so that the graph stays queryable by Dataview, traversable by `grep` and `jq`, and faithful to the research record.

## 1. Frontmatter schema

Every note starts with this YAML block. Keys are required unless marked optional. Strings that contain `:` or `#` must be quoted.

```yaml
---
title: <Note name>                 # identical to the filename without .md
aliases: [...]                     # other names; merged concepts live here
type: <type>                       # see section 2
section: <section>                 # see section 3
tags: [sandbox/<section>, <type>, ...]   # controlled vocabulary, no '#'
status: verified | proposal | draft      # plus seedling and built, see section 5
confidence: high | medium | low
created: 2026-09-24
updated: 2026-09-24                # bump on every edit
summary: <one line>                # the same line as in _manifest.json
related: ["[[...]]", ...]          # at least the manifest links_to set
sources: [<urls>]                  # every URL cited in the body
# optional:
code: [code/crates/netguard/src/canon.rs, ...]   # paths that implement this note
milestone: M0                      # milestone that delivers it
superseded_by: "[[ADR-0NN ...]]"   # ADRs only
---
```

`_manifest.json` at the vault root mirrors `title`, `type`, `section`, `summary` and the required `links_to` for every note. When you add or rename a note, update the manifest in the same change.

## 2. Note types

| type | Used for | Body skeleton | Template |
|---|---|---|---|
| `moc` | Map of content for a section, plus [[00 Home]] | intro, grouped links with one-line summaries, "How this section connects" | none |
| `meta` | Vault machinery (this note, [[Glossary]], [[Dashboard]]...) | free | none |
| `source-index` | [[Bibliography]] | URLs grouped by topic → notes | none |
| `concept` | One idea, design pattern or invariant | Summary, Details, Evidence, Implications for the build, Relationships | `Template Note` |
| `paper` | One paper or research system audited | Citation, Mechanism, Evidence, Counter-evidence, Where the probabilistic part lives, Adopt / Improve / Add | `Template Paper` |
| `primitive` | One isolation or kernel primitive | Boundary, Performance, Security record, Verdict, Sharp edges | `Template Note` |
| `standard` | A spec, RFC, token format or policy language | What it specifies, Fields, Limits, How the broker uses it | `Template Note` |
| `component` | One crate or runtime component of the product | Responsibility, Inputs/outputs, Invariants upheld, Interfaces, Failure modes, Tests | `Template Component` |
| `interface` | A trait, API, schema or file format | Signature or schema (verbatim), Contract, Versioning, Tests | `Template Component` |
| `incident` | One real-world incident or advisory | Timeline, Mechanism, Root cause, Stopping control, Regression test | `Template Incident` |
| `product` | One product or a tightly grouped set of competitors | Isolation, Secret handling, Scoping, Openness, Gap versus this thesis | `Template Note` |
| `decision` | One architecture decision record | Context, Decision, Alternatives, Consequences, Invariants affected | `Template ADR` |
| `milestone` | One MVP milestone or the plan | Scope, Acceptance criteria, Components delivered, Tests, Build log | `Template Note` |
| `eval` | A benchmark or evaluation layer | What it measures, Method, Threshold, How to run, Reporting | `Template Note` |
| `risk` | Risks with evidence and mitigation | Risk, Evidence, Mitigation, Owner/trigger | `Template Note` |
| `problem` | An open research problem or the problem statement | Problem, Why open, Evidence, What a solution looks like, Hooks in the MVP | `Template Note` |

## 3. Sections and folders

| section | folder | MOC |
|---|---|---|
| `meta` | vault root and `00-meta/` | [[00 Home]] |
| `problem` | `10-problem/` | [[MOC Problem]] |
| `threat` | `20-threat-model/` (incidents in `incidents/`) | [[MOC Threat Model]] |
| `research` | `30-research/` | [[MOC Research]] |
| `primitives` | `40-primitives/` | [[MOC Primitives]] |
| `identity` | `50-identity/` | [[MOC Identity]] |
| `architecture` | `60-architecture/` (`invariants/`, `components/`, `interfaces/`) | [[MOC Architecture]] |
| `policy` | `70-policy/` | [[MOC Policy]] |
| `landscape` | `80-landscape/` | [[MOC Landscape]] |
| `build` | `90-build/` (`milestones/`, `evaluation/`) | [[MOC Build]] |
| `decisions` | `95-decisions/` | [[MOC Decisions]] |
| `open` | `99-open-problems/` | [[MOC Open Problems]] |

`templates/` holds note templates (excluded from Dataview queries); `code/` holds the product source (excluded from Obsidian indexing via `.obsidian/app.json`).

## 4. Tag vocabulary (controlled)

Tags never carry `#` in frontmatter. Use only these families; propose additions in [[Build Log]].

- **Section:** `sandbox/meta`, `sandbox/problem`, `sandbox/threat`, `sandbox/research`, `sandbox/primitives`, `sandbox/identity`, `sandbox/architecture`, `sandbox/policy`, `sandbox/landscape`, `sandbox/build`, `sandbox/decisions`, `sandbox/open` (exactly one, matching `section`).
- **Type:** the `type` value itself (`moc`, `concept`, `paper`, `primitive`, `standard`, `component`, `interface`, `incident`, `product`, `decision`, `milestone`, `eval`, `risk`, `problem`, `meta`, `source-index`).
- **Topic:** `topic/isolation`, `topic/egress`, `topic/dns`, `topic/tls`, `topic/credentials`, `topic/identity`, `topic/policy`, `topic/ifc`, `topic/audit`, `topic/learning`, `topic/mcp`, `topic/git`, `topic/filesystem`, `topic/supply-chain`, `topic/evaluation`, `topic/approval`, `topic/build`, `topic/market`.
- **Platform:** `platform/macos`, `platform/linux`, `platform/ci`, `platform/k8s`, `platform/cloud`, `platform/windows`.
- **Control (threat vocabulary):** `control/iso`, `control/fs`, `control/egress`, `control/cred-out`, `control/task-tok`, `control/pin`, `control/audit`, `control/hitl`.
- **Adversary:** `adversary/a1` to `adversary/a6`. **Trust boundary:** `boundary/tb1` to `boundary/tb7`.
- **Invariant:** `invariant/i1` to `invariant/i9` (on notes that enforce or test that invariant).
- **Milestone:** `milestone/m0` to `milestone/m4`, `milestone/phase2`, `milestone/phase3`.
- **Evidence quality:** `evidence/secondary` (rests on a secondary source), `evidence/single-source`, `evidence/conflict` (sources disagree), `evidence/unverified`.

## 5. Status values

| status | Meaning |
|---|---|
| `seedling` | Exists only as a manifest entry or stub; not yet written. |
| `draft` | Written but not yet checked against sources, or obsolete (explain in body). |
| `verified` | Every factual claim carries an inline citation from the research record (report or research notes). |
| `proposal` | The note's substance is a design recommendation (**Proposal** in the report), not a sourced fact. Facts inside it are still cited inline. |
| `built` | Implemented in `code/` with passing tests; the note has a `## Build log` section and a `code:` list. |

MOCs and meta notes use `verified` when their structure is complete. Architecture, policy, build and decision notes are mostly `proposal` until built. Incidents, papers, primitives, standards and products are mostly `verified`.

## 6. Confidence values

- `high`: primary sources (spec, advisory, paper, vendor docs) agree.
- `medium`: rests partly on secondary sources, vendor self-reports or the researcher's inference.
- `low`: single secondary source, conflicting sources, or marked unverified in the record. Anything `low` must also appear in [[Open Questions and Unverified Claims]].

## 7. Writing rules

- **Reading convention (from the report):** a sentence with an inline citation is a verified fact; a paragraph, table row or code block marked **Proposal** is a design recommendation. Start proposal paragraphs with `**Proposal.**`.
- Cite inline as a markdown link right after the claim: `... 4-11 µs median ([arXiv 2403.04651](https://arxiv.org/html/2403.04651)).` Add every URL to `sources:`.
- Where sources conflict, say so in a callout: `> [!warning] Conflict` ... and tag `evidence/conflict`. Unverified items use `> [!question] Unverified`.
- Do not invent numbers, versions, dates or product behaviour. If the research record does not say it, write "not in the record" and add it to [[Open Questions and Unverified Claims]].
- Code blocks from the report (Cedar schema, policies, Rust traits, TOML, JSON grant, repository tree) are copied verbatim and labelled "Proposal; not compiled".
- One idea per note. If a note starts covering two ideas, split it, link both from the MOC, and update `_manifest.json`.

## 8. Link semantics

Plain `[[wikilinks]]` are untyped for Obsidian's graph. To make relationships machine-readable, each content note ends with a `## Relationships` section using Dataview inline fields, one verb per line:

```markdown
## Relationships
- implements:: [[I6 Single Canonicaliser]]
- depends-on:: [[Broker DNS Resolver]]
- mitigates:: [[sandbox-runtime SOCKS NUL-Byte Bypass]]
- evaluated-by:: [[L1 Conformance Suite]]
```

Allowed verbs: `depends-on`, `implements`, `mitigates` (control → incident or risk) / `mitigated-by` (incident → control), `motivated-by` (design → evidence), `evaluated-by` (thing → test or benchmark), `supersedes` / `superseded-by`, `competes-with`, `contrasts-with`, `part-of`, `example-of`, `delivered-by` (component → milestone), `decided-by` (design → ADR). The frontmatter `related:` list must include every note named in Relationships.

## 9. File naming

- Title Case, human-readable, unique across the vault (case-insensitive), identical to `title`.
- Forbidden characters: `# | ^ : % [ ] / \ ;`. Avoid `?` and quotes.
- ADRs: `ADR-NNN Short Title` (three digits). Invariants: `I<n> ...`. Milestones: `M<n> ...`. Eval layers: `L<n> ...`.
- Keep product and technology names in their canonical case when they are lowercase by convention (`bubblewrap`, `seccomp-bpf`, `sandbox-runtime`, `broker.toml`, `gVisor`).

## 10. Templates

Templates live in `templates/` and use Obsidian core Templates placeholders (`{{title}}`, `{{date:YYYY-MM-DD}}`); `.obsidian/templates.json` points the core plugin at that folder:

- `Template Note`: concept, primitive, standard, product, milestone, eval, risk, problem.
- `Template Paper`: papers and audited systems.
- `Template Component`: components and interfaces.
- `Template Incident`: incidents and advisories.
- `Template ADR`: decisions.

After creating a note from a template: fill every frontmatter key, delete unused sections, link it from its MOC and add it to `_manifest.json`.
