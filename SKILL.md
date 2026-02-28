---
name: tech-due-diligence
description: >
  Perform a comprehensive technical due diligence analysis on one or more code repositories.
  Use this skill whenever the user wants to evaluate a codebase for investment decisions, acquisitions,
  partnership assessments, or internal tech audits. Triggers include any mention of 'tech due diligence',
  'code audit', 'repository assessment', 'codebase evaluation', 'technical review of a repo',
  'engineering health check', or requests to analyze the quality, risk, and maturity of a software project.
  Also use when the user asks to assess technical debt, architecture quality, or engineering practices
  across one or more repositories — even if they don't use the phrase 'due diligence' explicitly.
  Works with mono-repos, multi-repo setups, and single repositories.
---

# Technical Due Diligence — Codebase Analysis Skill

## Purpose

Produce a structured **Technical Due Diligence Report** by analyzing one or more code repositories.
The report should give a decision-maker a clear picture of: architecture quality, code health,
security posture, dependency risk, test coverage, CI/CD maturity, documentation quality,
and overall engineering culture — with concrete evidence backing every claim.

---

## Phase 0: Discovery & Planning

Before any analysis, orient yourself.

### 0.1 — Detect Repository Layout

Run the bundled discovery script to map out the workspace:

```bash
bash /path/to/skill/scripts/repo-scanner.sh <root-folder>
```

This outputs a structured summary: how many Git roots exist, languages detected,
approximate lines of code, and top-level directory structure per repo.

If the script is unavailable, do it manually:

```bash
# Find all git roots
find <root-folder> -name ".git" -type d -maxdepth 3 | sed 's/\/.git$//'

# For each root, get a quick fingerprint
for repo in $(find <root-folder> -name ".git" -type d -maxdepth 3 | sed 's/\/.git$//'); do
  echo "=== $repo ==="
  git -C "$repo" log --oneline -5
  git -C "$repo" shortlog -sn --no-merges | head -5
  find "$repo" -type f | grep -v '.git' | sed 's/.*\.//' | sort | uniq -c | sort -rn | head -10
done
```

Classify the layout:

| Layout | Signal |
|---|---|
| **Single repo** | One `.git` root |
| **Mono-repo** | One `.git` root, multiple distinct services/packages under it |
| **Multi-repo** | Multiple `.git` roots as sibling folders |

### 0.2 — Build an Analysis Plan

Based on discovery, decide:

1. **Which sub-analyses apply** — read [references/analysis-dimensions.md](./references/analysis-dimensions.md) for the full menu. Not every dimension applies to every repo (e.g., a pure library has no deployment pipeline to analyze).
2. **Which repos/services are high-priority** — if there are 30 microservices, the user probably doesn't want equal depth on all of them. Identify core services by commit activity, dependency centrality, or ask the user.
3. **Estimated scope** — give the user a quick summary: "I found 4 repos, ~120k LOC total, primarily TypeScript and Python. I'll do deep analysis on the 2 core services and a lighter pass on the others. Expected dimensions: architecture, code quality, dependencies, security, testing, CI/CD, documentation. Anything you want me to add or skip?"

Wait for user confirmation before proceeding.

---

## Phase 1: Agent-Based Analysis

This is the core of the skill. Each analysis dimension runs as an independent sub-agent task.
The reason for this decomposition: each dimension requires reading different files, running different
commands, and producing different artifacts. Parallel execution keeps total wall-clock time manageable
on large codebases, and isolated agents avoid context pollution between unrelated analyses.

### Spawning Sub-Agents

For each applicable dimension from the analysis plan, spawn a sub-agent with this template:

```
You are a specialist analyst performing a technical due diligence review.

**Your dimension**: [DIMENSION_NAME]
**Repository path**: [REPO_PATH]
**Repository context**: [BRIEF_CONTEXT — e.g., "Python FastAPI backend, ~15k LOC, 3 active contributors"]

Read the analysis instructions at: /path/to/skill/references/analysis-dimensions.md
Navigate to the section for your dimension and follow the instructions precisely.

Save your findings as a structured markdown file to:
  [WORKSPACE]/analysis/[REPO_NAME]/[DIMENSION_SLUG].md

Your output must follow this structure:
  ## [Dimension Name]
  ### Summary
  One paragraph with your overall assessment and a rating (Critical / Concerning / Acceptable / Strong).

  ### Evidence
  Specific files, patterns, metrics, and commands you ran that support your assessment.

  ### Risks
  Concrete risks identified, each with severity (High / Medium / Low) and remediation effort estimate.

  ### Recommendations
  Prioritized list of improvements, from most impactful to least.
```

### Dimension Catalogue

These are the standard dimensions. Read [references/analysis-dimensions.md](./references/analysis-dimensions.md) for the full investigative playbook per dimension.

| # | Dimension | Slug | What it covers |
|---|---|---|---|
| 1 | Architecture & Design | `architecture` | System design, modularity, coupling, scalability patterns |
| 2 | Code Quality & Standards | `code-quality` | Style consistency, complexity, anti-patterns, readability |
| 3 | Dependency & Supply Chain | `dependencies` | Outdated deps, vulnerability exposure, license risk, lock files |
| 4 | Security Posture | `security` | Secrets in code, auth patterns, input validation, known vuln classes |
| 5 | Testing & Quality Assurance | `testing` | Coverage, test types, test quality, flaky test signals |
| 6 | CI/CD & DevOps | `cicd` | Pipeline config, deployment strategy, environment management |
| 7 | Documentation & Knowledge | `documentation` | READMEs, API docs, ADRs, inline comments, onboarding quality |
| 8 | Git Health & Team Dynamics | `git-health` | Commit patterns, bus factor, PR practices, branch strategy |
| 9 | Performance & Scalability | `performance` | Obvious bottlenecks, caching, database patterns, resource usage |
| 10 | Infrastructure & Configuration | `infrastructure` | IaC presence, config management, environment parity |

### Cross-Repo Coordination (Multi-Repo / Mono-Repo)

When analyzing multiple repos or services:

- Each sub-agent operates on a **single repo or service boundary**.
- After all per-repo analyses complete, run a **cross-cutting synthesis agent** that:
  - Reads all per-repo dimension files
  - Identifies systemic patterns (e.g., "none of the 4 repos have integration tests")
  - Identifies inconsistencies (e.g., "service A pins dependencies, services B-D don't")
  - Maps inter-service dependencies and API contract risks
  - Assesses overall architectural coherence

---

## Phase 2: Synthesis & Report Generation

Once all sub-agent analyses are complete, compile the final report.

### 2.1 — Aggregate Findings

Read all `[WORKSPACE]/analysis/[REPO_NAME]/*.md` files. Build a unified risk register and scoring matrix.

### 2.2 — Generate the Report

Follow the template in [references/report-template.md](./references/report-template.md).

The report is a **docx file** (use the docx skill if available) with these sections:

1. **Executive Summary** — 1 page max. Overall verdict, top 3 risks, top 3 strengths, recommendation.
2. **Scope & Methodology** — What was analyzed, what wasn't, and how.
3. **Scoring Matrix** — Table: each dimension × each repo, with ratings and color coding.
4. **Detailed Findings** — One section per dimension, aggregated across repos with per-repo callouts.
5. **Risk Register** — All risks in one table: ID, description, severity, affected repos, remediation cost.
6. **Recommendations Roadmap** — Prioritized by impact/effort, grouped into immediate / short-term / long-term.
7. **Appendices** — Raw metrics, tool outputs, file listings referenced in the report.

### 2.3 — Present to User

Save the report to the output directory and present it. Offer to:
- Generate a shorter executive briefing (2-page PDF) for non-technical stakeholders
- Export the risk register as a standalone spreadsheet
- Create a presentation deck summarizing key findings

---

## Environment-Specific Notes

### Claude.ai (No Sub-Agents)

Sub-agents aren't available. Execute each dimension analysis **sequentially** in the same session.
The structure remains the same — write each dimension's findings to a separate file, then synthesize.
For large codebases, prioritize the most impactful dimensions first and offer to do a "light" vs "deep" analysis.

### Claude Code / Cowork (Sub-Agents Available)

Spawn sub-agents in parallel as described above. This is the intended execution mode.
Group sub-agents in batches if there are more than 10 to avoid overwhelming the system.

---

## Key Principles

- **Evidence over opinion.** Every claim in the report must reference a specific file, metric, or command output. "The code quality is poor" is useless. "The average cyclomatic complexity across 47 Python files is 23.4, with 12 functions exceeding 50" is useful.
- **Calibrate depth to risk.** A prototype with 2k LOC doesn't need the same depth as a production system serving millions. Ask about context if unclear.
- **Separate facts from interpretation.** Present findings factually first, then interpret. Let the reader draw their own conclusions where reasonable.
- **Be fair.** Most codebases have warts. The job is to find them, assess their severity honestly, and suggest fixes — not to be harsh for the sake of it.
