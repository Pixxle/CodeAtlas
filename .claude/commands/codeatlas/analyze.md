You are performing a comprehensive Technical Due Diligence analysis on a codebase.

**Target path**: $ARGUMENTS

If no target path was provided, ask the user which directory or repository to analyze.

## Reference Files

Find the CodeAtlas reference files by checking these locations in order:
1. `~/.claude/codeatlas/references/` (global install)
2. `./references/` (running from CodeAtlas project root)

You need three reference files during this analysis:
- `analysis-dimensions.md` — detailed investigative playbook for each dimension
- `cross-repo-synthesis.md` — instructions for cross-repo synthesis (multi-repo only)
- `report-template.md` — final report structure

Read these files when you reach the relevant phase. If they cannot be found, proceed using the embedded instructions in this command.

## Output Directory

Create `codeatlas-output/` in the current working directory for all artifacts.

---

## Phase 0: Discovery & Planning

### 0.1 — Run Discovery

Look for the scanner script at `~/.claude/codeatlas/scripts/repo-scanner.sh` or `./scripts/repo-scanner.sh`. If found, run it against the target path. Otherwise, do manual discovery:

1. Find all `.git` roots under the target path (max depth 4)
2. For each repo: detect languages, approximate LOC, top contributors, recent commits, key config files
3. Classify the layout:
   - **Single repo**: one `.git` root
   - **Mono-repo**: one `.git` root, multiple service/package directories
   - **Multi-repo**: multiple `.git` roots

Save results to `codeatlas-output/discovery.md`.

### 0.2 — Build an Analysis Plan

Based on discovery, determine:

1. **Which dimensions apply** — read the analysis-dimensions reference file for the full menu. Not every dimension applies to every repo (e.g., a library has no deployment pipeline).
2. **Which repos/services are high-priority** — identify core services by commit activity, dependency centrality, or ask the user.
3. **Estimated scope** — present a summary to the user: repos found, LOC, languages, proposed dimensions.

**Wait for user confirmation before proceeding to Phase 1.**

---

## Phase 1: Agent-Based Analysis

For each applicable (dimension × repo) combination, spawn a sub-agent using the Task tool with `subagent_type: "general-purpose"`.

### Sub-Agent Prompt Template

For each agent, use this prompt structure:

```
You are a specialist analyst performing a technical due diligence review.

**Your dimension**: [DIMENSION_NAME]
**Repository path**: [REPO_PATH]
**Repository context**: [BRIEF_CONTEXT — e.g., "Python FastAPI backend, ~15k LOC, 3 active contributors"]

Read the analysis instructions at: [PATH_TO_ANALYSIS_DIMENSIONS_FILE]
Navigate to the section for your dimension and follow the investigation steps precisely.

Save your findings as a structured markdown file to:
  codeatlas-output/analysis/[REPO_NAME]/[DIMENSION_SLUG].md

Your output file must follow this structure:

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

| # | Dimension | Slug | Covers |
|---|-----------|------|--------|
| 1 | Architecture & Design | `architecture` | System structure, modularity, coupling, scalability |
| 2 | Code Quality & Standards | `code-quality` | Style consistency, complexity, anti-patterns |
| 3 | Dependency & Supply Chain | `dependencies` | Outdated deps, CVEs, license risk, lock files |
| 4 | Security Posture | `security` | Secrets, auth, input validation, vulnerability classes |
| 5 | Testing & Quality Assurance | `testing` | Coverage, test types, test quality, flakiness |
| 6 | CI/CD & DevOps | `cicd` | Pipelines, deployment strategy, environment management |
| 7 | Documentation & Knowledge | `documentation` | READMEs, API docs, ADRs, onboarding quality |
| 8 | Git Health & Team Dynamics | `git-health` | Commit patterns, bus factor, PR practices |
| 9 | Performance & Scalability | `performance` | Bottlenecks, caching, database patterns, monitoring |
| 10 | Infrastructure & Configuration | `infrastructure` | IaC, config management, containers, migrations |

### Execution Strategy

- Spawn sub-agents in **parallel** — group into batches of up to 5 if there are many combinations.
- Each agent operates on a single (repo × dimension) pair.
- Use `run_in_background: true` for all agents, then collect results.

---

## Phase 2: Synthesis & Report

### 2.1 — Cross-Repo Synthesis (if multiple repos/services)

After all per-repo analyses complete, spawn a synthesis agent:
- Read the `cross-repo-synthesis.md` reference file for detailed instructions
- Read all files in `codeatlas-output/analysis/*/`
- Identify systemic patterns, cross-cutting risks, inter-service dependencies, consistency gaps
- Write findings to `codeatlas-output/synthesis/cross-repo-synthesis.md`

### 2.2 — Generate the Report

Read the `report-template.md` reference file for the full template structure. Generate the final report at `codeatlas-output/report/tdd-report.md` with these sections:

1. **Executive Summary** — 1 page max. Overall verdict, top strengths, critical risks, scoring table.
2. **Scope & Methodology** — What was analyzed, what wasn't, how.
3. **Scoring Matrix** — Dimensions × repos with ratings.
4. **Detailed Findings** — Per-dimension breakdown with evidence and per-repo callouts.
5. **Risk Register** — All risks consolidated: ID, description, severity, affected repos, remediation.
6. **Recommendations Roadmap** — Immediate / short-term / medium-term / long-term.
7. **Appendices** — Raw metrics, file references, tool outputs.

### 2.3 — Present Results

Tell the user the analysis is complete and where files are saved. Offer to:
- Generate a shorter executive briefing for non-technical stakeholders
- Export the risk register as a standalone table
- Deep-dive into any specific dimension or finding
