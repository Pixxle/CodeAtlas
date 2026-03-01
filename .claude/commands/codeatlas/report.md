You are generating a Technical Due Diligence report from existing analysis files.

**Output directory**: $ARGUMENTS (default: `codeatlas-output/`)

## Steps

### 1. Locate Analysis Files

Look for analysis artifacts in the output directory:

```
<output-dir>/
  discovery.md
  analysis/
    <repo-name>/
      architecture.md
      code-quality/
        code-style.md
        code-complexity.md
        code-debt.md
        code-error-handling.md
      dependencies.md
      security.md
      testing.md
      cicd.md
      documentation.md
      git-health.md
      performance.md
      infrastructure.md
  synthesis/
    cross-repo-synthesis.md
```

Read all `.md` files found under `analysis/` and `synthesis/`. If no analysis files exist, tell the user to run `/codeatlas:analyze <path>` first.

### 2. Read Report Template

Find and read the report template from:
1. `~/.claude/codeatlas/references/report-template.md` (global install)
2. `./references/report-template.md` (CodeAtlas project root)

If not found, use the embedded structure below.

### 3. Generate the Report

Write the report to `<output-dir>/report/tdd-report.md` following this structure:

#### Section 1: Executive Summary (1 page max)
- Overall assessment with clear verdict: proceed / proceed with conditions / significant concerns
- Contextualize for the project's stage (seed startup vs mature product)
- 3-5 key strengths with evidence
- 3-5 critical risks with severity and business impact
- Scoring summary table: each dimension with rating and confidence level

#### Section 2: Scope & Methodology
- Repositories analyzed with basic stats (name, languages, LOC, contributors)
- What was NOT analyzed (deployed infra, runtime behavior, etc.)
- Methodology description (static analysis, 4-point rating scale, evidence-based)

#### Section 3: Scoring Matrix
- Table: dimensions as rows, repos as columns, ratings in cells
- For single-repo, use a simpler vertical format

#### Section 4: Detailed Findings
For each dimension:
- Rating (Critical / Concerning / Acceptable / Strong)
- 2-3 paragraph assessment with industry context
- Evidence with specific file references
- Per-repo breakdown (if multi-repo)
- Risk table: ID, description, severity, affected repos, remediation effort
- Prioritized recommendations

#### Section 5: Risk Register
Consolidated table of all risks across all dimensions:
- P0: Must fix immediately / blocker
- P1: Fix within 30 days
- P2: Fix within 90 days
- P3: Long-term improvement

#### Section 6: Recommendations Roadmap
- Immediate (pre-close / week 1-2)
- Short-term (month 1-3)
- Medium-term (month 3-6)
- Long-term (month 6-12)
- Estimated total remediation investment in person-months

#### Section 7: Appendices
- Raw repository statistics
- Detailed file references
- Tool outputs
- Glossary for non-technical readers

### 4. Present to User

Tell the user the report is ready and where it's saved. Offer to:
- Generate a shorter executive briefing (2-page summary for non-technical stakeholders)
- Export the risk register as a standalone table
- Create a presentation outline summarizing key findings
- Deep-dive into any specific dimension
