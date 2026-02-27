# CodeAtlas Skill

CodeAtlas is an evidence-first technical due diligence skill that analyzes a repository and produces structured risk and maturity artifacts.
It orchestrates focused analyzers (sub-agent style) for architecture, staleness, dependencies, infrastructure/DevOps, security/auth patterns, data integrity, and team/process signals.

## Contents

- `codeatlas/SKILL.md`: Skill instructions and workflow.
- `codeatlas/scripts/run_codeatlas.py`: Local runner that generates report artifacts.
- `codeatlas/scripts/run_codeatlas_portfolio.py`: Portfolio runner for roots with many repos.
- `codeatlas/references/spec.json`: Contract/spec reference.

## What It Produces

- `tdd_report_json`
- `risk_matrix_json`
- `metrics_summary_json`
- `security_maturity_index_json`
- `evidence_index_json`
- `slack_intel_json` (when enabled/capable)
- `tdd_report_pdf` (if PDF engine available)
- Human-readable narrative sections with explicit `Finding/Evidence/Risk/Action/Confidence` entries.

## Quick Start

Single repository:

```bash
python3 /Users/dennisvinterfjard/Projects/CodeAtlas/codeatlas/scripts/run_codeatlas.py \
  --repo /absolute/path/to/repo \
  --out /absolute/path/to/output \
  --timeframe-days 180 \
  --stale-days 365 \
  --risk-appetite medium \
  --report-format both
```

Portfolio root (many repositories):

```bash
python3 /Users/dennisvinterfjard/Projects/CodeAtlas/codeatlas/scripts/run_codeatlas_portfolio.py \
  --portfolio-root /absolute/path/to/root-with-many-repos \
  --out /absolute/path/to/output \
  --report-format both
```

## Notes

- `quick_validate.py` from the skill-creator toolchain requires `PyYAML`.
- PDF generation uses `reportlab` if installed, with `pandoc` fallback when available.
- Portfolio flow defaults to requiring a PDF (`--require-pdf`) and fails the run if PDF rendering is unavailable.
