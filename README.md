# CodeAtlas Skill

CodeAtlas is an evidence-first technical due diligence skill that analyzes a repository and produces structured risk and maturity artifacts.

## Contents

- `codeatlas/SKILL.md`: Skill instructions and workflow.
- `codeatlas/scripts/run_codeatlas.py`: Local runner that generates report artifacts.
- `codeatlas/references/spec.json`: Contract/spec reference.

## What It Produces

- `tdd_report_json`
- `risk_matrix_json`
- `metrics_summary_json`
- `security_maturity_index_json`
- `evidence_index_json`
- `slack_intel_json` (when enabled/capable)
- `tdd_report_pdf` (if PDF engine available)

## Quick Start

```bash
python3 /Users/dennisvinterfjard/Projects/CodeAtlas/codeatlas/scripts/run_codeatlas.py \
  --repo /absolute/path/to/repo \
  --out /absolute/path/to/output \
  --timeframe-days 180 \
  --stale-days 365 \
  --risk-appetite medium \
  --report-format both
```

## Notes

- `quick_validate.py` from the skill-creator toolchain requires `PyYAML`.
- PDF generation uses `reportlab` if installed, with `pandoc` fallback when available.
